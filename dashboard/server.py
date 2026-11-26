"""
Track C — Dashboard Backend
FastAPI server that:
  - Bridges to the C++ DPI engine via a localhost TCP socket (JSON events).
  - Serves REST endpoints for stats, connections, blocked list, events.
  - Pushes live updates to the browser over WebSocket /ws.
  - Exports HTML and PDF reports via /api/report.
"""

from __future__ import annotations

import asyncio
import collections
import html
import json
import math
import os
import random
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_HTML_PATH = STATIC_DIR / "index.html"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Port the C++ engine will stream JSON events to (§4 integration contract).
ENGINE_HOST = "127.0.0.1"
ENGINE_PORT = 9000          # Dashboard listens here to accept engine pushes

# VPN enforcement policy: "block" vs "flag-only" (consistent across engine and dashboard)
VPN_ACTION = os.getenv("VPN_ACTION", "").lower().strip()
if not VPN_ACTION:
    dash_block = os.getenv("DASHBOARD_BLOCK_VPN", "").lower().strip()
    if dash_block in ("1", "true", "block", "yes"):
        VPN_ACTION = "block"
    else:
        VPN_ACTION = "flag-only"

# How often (seconds) to push stats to WebSocket clients.
WS_PUSH_INTERVAL = 1.0

# Ring-buffer sizes
MAX_CONNECTIONS = 200
MAX_EVENTS = 100

# Default packet size (bytes) fallback when contract-compliant app_classified events omit wire length
DEFAULT_PACKET_BYTES = 512

# Maximum frame/buffer size (64 KB) to protect against memory exhaustion from un-delimited streams
MAX_IPC_FRAME_SIZE = 64 * 1024


# ---------------------------------------------------------------------------
# In-memory state (updated by IPC bridge)
# ---------------------------------------------------------------------------

class DashboardState:
    """Thread-safe-ish state store updated by the IPC bridge coroutine."""

    def __init__(self) -> None:
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.throughput_bps: float = 0.0
        self._last_bytes: int = 0
        self._last_ts: float = time.time()
        self._event_counter: int = 0

        # app_name -> packet count
        self.app_breakdown: dict[str, int] = {}

        self.blocked_total: int = 0
        self.blocked_reasons: dict[str, int] = {}

        self.scan_alerts: int = 0
        self.syn_flood_alerts: int = 0
        self.dns_tunnel_alerts: int = 0
        self.malicious_domain_blocks: int = 0
        self.vpn_detections: int = 0
        self.vpn_blocks: int = 0

        # Ring buffers
        self.connections: collections.deque[dict] = collections.deque(
            maxlen=MAX_CONNECTIONS
        )
        self.events: collections.deque[dict] = collections.deque(maxlen=MAX_EVENTS)

    # ------------------------------------------------------------------
    # Ingest an event from the C++ engine (§4.2 schema) or mock generator
    # ------------------------------------------------------------------

    def ingest(self, event: Any) -> None:
        # Require dictionary before processing so malformed JSON does not raise AttributeError
        if not isinstance(event, dict):
            return

        kind = event.get("event")

        # Consume engine's aggregate byte statistics if provided (§4.3)
        if kind == "stats" or ("total_packets" in event and "total_bytes" in event):
            if "total_packets" in event:
                self.total_packets = int(event["total_packets"])
            if "total_bytes" in event:
                self.total_bytes = int(event["total_bytes"])
            if "throughput_bps" in event:
                self.throughput_bps = float(event["throughput_bps"])
            if "app_breakdown" in event and isinstance(event["app_breakdown"], dict):
                self.app_breakdown.update(event["app_breakdown"])
            if "blocked_total" in event:
                self.blocked_total = int(event["blocked_total"])
            if "blocked_reasons" in event and isinstance(event["blocked_reasons"], dict):
                self.blocked_reasons.update(event["blocked_reasons"])
            if "scan_alerts" in event:
                self.scan_alerts = int(event["scan_alerts"])
            if "syn_flood_alerts" in event:
                self.syn_flood_alerts = int(event["syn_flood_alerts"])
            if "dns_tunnel_alerts" in event:
                self.dns_tunnel_alerts = int(event["dns_tunnel_alerts"])
            if "malicious_domain_blocks" in event:
                self.malicious_domain_blocks = int(event["malicious_domain_blocks"])
            if "vpn_detections" in event:
                self.vpn_detections = int(event["vpn_detections"])
            if "vpn_blocks" in event:
                self.vpn_blocks = int(event["vpn_blocks"])
            return

        if kind == "app_classified":
            self.total_packets += 1
            pkt_bytes = next(
                (event.get(key) for key in ("bytes", "length", "packet_len", "size")
                 if event.get(key) is not None),
                DEFAULT_PACKET_BYTES,
            )
            try:
                pkt_bytes = max(0, int(pkt_bytes))
            except (TypeError, ValueError, OverflowError):
                pkt_bytes = DEFAULT_PACKET_BYTES
            self.total_bytes += pkt_bytes

            app = str(event.get("app") or "Unknown")
            self.app_breakdown[app] = self.app_breakdown.get(app, 0) + 1

            if event.get("blocked"):
                self.blocked_total += 1
                reason = str(event.get("reason") or "OTHER")
                self.blocked_reasons[reason] = (
                    self.blocked_reasons.get(reason, 0) + 1
                )

            self.connections.appendleft(event)

        elif kind == "anomaly":
            self._event_counter += 1
            if "id" not in event:
                event["id"] = self._event_counter

            atype = str(event.get("type", "")).upper()
            self.events.appendleft(event)
            if atype == "PORT_SCAN":
                self.scan_alerts += 1
            elif atype == "SYN_FLOOD":
                self.syn_flood_alerts += 1
            elif atype == "DNS_TUNNEL":
                self.dns_tunnel_alerts += 1

        elif kind == "security_alert":
            self._event_counter += 1
            if "id" not in event:
                event["id"] = self._event_counter

            alert_type = str(event.get("alert_type") or event.get("reason") or "")
            self.events.appendleft(event)

            if alert_type == "VPN_DETECTED":
                self.vpn_detections += 1
                if event.get("blocked"):
                    self.vpn_blocks += 1
            elif alert_type == "MALICIOUS":
                self.malicious_domain_blocks += 1
            elif alert_type == "PORT_SCAN":
                self.scan_alerts += 1
            elif alert_type == "SYN_FLOOD":
                self.syn_flood_alerts += 1
            elif alert_type == "DNS_TUNNEL":
                self.dns_tunnel_alerts += 1

            # IMPORTANT: Do NOT increment self.blocked_total or self.blocked_reasons here!
            # The blocked_total and blocked_reasons metrics are updated exclusively by the
            # app_classified or stats frames. This strictly prevents double-counting.

    def stats_snapshot(self) -> dict:
        """Calculates throughput against current wall-clock time so rate drops to 0
        when traffic ceases, and returns the aggregated metrics.
        """
        now = time.time()
        elapsed = now - self._last_ts
        if elapsed >= 1.0:
            self.throughput_bps = (self.total_bytes - self._last_bytes) * 8 / elapsed
            self._last_bytes = self.total_bytes
            self._last_ts = now

        return {
            "ts": int(now),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "throughput_bps": round(self.throughput_bps, 2),
            "app_breakdown": dict(self.app_breakdown),
            "blocked_total": self.blocked_total,
            "blocked_reasons": dict(self.blocked_reasons),
            "scan_alerts": self.scan_alerts,
            "syn_flood_alerts": self.syn_flood_alerts,
            "dns_tunnel_alerts": self.dns_tunnel_alerts,
            "malicious_domain_blocks": self.malicious_domain_blocks,
            "vpn_detections": self.vpn_detections,
            "vpn_blocks": self.vpn_blocks,
            "vpn_action": VPN_ACTION,
        }


state = DashboardState()


# ---------------------------------------------------------------------------
# Mock data generator (used only when C++ engine is NOT connected)
# ---------------------------------------------------------------------------

_APPS = ["Google", "YouTube", "DNS", "Netflix", "Facebook", "Unknown",
         "GitHub", "Zoom", "Cloudflare", "Spotify"]
_REASONS = ["DOMAIN", "IP", "APP", "MALICIOUS", "VPN_DETECTED"]
_ANOMALIES = ["PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"]


def _mock_event() -> dict:
    app = random.choice(_APPS)
    blocked = random.random() < 0.15
    reason = random.choice(_REASONS) if blocked else None
    return {
        "event": "app_classified",
        "ts": time.time(),
        "five_tuple": {
            "src_ip": f"10.0.0.{random.randint(1, 254)}",
            "src_port": random.randint(1024, 65535),
            "dst_ip": f"142.250.{random.randint(0, 255)}.{random.randint(0, 255)}",
            "dst_port": 443,
            "proto": "TCP",
        },
        "app": app,
        "blocked": blocked,
        "reason": reason,
        "bytes": random.randint(64, 8192),
    }


def _maybe_anomaly_event() -> dict | None:
    if random.random() < 0.05:   # 5 % chance per tick
        atype = random.choice(_ANOMALIES)
        return {
            "event": "anomaly",
            "ts": time.time(),
            "type": atype,
            "detail": {
                "src_ip": f"10.0.0.{random.randint(1, 254)}",
                "info": "simulated",
            },
        }
    return None


def _maybe_security_alert() -> dict | None:
    if random.random() < 0.06:   # 6 % chance per tick
        if random.random() < 0.5:
            domain = random.choice([
                "bad-malware-domain.com",
                "c2-server.evilcorp.biz",
                "urlhaus-test-malware.org",
            ])
            return {
                "event": "security_alert",
                "ts": time.time(),
                "alert_type": "MALICIOUS",
                "five_tuple": {
                    "src_ip": f"10.0.0.{random.randint(1, 254)}",
                    "src_port": random.randint(1024, 65535),
                    "dst_ip": f"198.51.100.{random.randint(1, 254)}",
                    "dst_port": 443,
                    "proto": "TCP",
                },
                "app_or_domain": domain,
                "blocked": True,
                "reason": "MALICIOUS",
                "detail": f"Matched URLhaus blocklist: {domain}",
            }
        vpn_app = random.choice(["WireGuard", "OpenVPN"])
        vpn_blocked = VPN_ACTION == "block"
        return {
            "event": "security_alert",
            "ts": time.time(),
            "alert_type": "VPN_DETECTED",
            "five_tuple": {
                "src_ip": f"10.0.0.{random.randint(1, 254)}",
                "src_port": random.randint(1024, 65535),
                "dst_ip": f"185.159.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "dst_port": 51820 if vpn_app == "WireGuard" else 1194,
                "proto": "UDP",
            },
            "app_or_domain": vpn_app,
            "blocked": vpn_blocked,
            "reason": "VPN_DETECTED" if vpn_blocked else "",
            "detail": f"{vpn_app} tunnel detected (policy: {VPN_ACTION})",
        }
    return None


# ---------------------------------------------------------------------------
# IPC bridge (Dashboard accepts connections from C++ engine; falls back to mock)
# ---------------------------------------------------------------------------

_active_engine_conns: set[asyncio.StreamWriter] = set()
_ipc_server: asyncio.AbstractServer | None = None
_supervised_processes: set[Any] = set()
_start_time: float = time.monotonic()


def register_child_process(proc: Any) -> None:
    """Register a supervised child process for cleanup on server shutdown."""
    _supervised_processes.add(proc)


async def shutdown_ipc_and_children() -> None:
    """Close active engine connections, the IPC listening socket, and child processes."""
    global _ipc_server
    # Close active engine connections BEFORE awaiting _ipc_server.wait_closed()
    # because Python 3.12+ wait_closed() blocks until accepted sockets close.
    for writer in list(_active_engine_conns):
        _active_engine_conns.discard(writer)
        try:
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
        except Exception:
            pass

    if _ipc_server is not None:
        _ipc_server.close()
        try:
            await asyncio.wait_for(_ipc_server.wait_closed(), timeout=2.0)
        except Exception:
            pass
        _ipc_server = None

    for proc in list(_supervised_processes):
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    await asyncio.to_thread(proc.wait, timeout=2.0)
                except Exception:
                    proc.kill()
                    await asyncio.to_thread(proc.wait, timeout=1.0)
            if proc.poll() is not None:
                _supervised_processes.discard(proc)
            else:
                print(f"[shutdown] warning: child process {getattr(proc, 'pid', proc)} still running")
        except Exception as exc:
            print(f"[shutdown] warning: failed to terminate child process {getattr(proc, 'pid', proc)}: {exc}")


async def handle_engine_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handles an incoming connection from the C++ DPI engine."""
    peer = writer.get_extra_info("peername")
    print(f"[ipc] C++ engine connected from {peer}")
    _active_engine_conns.add(writer)
    buf = b""
    try:
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_IPC_FRAME_SIZE:
                print(
                    f"[ipc] Warning: frame size limit exceeded ({len(buf)} > "
                    f"{MAX_IPC_FRAME_SIZE} bytes) from {peer}; closing connection."
                )
                break
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if line:
                    try:
                        event = json.loads(line)
                        if isinstance(event, dict):
                            state.ingest(event)
                            if manager._clients and event.get("event") in (
                                "anomaly",
                                "app_classified",
                                "security_alert",
                            ):
                                await manager.broadcast(event)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        pass
    except (OSError, asyncio.IncompleteReadError):
        pass
    finally:
        _active_engine_conns.discard(writer)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        print(f"[ipc] C++ engine disconnected from {peer}.")


async def ipc_bridge() -> None:
    """Dashboard-side TCP listener to accept engine connections (§4 topology).
    If port 9000 is occupied by an engine server, retries connecting as a client with backoff.
    """
    global _ipc_server
    try:
        server = await asyncio.start_server(
            handle_engine_connection, ENGINE_HOST, ENGINE_PORT
        )
        _ipc_server = server
        print(f"[ipc] Dashboard listening for C++ engine on {ENGINE_HOST}:{ENGINE_PORT}")
        try:
            async with server:
                await server.serve_forever()
        finally:
            if _ipc_server is server:
                _ipc_server = None
            server.close()
            try:
                await server.wait_closed()
            except Exception:
                pass
    except OSError:
        # Fallback if an engine is already running as a server on ENGINE_PORT
        print(f"[ipc] Port {ENGINE_PORT} in use; attempting outbound client connection...")
        while True:
            try:
                reader, writer = await asyncio.open_connection(ENGINE_HOST, ENGINE_PORT)
                await handle_engine_connection(reader, writer)
            except OSError:
                await asyncio.sleep(2.0)


async def mock_feeder() -> None:
    """Generates mock data only while disconnected from live engines (Violation 4)."""
    while True:
        await asyncio.sleep(1.0)
        if not _active_engine_conns:
            for _ in range(10):
                evt = _mock_event()
                state.ingest(evt)
                if manager._clients:
                    await manager.broadcast(evt)
            anomaly = _maybe_anomaly_event()
            if anomaly:
                state.ingest(anomaly)
                if manager._clients:
                    await manager.broadcast(anomaly)
            sec_alert = _maybe_security_alert()
            if sec_alert:
                state.ingest(sec_alert)
                if manager._clients:
                    await manager.broadcast(sec_alert)


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------

class ConnectionManager:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        # Idempotent removal prevents ValueError on concurrent disconnect
        self._clients.discard(ws)

    async def broadcast(self, data: dict) -> None:
        # Iterate over a snapshot list to allow safe concurrent removal
        for ws in list(self._clients):
            try:
                await ws.send_json(data)
            except Exception:
                self._clients.discard(ws)


manager = ConnectionManager()


async def ws_broadcaster() -> None:
    """Push aggregated stats to all connected WebSocket clients every second."""
    while True:
        await asyncio.sleep(WS_PUSH_INTERVAL)
        if manager._clients:
            await manager.broadcast(state.stats_snapshot())


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _start_time
    _start_time = time.monotonic()
    # Start background tasks
    bridge_task = asyncio.create_task(ipc_bridge())
    mock_task = asyncio.create_task(mock_feeder())
    broadcast_task = asyncio.create_task(ws_broadcaster())
    try:
        yield
    finally:
        bridge_task.cancel()
        mock_task.cancel()
        broadcast_task.cancel()
        # Close active engine connections and IPC server first so ipc_bridge's
        # server.wait_closed() does not deadlock waiting on open engine sockets.
        await shutdown_ipc_and_children()
        await asyncio.gather(
            bridge_task, mock_task, broadcast_task, return_exceptions=True
        )


app = FastAPI(title="Packet Analyzer Dashboard", lifespan=lifespan)

# Serve frontend static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check() -> dict[str, Any]:
    """Liveness and IPC readiness probe."""
    uptime = max(0.0, round(time.monotonic() - _start_time, 2))
    engine_conns = len(_active_engine_conns)
    ipc_listening = _ipc_server is not None and _ipc_server.is_serving()
    return {
        "status": "ok",
        "uptime_seconds": uptime,
        "engine_connected": engine_conns > 0,
        "active_engine_connections": engine_conns,
        "ipc": {
            "host": ENGINE_HOST,
            "port": ENGINE_PORT,
            "listening": ipc_listening,
        },
    }


@app.get("/api/stats")
async def get_stats() -> dict:
    """Aggregated stats snapshot (§4.3 schema)."""
    return state.stats_snapshot()


@app.get("/api/connections")
async def get_connections() -> list[dict[str, Any]]:
    """Most recent classified connections (ring buffer)."""
    return list(state.connections)


@app.get("/api/blocked")
async def get_blocked() -> list[dict[str, Any]]:
    """Only the blocked connections."""
    return [c for c in state.connections if c.get("blocked")]


@app.get("/api/events")
async def get_events() -> list[dict[str, Any]]:
    """Recent anomaly/security events."""
    return list(state.events)

# AI Analyst Agent endpoints
@app.get("/api/ai/stats")
async def get_ai_stats() -> dict[str, Any]:
    """Get engine statistics for AI analyst agent."""
    engine = state.engine
    if engine:
        stats = engine.get_stats()
        return {
            "total_packets": stats.total_packets,
            "throughput_bps": stats.throughput_bps,
            "total_bytes": stats.total_bytes,
            "filtered_packets": stats.filtered_packets,
            "scan_alerts": stats.scan_alerts,
            "syn_flood_alerts": stats.syn_flood_alerts,
            "dns_tunnel_alerts": stats.dns_tunnel_alerts,
            "malicious_domain_blocks": stats.malicious_domain_blocks,
            "vpn_detections": stats.vpn_detections,
        }
    return {}


@app.get("/api/ai/events")
async def get_ai_events(limit: int = 50) -> list[dict[str, Any]]:
    """Get recent events for AI analyst agent."""
    engine = state.engine
    if engine:
        events = engine.get_events(limit)
        return [
            {
                "timestamp": e.timestamp,
                "alert_type": e.alert_type,
                "app_or_domain": e.app_or_domain,
                "blocked": e.blocked,
                "reason": e.reason,
                "detail": e.detail,
            }
            for e in events
        ]
    return []


@app.get("/api/ai/blocked")
async def get_ai_blocked() -> list[dict[str, Any]]:
    """Get blocked connections for AI analyst agent."""
    engine = state.engine
    if engine:
        blocked = engine.get_blocked()
        return [
            {
                "src_ip": b.src_ip,
                "dst_ip": b.dst_ip,
                "app_or_domain": b.app_or_domain,
                "blocked": b.blocked,
                "reason": b.reason,
            }
            for b in blocked
        ]
    return []


@app.get("/api/ai/summary")
async def get_ai_summary() -> dict[str, Any]:
    """Get a summary for the AI analyst agent."""
    engine = state.engine
    if engine:
        stats = engine.get_stats()
        events = engine.get_events(limit=10)
        blocked = engine.get_blocked()
        return {
            "stats": {
                "scan_alerts": stats.scan_alerts if stats else 0,
                "syn_flood_alerts": stats.syn_flood_alerts if stats else 0,
                "dns_tunnel_alerts": stats.dns_tunnel_alerts if stats else 0,
                "malicious_domain_blocks": stats.malicious_domain_blocks if stats else 0,
                "vpn_detections": stats.vpn_detections if stats else 0,
            },
            "recent_events": [
                {
                    "alert_type": e.alert_type,
                    "app_or_domain": e.app_or_domain,
                    "blocked": e.blocked,
                }
                for e in events
            ],
            "blocked_connections": len(blocked) if blocked else 0,
        }
    return {}


@app.get("/api/ai/suggest_block")
async def suggest_block_rule(kind: str, value: str, reason: str) -> dict[str, str]:
    """Propose a block rule for human approval.
    
    The AI analyst suggests a block rule. Human approval required.
    Approval would call dpi_cli rule-add command.
    """
    engine = state.engine
    if engine:
        # Validate the rule kind
        valid_kinds = {"src_ip", "dst_ip", "app", "domain", "port"}
        if kind not in valid_kinds:
            return {"error": f"Invalid rule kind: {kind}. Valid: {valid_kinds}"}
        return {
            "suggestion": f"Block {kind}={value} ({reason})",
            "action": "dpi_cli rule-add --type {kind} --value {value}",
            "requires_human_approval": True,
        }
    return {"error": "Engine not available"}


@app.get("/api/ai/summary_v2")
async def get_ai_summary_v2() -> dict[str, Any]:
    """Enhanced summary with more detail for AI analyst."""
    engine = state.engine
    if engine:
        stats = engine.get_stats()
        events = engine.get_events(limit=20)
        blocked = engine.get_blocked()
        return {
            "stats": {
                "total_packets": stats.total_packets if stats else 0,
                "throughput_bps": stats.throughput_bps if stats else 0,
                "total_bytes": stats.total_bytes if stats else 0,
                "scan_alerts": stats.scan_alerts if stats else 0,
                "syn_flood_alerts": stats.syn_flood_alerts if stats else 0,
                "dns_tunnel_alerts": stats.dns_tunnel_alerts if stats else 0,
                "malicious_domain_blocks": stats.malicious_domain_blocks if stats else 0,
                "vpn_detections": stats.vpn_detections if stats else 0,
            },
            "recent_events": [
                {
                    "timestamp": e.timestamp,
                    "alert_type": e.alert_type,
                    "app_or_domain": e.app_or_domain,
                    "blocked": e.blocked,
                    "reason": e.reason,
                }
                for e in events
            ],
            "blocked_connections": [
                {
                    "src_ip": b.src_ip,
                    "dst_ip": b.dst_ip,
                    "app_or_domain": b.app_or_domain,
                    "blocked": b.blocked,
                }
                for b in blocked
            ],
            "engine_status": "active" if engine else "inactive",
        }
    return {}


@app.get("/api/ai/health")
async def ai_health_check() -> dict[str, str]:
    """Health check for AI analyst agent."""
    return {"status": "healthy", "message": "AI analyst agent endpoints available"}
# AI analyst agent endpoints
# AI analyst agent endpoints
    """Recent anomaly/security events."""
    return list(state.events)


# ---------------------------------------------------------------------------
# WebSocket live endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await manager.connect(ws)
    try:
        # Send an immediate snapshot so the client doesn't wait 1 s
        await ws.send_json(state.stats_snapshot())
        while True:
            # Keep the socket alive; broadcaster handles pushes
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------

def _fmt_bytes(num: int | float) -> str:
    val = float(num or 0)
    if val >= 1e9:
        return f"{val / 1e9:.2f} GB"
    if val >= 1e6:
        return f"{val / 1e6:.2f} MB"
    if val >= 1e3:
        return f"{val / 1e3:.1f} KB"
    return f"{int(val)} B"


def _fmt_bps(bps: float) -> str:
    val = float(bps or 0)
    if val >= 1e6:
        return f"{val / 1e6:.2f} Mbps"
    if val >= 1e3:
        return f"{val / 1e3:.1f} Kbps"
    return f"{round(val)} bps"


def _summarize_alert_event(event: dict[str, Any]) -> tuple[str, str, str, str]:
    """Return (timestamp_str, alert_type, action_label, detail_text) for reports."""
    ts_raw = event.get("ts")
    ts_str = "—"
    if isinstance(ts_raw, (int, float)) and not isinstance(ts_raw, bool) and math.isfinite(ts_raw) and ts_raw > 0:
        try:
            ts_str = time.strftime("%H:%M:%S", time.localtime(ts_raw))
        except (ValueError, OverflowError, OSError):
            ts_str = "—"

    alert_type = str(
        event.get("alert_type") or event.get("type") or event.get("reason") or "ALERT"
    ).upper()

    if event.get("blocked"):
        action = "BLOCKED"
    elif alert_type == "VPN_DETECTED":
        action = "FLAGGED"
    else:
        action = "ALERT"

    detail = event.get("detail")
    if isinstance(detail, dict):
        detail_text = " ".join(f"{k}={v}" for k, v in detail.items())
    elif detail:
        detail_text = str(detail)
    else:
        detail_text = str(event.get("app_or_domain") or "—")

    return ts_str, alert_type, action, detail_text


_ALERT_BADGE_COLORS = {
    "MALICIOUS": ("#ff9994", "rgba(248, 81, 73, 0.16)", "rgba(248, 81, 73, 0.45)"),
    "SYN_FLOOD": ("#ff9994", "rgba(248, 81, 73, 0.16)", "rgba(248, 81, 73, 0.45)"),
    "VPN_DETECTED": ("#ffdf85", "rgba(227, 179, 65, 0.16)", "rgba(227, 179, 65, 0.45)"),
    "PORT_SCAN": ("#ffb86c", "rgba(255, 159, 0, 0.16)", "rgba(255, 159, 0, 0.45)"),
    "DNS_TUNNEL": ("#76e3ea", "rgba(118, 227, 234, 0.16)", "rgba(118, 227, 234, 0.45)"),
}


def _render_html_report() -> str:
    snap = state.stats_snapshot()
    total_classified = max(1, sum(snap["app_breakdown"].values()))
    rows = "".join(
        (
            f"<tr>"
            f"<td>{html.escape(str(app))}</td>"
            f"<td class='mono r'>{count:,}</td>"
            f"<td class='mono r'>{(count / total_classified) * 100:.1f}%</td>"
            f"</tr>"
        )
        for app, count in sorted(
            snap["app_breakdown"].items(), key=lambda x: -x[1]
        )
    )
    total_blocked_reasons = max(1, sum(snap["blocked_reasons"].values()))
    blocked_rows = "".join(
        (
            f"<tr>"
            f"<td><span class='badge' style='color:#ff9994;background:rgba(248,81,73,0.16);border-color:rgba(248,81,73,0.45)'>{html.escape(str(reason))}</span></td>"
            f"<td class='mono r'>{count:,}</td>"
            f"<td class='mono r'>{(count / total_blocked_reasons) * 100:.1f}%</td>"
            f"</tr>"
        )
        for reason, count in sorted(
            snap["blocked_reasons"].items(), key=lambda x: -x[1]
        )
    )

    REPORT_RECENT_EVENT_LIMIT = 25

    alert_rows_list = []
    for ev in list(state.events)[:REPORT_RECENT_EVENT_LIMIT]:
        ts_str, atype, action, detail_text = _summarize_alert_event(ev)
        fg, bg, border = _ALERT_BADGE_COLORS.get(
            atype, ("#c9d1d9", "rgba(139,148,158,0.15)", "rgba(139,148,158,0.35)")
        )
        action_color = "#ff9994" if action == "BLOCKED" else "#ffdf85"
        alert_rows_list.append(
            f"<tr>"
            f"<td class='mono dim'>{html.escape(ts_str)}</td>"
            f"<td><span class='badge' style='color:{fg};background:{bg};border-color:{border}'>{html.escape(atype)}</span></td>"
            f"<td class='mono' style='color:{action_color};font-weight:600'>{html.escape(action)}</td>"
            f"<td class='mono'>{html.escape(detail_text)}</td>"
            f"</tr>"
        )
    alert_rows = "".join(alert_rows_list)

    total_alerts = (
        snap["scan_alerts"]
        + snap["syn_flood_alerts"]
        + snap["dns_tunnel_alerts"]
        + snap["malicious_domain_blocks"]
        + snap["vpn_detections"]
    )
    alert_banner_class = "banner-alert" if total_alerts > 0 else "banner-ok"
    alert_banner_text = (
        f"{total_alerts:,} total security alert(s) recorded across detectors"
        if total_alerts > 0
        else "No security alerts recorded — traffic nominal"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Packet Analyzer Pro — DPI Report</title>
  <style>
    :root {{
      --bg: #0e141d;
      --bg2: #131a26;
      --bg3: #1c2536;
      --border: #263345;
      --text: #e6edf3;
      --text-dim: #9aa5b4;
      --blue: #58a6ff;
      --green: #3fb950;
      --red: #ff9994;
      --orange: #ffdf85;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 28px 36px;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    .report-header {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 18px 22px;
      background: #111722;
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 18px;
    }}
    h1 {{
      margin: 0;
      font-size: 1.25rem;
      color: #f0f6fc;
      letter-spacing: 0.02em;
    }}
    .meta {{
      font-size: 0.85rem;
      color: var(--text-dim);
      margin-top: 4px;
    }}
    .policy-pill {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      padding: 4px 10px;
      border-radius: 4px;
      border: 1px solid rgba(56, 139, 253, 0.4);
      background: rgba(56, 139, 253, 0.14);
      color: #93c5fd;
    }}
    .banner-alert, .banner-ok {{
      padding: 10px 16px;
      border-radius: 6px;
      font-size: 0.9rem;
      font-weight: 600;
      margin-bottom: 20px;
      border: 1px solid;
    }}
    .banner-alert {{
      background: rgba(248, 81, 73, 0.14);
      border-color: rgba(248, 81, 73, 0.45);
      color: #ffb4ae;
    }}
    .banner-ok {{
      background: rgba(63, 185, 80, 0.12);
      border-color: rgba(63, 185, 80, 0.35);
      color: #7ee787;
    }}
    h2 {{
      font-size: 0.95rem;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: #93c5fd;
      margin: 24px 0 12px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border);
    }}
    .stat-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
      gap: 12px;
      margin-bottom: 22px;
    }}
    .stat {{
      padding: 12px 16px;
      background: var(--bg2);
      border-radius: 6px;
      border: 1px solid var(--border);
    }}
    .stat.alert-active {{
      border-color: rgba(248, 81, 73, 0.5);
      background: rgba(248, 81, 73, 0.08);
    }}
    .stat h3 {{
      margin: 0 0 6px;
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
    }}
    .stat p {{
      margin: 0;
      font-size: 1.35rem;
      font-weight: 700;
      color: #f0f6fc;
      font-family: 'JetBrains Mono', monospace;
    }}
    .stat .sub {{
      font-size: 0.75rem;
      color: var(--text-dim);
      margin-top: 2px;
      font-family: 'JetBrains Mono', monospace;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      margin-bottom: 22px;
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
    }}
    th, td {{
      border-bottom: 1px solid #1a2433;
      padding: 9px 14px;
      text-align: left;
      font-size: 0.85rem;
    }}
    th {{
      background: #111722;
      color: var(--text-dim);
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .mono {{ font-family: 'JetBrains Mono', monospace; }}
    .dim {{ color: var(--text-dim); }}
    .r {{ text-align: right; }}
    .empty {{
      text-align: center;
      color: var(--text-dim);
      padding: 20px;
      font-style: italic;
    }}
    .badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.74rem;
      font-weight: 700;
      border: 1px solid;
    }}
    @media print {{
      body {{ background: #fff; color: #111; padding: 16px; }}
      .report-header, .stat, table {{ background: #fff; border-color: #cbd5e1; }}
      th {{ background: #f1f5f9; color: #334155; }}
      h1, .stat p {{ color: #0f172a; }}
      h2 {{ color: #1d4ed8; }}
    }}
  </style>
</head>
<body>
  <div class="report-header">
    <div>
      <h1>Packet Analyzer Pro — DPI Report</h1>
      <div class="meta">Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</div>
    </div>
    <div class="policy-pill">VPN Policy: {html.escape(VPN_ACTION.upper())}</div>
  </div>

  <div class="{alert_banner_class}">{html.escape(alert_banner_text)}</div>

  <h2>Stage 01–04 Telemetry Summary</h2>
  <div class="stat-grid">
    <div class="stat"><h3>Total Packets</h3><p>{snap['total_packets']:,}</p></div>
    <div class="stat"><h3>Total Bytes</h3><p>{_fmt_bytes(snap['total_bytes'])}</p><div class="sub">{snap['total_bytes']:,} B</div></div>
    <div class="stat"><h3>Throughput</h3><p>{_fmt_bps(snap['throughput_bps'])}</p><div class="sub">{snap['throughput_bps']:,.0f} bps</div></div>
    <div class="stat {'alert-active' if snap['blocked_total'] > 0 else ''}"><h3>Blocked Packets</h3><p>{snap['blocked_total']:,}</p></div>
    <div class="stat {'alert-active' if snap['malicious_domain_blocks'] > 0 else ''}"><h3>Malicious Blocks</h3><p>{snap['malicious_domain_blocks']}</p></div>
    <div class="stat {'alert-active' if snap['vpn_detections'] > 0 else ''}"><h3>VPN Detections</h3><p>{snap['vpn_detections']}</p><div class="sub">Blocked: {snap['vpn_blocks']}</div></div>
    <div class="stat {'alert-active' if snap['scan_alerts'] > 0 else ''}"><h3>Port Scan Alerts</h3><p>{snap['scan_alerts']}</p></div>
    <div class="stat {'alert-active' if snap['syn_flood_alerts'] > 0 else ''}"><h3>SYN Flood Alerts</h3><p>{snap['syn_flood_alerts']}</p></div>
    <div class="stat {'alert-active' if snap['dns_tunnel_alerts'] > 0 else ''}"><h3>DNS Tunnel Alerts</h3><p>{snap['dns_tunnel_alerts']}</p></div>
  </div>

  <h2>Recent Security Alerts</h2>
  <table>
    <thead>
      <tr><th>Time</th><th>Alert Type</th><th>Action</th><th>Details</th></tr>
    </thead>
    <tbody>
      {alert_rows if alert_rows else '<tr><td colspan="4" class="empty">No security alerts recorded during this session.</td></tr>'}
    </tbody>
  </table>

  <h2>Application Breakdown</h2>
  <table>
    <thead>
      <tr><th>Application</th><th class="r">Packets</th><th class="r">Share</th></tr>
    </thead>
    <tbody>
      {rows if rows else '<tr><td colspan="3" class="empty">No application traffic recorded yet.</td></tr>'}
    </tbody>
  </table>

  <h2>Blocked Traffic by Reason</h2>
  <table>
    <thead>
      <tr><th>Reason</th><th class="r">Count</th><th class="r">Share</th></tr>
    </thead>
    <tbody>
      {blocked_rows if blocked_rows else '<tr><td colspan="3" class="empty">No blocked traffic recorded.</td></tr>'}
    </tbody>
  </table>
</body>
</html>"""


@app.get("/api/report")
async def export_report(format: str = "html"):
    """
    Export a snapshot report.
    ?format=html  → HTML file download
    ?format=pdf   → PDF file download (requires reportlab)
    """
    html_content = _render_html_report()

    if format == "pdf":
        try:
            from io import BytesIO

            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.platypus import (
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )

            snap = state.stats_snapshot()
            buf = BytesIO()
            doc = SimpleDocTemplate(
                buf,
                pagesize=A4,
                leftMargin=36,
                rightMargin=36,
                topMargin=36,
                bottomMargin=36,
            )
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                "EnterpriseTitle",
                parent=styles["Title"],
                textColor=colors.HexColor("#0f172a"),
                fontSize=18,
                spaceAfter=4,
            )
            heading_style = ParagraphStyle(
                "EnterpriseHeading",
                parent=styles["Heading2"],
                textColor=colors.HexColor("#1f6feb"),
                fontSize=12,
                spaceBefore=10,
                spaceAfter=6,
            )
            story = []

            story.append(Paragraph("Packet Analyzer Pro — DPI Report", title_style))
            story.append(
                Paragraph(
                    f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; "
                    f"VPN Policy: {xml_escape(VPN_ACTION.upper())}",
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 14))

            story.append(Paragraph("Stage 01–04 Telemetry Summary", heading_style))
            summary_rows = [
                ["Metric", "Value", "Metric", "Value"],
                [
                    "Total Packets",
                    f"{snap['total_packets']:,}",
                    "Port Scan Alerts",
                    str(snap["scan_alerts"]),
                ],
                [
                    "Total Bytes",
                    f"{_fmt_bytes(snap['total_bytes'])} ({snap['total_bytes']:,} B)",
                    "SYN Flood Alerts",
                    str(snap["syn_flood_alerts"]),
                ],
                [
                    "Throughput",
                    f"{_fmt_bps(snap['throughput_bps'])} ({snap['throughput_bps']:,.0f} bps)",
                    "DNS Tunnel Alerts",
                    str(snap["dns_tunnel_alerts"]),
                ],
                [
                    "Blocked Total",
                    f"{snap['blocked_total']:,}",
                    "Malicious Blocks",
                    str(snap["malicious_domain_blocks"]),
                ],
                [
                    "VPN Detections",
                    str(snap["vpn_detections"]),
                    "VPN Blocks",
                    str(snap["vpn_blocks"]),
                ],
            ]
            summary_table = Table(summary_rows, colWidths=[115, 145, 115, 145])
            summary_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#131a26")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                        ("PADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            story.append(summary_table)
            story.append(Spacer(1, 12))

            story.append(Paragraph("Recent Security Alerts", heading_style))
            recent_events = list(state.events)[:25]
            if recent_events:
                ev_table_rows = [["Time", "Type", "Action", "Detail"]]
                for ev in recent_events:
                    ts_str, atype, action, detail_text = _summarize_alert_event(ev)
                    ev_table_rows.append(
                        [
                            ts_str,
                            atype,
                            action,
                            Paragraph(xml_escape(detail_text[:120]), styles["Normal"]),
                        ]
                    )
                ev_table = Table(ev_table_rows, colWidths=[60, 95, 65, 300])
                ev_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#131a26")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                            ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("PADDING", (0, 0), (-1, -1), 5),
                        ]
                    )
                )
                story.append(ev_table)
            else:
                story.append(
                    Paragraph("No security alerts recorded during this session.", styles["Normal"])
                )
            story.append(Spacer(1, 12))

            story.append(Paragraph("Application Breakdown", heading_style))
            app_items = sorted(snap["app_breakdown"].items(), key=lambda x: -x[1])
            if app_items:
                total_app_pkts = max(1, sum(c for _, c in app_items))
                app_rows = [["Application", "Packets", "Share"]]
                for app_name, count in app_items:
                    app_rows.append(
                        [
                            str(app_name),
                            f"{count:,}",
                            f"{(count / total_app_pkts) * 100:.1f}%",
                        ]
                    )
                app_table = Table(app_rows, colWidths=[260, 130, 130])
                app_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#131a26")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 9),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                            ("PADDING", (0, 0), (-1, -1), 5),
                        ]
                    )
                )
                story.append(app_table)
            else:
                story.append(
                    Paragraph("No application traffic recorded yet.", styles["Normal"])
                )
            story.append(Spacer(1, 12))

            story.append(Paragraph("Blocked Traffic by Reason", heading_style))
            blocked_items = sorted(snap["blocked_reasons"].items(), key=lambda x: -x[1])
            if blocked_items:
                total_blk = max(1, sum(c for _, c in blocked_items))
                blk_rows = [["Reason", "Count", "Share"]]
                for reason, count in blocked_items:
                    blk_rows.append(
                        [
                            str(reason),
                            f"{count:,}",
                            f"{(count / total_blk) * 100:.1f}%",
                        ]
                    )
                blk_table = Table(blk_rows, colWidths=[260, 130, 130])
                blk_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#131a26")),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, -1), 9),
                            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                            ("PADDING", (0, 0), (-1, -1), 5),
                        ]
                    )
                )
                story.append(blk_table)
            else:
                story.append(
                    Paragraph("No blocked traffic recorded.", styles["Normal"])
                )

            doc.build(story)
            pdf_bytes = buf.getvalue()

            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": "attachment; filename=dpi_report.pdf"
                },
            )

        except ImportError:
            return Response(
                content="reportlab not installed. Run: pip install reportlab",
                status_code=500,
            )

    # Default: HTML
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": "attachment; filename=dpi_report.html"},
    )


# ---------------------------------------------------------------------------
# Root — serve the dashboard
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def root():
    with open(INDEX_HTML_PATH, encoding="utf-8") as f:
        return f.read()
