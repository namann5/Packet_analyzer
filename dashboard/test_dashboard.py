"""
Track C — Dashboard Pytest Suite
Functional and unit tests for DashboardState, REST API endpoints, HTML/PDF report export,
IPC engine connection handling, and WebSocket push.
"""

from __future__ import annotations

import os
import sys
import pytest
import asyncio
import json

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi.testclient import TestClient

from dashboard.server import (
    app,
    state,
    DashboardState,
    handle_engine_connection,
    MAX_CONNECTIONS,
    MAX_EVENTS,
    MAX_IPC_FRAME_SIZE,
    DEFAULT_PACKET_BYTES,
)


@pytest.fixture(autouse=True)
def reset_state():
    """Reset global dashboard state before each test."""
    state.total_packets = 0
    state.total_bytes = 0
    state.throughput_bps = 0.0
    state._last_bytes = 0
    state._event_counter = 0
    state.app_breakdown.clear()
    state.blocked_total = 0
    state.blocked_reasons.clear()
    state.scan_alerts = 0
    state.syn_flood_alerts = 0
    state.dns_tunnel_alerts = 0
    state.malicious_domain_blocks = 0
    state.vpn_detections = 0
    state.vpn_blocks = 0
    state.connections.clear()
    state.events.clear()


# ============================================================================
# 1. Unit Tests for DashboardState
# ============================================================================

def test_dashboard_state_app_classified_ingest():
    s = DashboardState()
    event = {
        "event": "app_classified",
        "ts": 1710000000.0,
        "five_tuple": {
            "src_ip": "10.0.0.1",
            "src_port": 12345,
            "dst_ip": "1.1.1.1",
            "dst_port": 443,
            "proto": "TCP",
        },
        "app": "Google",
        "bytes": 1024,
        "blocked": False,
        "reason": None,
    }

    s.ingest(event)
    assert s.total_packets == 1
    assert s.total_bytes == 1024
    assert s.app_breakdown.get("Google") == 1
    assert len(s.connections) == 1
    assert s.blocked_total == 0


def test_dashboard_state_blocked_event_ingest():
    s = DashboardState()
    event = {
        "event": "app_classified",
        "ts": 1710000000.0,
        "five_tuple": {
            "src_ip": "10.0.0.2",
            "src_port": 54321,
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "proto": "UDP",
        },
        "app": "DNS",
        "bytes": 512,
        "blocked": True,
        "reason": "DOMAIN",
    }

    s.ingest(event)
    assert s.total_packets == 1
    assert s.total_bytes == 512
    assert s.blocked_total == 1
    assert s.blocked_reasons.get("DOMAIN") == 1


def test_dashboard_state_anomaly_ingest():
    s = DashboardState()
    for anomaly in ["PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"]:
        event = {
            "event": "anomaly",
            "ts": 1710000000.0,
            "type": anomaly,
            "detail": {"src_ip": "10.0.0.66", "target": "10.0.0.1"},
        }
        s.ingest(event)

    assert s.scan_alerts == 1
    assert s.syn_flood_alerts == 1
    assert s.dns_tunnel_alerts == 1
    assert len(s.events) == 3


def test_dashboard_state_aggregate_stats_ingest():
    s = DashboardState()
    stats_payload = {
        "event": "stats",
        "total_packets": 5000,
        "total_bytes": 2000000,
        "throughput_bps": 150000.0,
        "app_breakdown": {"YouTube": 3000, "Google": 2000},
        "blocked_total": 450,
        "blocked_reasons": {"APP": 250, "DOMAIN": 200},
        "scan_alerts": 5,
        "syn_flood_alerts": 2,
        "dns_tunnel_alerts": 1,
    }

    s.ingest(stats_payload)
    assert s.total_packets == 5000
    assert s.total_bytes == 2000000
    assert s.throughput_bps == 150000.0
    assert s.app_breakdown["YouTube"] == 3000
    assert s.blocked_total == 450
    assert s.scan_alerts == 5


def test_dashboard_state_ring_buffer_limits():
    s = DashboardState()
    for i in range(MAX_CONNECTIONS + 50):
        s.ingest({
            "event": "app_classified",
            "app": f"App_{i}",
            "blocked": False,
        })
    assert len(s.connections) == MAX_CONNECTIONS

    for i in range(MAX_EVENTS + 20):
        s.ingest({
            "event": "anomaly",
            "type": "PORT_SCAN",
            "detail": {"idx": i},
        })
    assert len(s.events) == MAX_EVENTS


def test_dashboard_state_malformed_input():
    s = DashboardState()
    # Malformed / non-dict inputs should not crash
    s.ingest(None)
    s.ingest("not a dict")
    s.ingest([1, 2, 3])
    s.ingest({"event": "unknown_event_type"})
    assert s.total_packets == 0


def test_dashboard_state_preserves_zero_and_rejects_bad_byte_counts():
    s = DashboardState()
    s.ingest({"event": "app_classified", "bytes": 0, "blocked": False})
    s.ingest({"event": "app_classified", "bytes": "not-a-number", "blocked": False})

    assert s.total_packets == 2
    assert s.total_bytes == DEFAULT_PACKET_BYTES


# ============================================================================
# 2. REST API Endpoints Tests
# ============================================================================

def test_api_stats():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "Google",
        "bytes": 2048,
        "blocked": False,
    })

    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["total_packets"] == 1
    assert data["total_bytes"] == 2048
    assert "Google" in data["app_breakdown"]


def test_api_connections():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "YouTube",
        "bytes": 500,
        "blocked": False,
    })

    res = client.get("/api/connections")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["app"] == "YouTube"


def test_api_blocked():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "YouTube",
        "bytes": 500,
        "blocked": True,
        "reason": "APP",
    })

    res = client.get("/api/blocked")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["blocked"] is True


def test_api_events():
    client = TestClient(app)
    state.ingest({
        "event": "anomaly",
        "type": "SYN_FLOOD",
        "detail": {"src_ip": "10.0.0.99"},
    })

    res = client.get("/api/events")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["type"] == "SYN_FLOOD"


def test_root_endpoint():
    client = TestClient(app)
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers.get("content-type", "")
    assert "PACKET ANALYZER" in res.text


# ============================================================================
# 3. Report Generation Tests (HTML and PDF)
# ============================================================================

def test_api_report_html():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "Google",
        "bytes": 1000,
        "blocked": False,
    })
    state.ingest({
        "event": "security_alert",
        "alert_type": "MALICIOUS",
        "detail": "URLhaus match: malware-c2.example.com",
        "app_or_domain": "malware-c2.example.com",
        "blocked": True,
        "reason": "MALICIOUS",
    })
    state.ingest({
        "event": "security_alert",
        "alert_type": "VPN_DETECTED",
        "detail": "WireGuard detected (UDP:51820)",
        "app_or_domain": "WireGuard",
        "blocked": False,
        "reason": "",
    })

    res = client.get("/api/report?format=html")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    assert "DPI Report" in res.text
    assert "Google" in res.text
    assert "Malicious Blocks" in res.text
    assert "<h3>Malicious Blocks</h3><p>1</p>" in res.text
    assert "VPN Detections" in res.text
    assert "<h3>VPN Detections</h3><p>1</p><div class=\"sub\">Blocked: 0</div>" in res.text


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    import base64
    import re
    import zlib

    chunks: list[str] = []
    for raw_stream in re.findall(rb"stream\r?\n(.*?)endstream", pdf_bytes, re.S):
        payload = raw_stream.strip()
        if payload.endswith(b"~>"):
            payload = base64.a85decode(b"<~" + payload, adobe=True)
        try:
            chunks.append(zlib.decompress(payload).decode("latin1", errors="ignore"))
        except Exception:
            chunks.append(payload.decode("latin1", errors="ignore"))
    return "\n".join(chunks)


def test_api_report_pdf():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "Google",
        "bytes": 1000,
        "blocked": True,
        "reason": "DOMAIN",
    })
    state.ingest({
        "event": "security_alert",
        "alert_type": "MALICIOUS",
        "detail": "URLhaus match: bad.xyz",
        "app_or_domain": "bad.xyz",
        "blocked": True,
        "reason": "MALICIOUS",
    })
    state.ingest({
        "event": "security_alert",
        "alert_type": "VPN_DETECTED",
        "detail": "OpenVPN detected on port 1194",
        "app_or_domain": "OpenVPN",
        "blocked": True,
        "reason": "VPN_DETECTED",
    })

    res = client.get("/api/report?format=pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF")

    pdf_text = _extract_pdf_text(res.content)
    assert "(Malicious Blocks)" in pdf_text
    assert "(VPN Detections)" in pdf_text
    assert "(VPN Blocks)" in pdf_text
    assert "(1)" in pdf_text
    assert "(Share)" in pdf_text
    assert "(100.0%)" in pdf_text


# ============================================================================
# 4. IPC Frame Stream Handling Test
# ============================================================================

def test_handle_engine_connection_stream():
    async def run_stream():
        events = [
            {"event": "app_classified", "app": "Google", "bytes": 128, "blocked": False},
            {"event": "anomaly", "type": "PORT_SCAN", "detail": {"src_ip": "1.2.3.4"}},
        ]
        raw_payload = "\n".join(json.dumps(e) for e in events).encode("utf-8") + b"\n"

        reader = asyncio.StreamReader()
        reader.feed_data(raw_payload)
        reader.feed_eof()

        class MockWriter:
            def get_extra_info(self, name):
                return ("127.0.0.1", 9000)
            def close(self):
                pass
            async def wait_closed(self):
                pass

        writer = MockWriter()
        await handle_engine_connection(reader, writer)

    asyncio.run(run_stream())
    assert state.total_packets == 1
    assert state.total_bytes == 128
    assert state.scan_alerts == 1


# ============================================================================
# 5. WebSocket Test
# ============================================================================

def test_websocket_endpoint():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "DNS",
        "bytes": 64,
        "blocked": False,
    })

    with client.websocket_connect("/ws") as websocket:
        data = websocket.receive_json()
        assert "total_packets" in data
        assert "total_bytes" in data
        assert data["total_packets"] == 1


# ============================================================================
# 6. Simulator Feed Generator Unit Tests
# ============================================================================

def test_simulate_feed_generators():
    from dashboard.simulate_feed import generate_packet_event, generate_anomaly_event

    pkt, sec_alert = generate_packet_event()
    assert pkt["event"] == "app_classified"
    assert "five_tuple" in pkt
    assert "src_ip" in pkt["five_tuple"]
    assert "dst_ip" in pkt["five_tuple"]
    assert "app" in pkt
    assert isinstance(pkt["bytes"], int)
    assert isinstance(pkt["blocked"], bool)

    anomaly = generate_anomaly_event()
    assert anomaly["event"] == "anomaly"
    assert anomaly["type"] in ["PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"]
    assert "detail" in anomaly
    assert "src_ip" in anomaly["detail"]


# ============================================================================
# 7. Security Alert & VPN / Malicious Handling Tests (Track B Verification)
# ============================================================================

def test_dashboard_state_security_alert_vpn_modes_and_no_double_count():
    s = DashboardState()

    # 1. Flag-only VPN event: security alert + flow frame (allowed)
    sec_alert_flag = {
        "event": "security_alert",
        "alert_type": "VPN_DETECTED",
        "detail": "WireGuard detected (UDP:51820)",
        "app_or_domain": "WireGuard",
        "blocked": False,
        "reason": "",
    }
    s.ingest(sec_alert_flag)
    assert s.vpn_detections == 1
    assert s.vpn_blocks == 0
    assert s.blocked_total == 0  # Alert alone MUST NOT increment blocked_total

    flow_flag = {
        "event": "app_classified",
        "app": "WireGuard",
        "bytes": 500,
        "blocked": False,
        "reason": None,
    }
    s.ingest(flow_flag)
    assert s.vpn_detections == 1
    assert s.vpn_blocks == 0
    assert s.blocked_total == 0

    # 2. Block VPN event: security alert + flow frame (blocked)
    sec_alert_block = {
        "event": "security_alert",
        "alert_type": "VPN_DETECTED",
        "detail": "OpenVPN detected on port 1194",
        "app_or_domain": "OpenVPN",
        "blocked": True,
        "reason": "VPN_DETECTED",
    }
    s.ingest(sec_alert_block)
    assert s.vpn_detections == 2
    assert s.vpn_blocks == 1
    assert s.blocked_total == 0  # Still 0 because app_classified hasn't arrived yet!

    flow_block = {
        "event": "app_classified",
        "app": "OpenVPN",
        "bytes": 256,
        "blocked": True,
        "reason": "VPN_DETECTED",
    }
    s.ingest(flow_block)
    # Total blocked must be exactly 1: no double counting between security_alert and app_classified
    assert s.blocked_total == 1
    assert s.blocked_reasons.get("VPN_DETECTED") == 1
    assert s.vpn_detections == 2
    assert s.vpn_blocks == 1


def test_dashboard_state_security_alert_malicious_domain():
    s = DashboardState()

    sec_alert = {
        "event": "security_alert",
        "alert_type": "MALICIOUS",
        "detail": "URLhaus match: malware-c2.example.com",
        "app_or_domain": "malware-c2.example.com",
        "blocked": True,
        "reason": "MALICIOUS",
    }
    s.ingest(sec_alert)
    assert s.malicious_domain_blocks == 1
    assert s.blocked_total == 0  # No double counting before flow frame

    flow_block = {
        "event": "app_classified",
        "app": "DNS",
        "bytes": 128,
        "blocked": True,
        "reason": "MALICIOUS",
    }
    s.ingest(flow_block)
    assert s.blocked_total == 1
    assert s.blocked_reasons.get("MALICIOUS") == 1
    assert s.malicious_domain_blocks == 1


def test_api_stats_vpn_and_malicious_fields():
    client = TestClient(app)
    state.ingest({
        "event": "security_alert",
        "alert_type": "VPN_DETECTED",
        "detail": "WireGuard handshake",
        "app_or_domain": "WireGuard",
        "blocked": False,
        "reason": "",
    })
    state.ingest({
        "event": "security_alert",
        "alert_type": "MALICIOUS",
        "detail": "URLhaus match: bad.xyz",
        "app_or_domain": "bad.xyz",
        "blocked": True,
        "reason": "MALICIOUS",
    })

    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert "vpn_detections" in data
    assert "vpn_blocks" in data
    assert "malicious_domain_blocks" in data
    assert "vpn_action" in data
    assert data["vpn_detections"] == 1
    assert data["malicious_domain_blocks"] == 1


# ============================================================================
# 8. Issue #9 Verification: Engine Anomaly & Block Events IPC Propagation
# ============================================================================

def test_issue_9_engine_anomaly_and_block_ipc_propagation():
    """Verify Issue #9 acceptance criteria:
    Engine anomaly + block events reach dashboard and populate
    /api/stats (scan_alerts, syn_flood_alerts, dns_tunnel_alerts, blocked_total),
    /api/events (PORT_SCAN, SYN_FLOOD, DNS_TUNNEL), and
    /api/blocked (MALICIOUS blocks).
    """
    client = TestClient(app)

    # 1. Anomaly event: PORT_SCAN (contract §4.2)
    state.ingest({
        "event": "anomaly",
        "ts": 1710000000.100,
        "type": "PORT_SCAN",
        "detail": {"src_ip": "10.0.0.66", "target": "10.0.0.1", "ports_seen": 20},
    })

    # 2. Anomaly event: SYN_FLOOD
    state.ingest({
        "event": "anomaly",
        "ts": 1710000000.200,
        "type": "SYN_FLOOD",
        "detail": {"src_ip": "10.0.0.77", "target": "10.0.0.1", "syn_rate_pps": 800},
    })

    # 3. Anomaly event: DNS_TUNNEL (2 distinct events)
    for i in range(2):
        state.ingest({
            "event": "anomaly",
            "ts": 1710000000.300 + i,
            "type": "DNS_TUNNEL",
            "detail": {"src_ip": "10.0.0.88", "domain": f"tunnel{i}.exfil.xyz", "entropy": 4.6},
        })

    # 4. Blocked security events: MALICIOUS (2x) mirrored as app_classified (EventSink::emitAlert)
    malicious_domains = ["c2-malware.example.com", "phishing-bank.example.org"]
    for domain in malicious_domains:
        state.ingest({
            "event": "app_classified",
            "ts": 1710000000.400,
            "five_tuple": {
                "src_ip": "10.0.0.99",
                "src_port": 54321,
                "dst_ip": "198.51.100.1",
                "dst_port": 443,
                "proto": "TCP",
            },
            "app": domain,
            "bytes": 0,
            "blocked": True,
            "reason": "MALICIOUS",
        })

    # 5. Acceptance check: /api/events returns all 4 anomaly events
    res_events = client.get("/api/events")
    assert res_events.status_code == 200
    events_data = res_events.json()
    assert len(events_data) == 4
    event_types = [e["type"] for e in events_data]
    assert event_types.count("PORT_SCAN") == 1
    assert event_types.count("SYN_FLOOD") == 1
    assert event_types.count("DNS_TUNNEL") == 2

    # 6. Acceptance check: /api/blocked shows the 2 MALICIOUS blocks
    res_blocked = client.get("/api/blocked")
    assert res_blocked.status_code == 200
    blocked_data = res_blocked.json()
    assert len(blocked_data) == 2
    assert all(b["blocked"] is True for b in blocked_data)
    assert all(b["reason"] == "MALICIOUS" for b in blocked_data)
    assert {b["app"] for b in blocked_data} == set(malicious_domains)

    # 7. Acceptance check: /api/stats shows accurate counters
    res_stats = client.get("/api/stats")
    assert res_stats.status_code == 200
    stats_data = res_stats.json()
    assert stats_data["scan_alerts"] == 1
    assert stats_data["syn_flood_alerts"] == 1
    assert stats_data["dns_tunnel_alerts"] == 2
    assert stats_data["blocked_total"] == 2
    assert stats_data["blocked_reasons"].get("MALICIOUS") == 2

    # 8. Acceptance check: Engine stats frame updates totals without erasing alert/blocked counters
    state.ingest({
        "event": "stats",
        "ts": 1710000001.0,
        "total_packets": 650,
        "total_bytes": 48000,
        "throughput_bps": 15000.0,
        "app_breakdown": {"Unknown": 648, "c2-malware.example.com": 1, "phishing-bank.example.org": 1},
        "blocked_total": 2,
        "blocked_reasons": {"IP": 0, "PORT": 0, "APP": 0, "DOMAIN": 0, "MALICIOUS": 2, "VPN_DETECTED": 0},
        "scan_alerts": 1,
        "syn_flood_alerts": 1,
        "dns_tunnel_alerts": 2,
    })

    res_stats_post = client.get("/api/stats")
    assert res_stats_post.status_code == 200
    stats_post = res_stats_post.json()
    assert stats_post["total_packets"] == 650
    assert stats_post["total_bytes"] == 48000
    assert stats_post["scan_alerts"] == 1
    assert stats_post["syn_flood_alerts"] == 1
    assert stats_post["dns_tunnel_alerts"] == 2
    assert stats_post["blocked_total"] == 2
    assert stats_post["blocked_reasons"]["MALICIOUS"] == 2


def test_issue_9_handle_engine_connection_streaming():
    """Verify handle_engine_connection parses streaming JSON lines and broadcasts."""
    from dashboard.server import handle_engine_connection
    from unittest.mock import MagicMock

    async def _run_stream_test():
        reader = asyncio.StreamReader()
        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = ("127.0.0.1", 12345)
        mock_writer.close = MagicMock()

        # Create async mock for wait_closed
        async def dummy_wait_closed():
            pass
        mock_writer.wait_closed = dummy_wait_closed

        # Feed frames over the reader stream
        frames = (
            json.dumps({
                "event": "anomaly",
                "type": "PORT_SCAN",
                "detail": {"src_ip": "10.0.0.66", "target": "10.0.0.1"},
            }) + "\n" +
            json.dumps({
                "event": "app_classified",
                "app": "bad-host.org",
                "bytes": 0,
                "blocked": True,
                "reason": "MALICIOUS",
            }) + "\n"
        )
        reader.feed_data(frames.encode("utf-8"))
        reader.feed_eof()

        await handle_engine_connection(reader, mock_writer)

    asyncio.run(_run_stream_test())

    assert state.scan_alerts == 1
    assert state.blocked_total == 1
    assert len(state.events) == 1
    assert len(state.connections) == 1
    assert state.connections[0]["blocked"] is True
    assert state.connections[0]["reason"] == "MALICIOUS"


# ============================================================================
# 9. Issue #20 Verification: UI Polish, Accessibility, Empty States & Reports
# ============================================================================

def test_issue_20_ui_structure_accessibility_and_no_conflict_markers():
    client = TestClient(app)

    res_html = client.get("/")
    assert res_html.status_code == 200
    body = res_html.text

    # Ensure zero leftover git merge conflict markers
    for marker in ("<<<<<<<", "=======", ">>>>>>>"):
        assert marker not in body

    # Stage 01-04 visual hierarchy & active alerts prominence
    assert "Stage 01" in body
    assert "Stage 02" in body
    assert "Stage 03" in body
    assert "Stage 04" in body
    assert "Active Security Alerts" in body

    # Alert feed filtering across all 5 detector types + ALL
    for alert_type in ("ALL", "MALICIOUS", "VPN_DETECTED", "PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"):
        assert f'data-type="{alert_type}"' in body

    # Accessibility: no noisy aria-live on toolbar-stats, alert-feed-list, or footer
    assert '<div class="toolbar-stats">' in body
    assert '<span class="idle-pill" id="tb-idle-pill" aria-live="polite">' in body
    assert '<ul class="alert-feed-list" id="alert-feed-list">' in body
    assert '<span class="alert-count-badge" id="alert-feed-count" aria-live="polite">' in body
    assert '<footer class="statusbar">' in body
    assert 'id="footer-pause-btn" aria-pressed="false"' in body

    # Empty states for connections, alerts, and charts
    assert "No packets captured yet" in body
    assert "No active security alerts" in body
    assert "No throughput data yet" in body

    # Accessibility essentials
    assert ":focus-visible" in body
    assert 'aria-label=' in body
    assert 'role="tablist"' in body
    assert "/static/app.js" in body

    # Static JS asset served cleanly
    res_js = client.get("/static/app.js")
    assert res_js.status_code == 200
    assert "niceCeil" in res_js.text
    assert "escapeHtml" in res_js.text
    assert "security_alert" in res_js.text
    assert "transportProto" in res_js.text
    assert "footerPauseBtn" in res_js.text

    # Behavioral JS test for alert filtering (when node is available)
    import shutil
    import subprocess
    if shutil.which("node"):
        js_harness = r"""
const fs = require("fs");
const vm = require("vm");
const elements = {};
function makeEl(id) {
  return {
    id, textContent: "", _innerHTML: "", value: "", style: {},
    get innerHTML() { return this._innerHTML; },
    set innerHTML(v) { this._innerHTML = String(v); if (!v) this.children = []; },
    dataset: {}, children: [],
    classList: {
      _s: new Set(),
      add(c) { this._s.add(c); },
      remove(c) { this._s.delete(c); },
      toggle(c, b) { if (b) this._s.add(c); else this._s.delete(c); },
      contains(c) { return this._s.has(c); }
    },
    attributes: {},
    setAttribute(k, v) { this.attributes[k] = String(v); },
    getAttribute(k) { return this.attributes[k]; },
    appendChild(child) { this.children.push(child); },
    querySelectorAll() { return []; },
    addEventListener() {}
  };
}
["alert-feed-list", "alert-feed-count", "alert-autoscroll-chk"].forEach(id => elements[id] = makeEl(id));
const filterBtns = ["ALL", "MALICIOUS", "VPN_DETECTED", "PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"].map(t => {
  const b = makeEl("btn-" + t);
  b.dataset = { type: t };
  return b;
});
const ctx = {
  console, Date, Math, Set, Array, Object, Number, String, JSON,
  document: {
    getElementById: (id) => elements[id] || null,
    querySelectorAll: (sel) => sel === ".alert-filter-btn" ? filterBtns : [],
    createElement: (tag) => makeEl(tag),
  },
  window: { addEventListener() {} },
  location: { protocol: "http:", host: "127.0.0.1:8000" },
  WebSocket: { OPEN: 1 },
  setInterval() {},
  setTimeout() {},
};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync("dashboard/static/app.js", "utf8"), ctx);
ctx.addSecurityAlert({ event: "security_alert", alert_type: "MALICIOUS", detail: "bad.test", ts: 1710000001 });
ctx.addSecurityAlert({ event: "security_alert", alert_type: "VPN_DETECTED", detail: "WireGuard", ts: 1710000002 });
ctx.addSecurityAlert({ event: "anomaly", type: "PORT_SCAN", detail: { src_ip: "10.0.0.2" }, ts: 1710000003 });
ctx.addSecurityAlert({ event: "anomaly", type: "SYN_FLOOD", detail: { src_ip: "10.0.0.3" }, ts: 1710000004 });
ctx.addSecurityAlert({ event: "anomaly", type: "DNS_TUNNEL", detail: { src_ip: "10.0.0.4" }, ts: 1710000005 });
ctx.setAlertFilter("ALL");
if (elements["alert-feed-list"].children.length !== 5) throw new Error("Expected 5 alerts for ALL");
if (elements["alert-feed-count"].textContent !== "5 alerts") throw new Error("Expected '5 alerts'");
for (const t of ["MALICIOUS", "VPN_DETECTED", "PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"]) {
  ctx.setAlertFilter(t);
  if (elements["alert-feed-list"].children.length !== 1) throw new Error("Expected 1 alert for " + t);
  if (elements["alert-feed-count"].textContent !== "1 / 5 shown") throw new Error("Expected '1 / 5 shown' for " + t);
}
const dnsPkt = ctx.normalizeConn({ event: "app_classified", app: "DNS", five_tuple: { proto: "UDP", dst_port: 53, src_port: 51515, src_ip: "10.0.0.5", dst_ip: "8.8.8.8" }, bytes: 90 });
if (dnsPkt.protocol !== "DNS" || dnsPkt.transportProto !== "UDP") throw new Error("UDP DNS transport not preserved");
ctx.addSecurityAlert({ event: "security_alert", alert_type: "MALICIOUS", detail: "<img src=x onerror=alert(1)>", ts: 1710000006 });
ctx.setAlertFilter("MALICIOUS");
if (elements["alert-feed-list"].children.some(li => li.innerHTML.includes("<img"))) throw new Error("Unescaped HTML in alert feed");
"""
        proc = subprocess.run(["node", "-e", js_harness], capture_output=True, text=True, check=False)
        assert proc.returncode == 0, f"JS alert filter / UDP DNS test failed: {proc.stderr}"


def test_issue_20_reports_empty_states_and_alerts_alignment():
    client = TestClient(app)

    # Empty state HTML & PDF reports
    empty_html = client.get("/api/report?format=html")
    assert empty_html.status_code == 200
    assert "No security alerts recorded during this session." in empty_html.text
    assert "No application traffic recorded yet." in empty_html.text
    assert "No blocked traffic recorded." in empty_html.text

    empty_pdf = client.get("/api/report?format=pdf")
    assert empty_pdf.status_code == 200
    assert empty_pdf.content.startswith(b"%PDF")
    empty_pdf_text = _extract_pdf_text(empty_pdf.content)
    assert "No security alerts recorded during this session." in empty_pdf_text
    assert "No application traffic recorded yet." in empty_pdf_text
    assert "No blocked traffic recorded." in empty_pdf_text

    # Populated with security alert + traffic
    state.ingest({
        "event": "security_alert",
        "ts": 1710000000.5,
        "alert_type": "MALICIOUS",
        "app_or_domain": "evil.example.net",
        "blocked": True,
        "reason": "MALICIOUS",
        "detail": "URLhaus match: evil.example.net",
    })
    state.ingest({
        "event": "app_classified",
        "app": "Google",
        "bytes": 2048,
        "blocked": False,
    })

    pop_html = client.get("/api/report?format=html")
    assert pop_html.status_code == 200
    assert "total security alert(s) recorded across detectors" in pop_html.text
    assert "evil.example.net" in pop_html.text
    assert "MALICIOUS" in pop_html.text
    assert "Google" in pop_html.text

    pop_pdf = client.get("/api/report?format=pdf")
    assert pop_pdf.status_code == 200
    assert pop_pdf.content.startswith(b"%PDF")
    pop_pdf_text = _extract_pdf_text(pop_pdf.content)
    assert "evil.example.net" in pop_pdf_text
    assert "(MALICIOUS)" in pop_pdf_text
    assert "(Google)" in pop_pdf_text


def test_issue_20_handle_engine_connection_broadcasts_security_alert():
    from unittest.mock import AsyncMock, MagicMock
    from dashboard.server import manager

    async def _run():
        reader = asyncio.StreamReader()
        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = ("127.0.0.1", 55555)
        mock_writer.close = MagicMock()

        async def dummy_wait_closed():
            pass
        mock_writer.wait_closed = dummy_wait_closed

        fake_ws = MagicMock()
        fake_ws.send_json = AsyncMock()
        manager._clients.add(fake_ws)
        try:
            alert_payload = {
                "event": "security_alert",
                "alert_type": "VPN_DETECTED",
                "app_or_domain": "WireGuard",
                "blocked": False,
                "detail": "WireGuard tunnel detected",
            }
            reader.feed_data((json.dumps(alert_payload) + "\n").encode("utf-8"))
            reader.feed_eof()
            await handle_engine_connection(reader, mock_writer)
            assert fake_ws.send_json.await_count == 1
            sent = fake_ws.send_json.await_args.args[0]
            assert sent["event"] == "security_alert"
            assert sent["alert_type"] == "VPN_DETECTED"
        finally:
            manager._clients.discard(fake_ws)

    asyncio.run(_run())


# ============================================================================
# 10. Issue #15 Verification: GET /health + Graceful Shutdown
# ============================================================================

def test_health_endpoint():
    """Verify Issue #15: GET /health returns 200 with uptime and IPC/engine status."""
    client = TestClient(app)
    for _ in range(3):
        res = client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert isinstance(data["uptime_seconds"], (int, float))
        assert data["uptime_seconds"] >= 0
        assert isinstance(data["engine_connected"], bool)
        assert isinstance(data["active_engine_connections"], int)
        assert "ipc" in data
        assert "host" in data["ipc"]
        assert "port" in data["ipc"]
        assert isinstance(data["ipc"]["listening"], bool)


def test_graceful_shutdown_cleans_up_ipc_and_children():
    """Verify Issue #15: shutdown closes IPC socket, active engine conns, and child processes."""
    import subprocess
    import sys as _sys
    import dashboard.server as srv

    async def _run():
        # Start a temporary IPC server on an ephemeral port and register it
        temp_server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        port = temp_server.sockets[0].getsockname()[1]
        srv._ipc_server = temp_server
        assert temp_server.is_serving()

        # Open a client connection to simulate an active engine writer
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        srv._active_engine_conns.add(writer)

        # Spawn a harmless child process and register it for supervision cleanup
        proc = subprocess.Popen([_sys.executable, "-c", "import time; time.sleep(30)"])
        srv.register_child_process(proc)
        assert proc.poll() is None

        try:
            await srv.shutdown_ipc_and_children()
            assert srv._ipc_server is None
            assert not temp_server.is_serving()
            assert writer.is_closing()
            assert len(srv._active_engine_conns) == 0
            assert len(srv._supervised_processes) == 0
            assert proc.poll() is not None
        finally:
            reader.feed_eof()
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=2)

    asyncio.run(_run())


def test_lifespan_releases_ipc_port_on_restart():
    """Verify lifespan startup/shutdown cleanly releases the IPC port so restart succeeds."""
    import socket
    import dashboard.server as srv

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        isolated_port = s.getsockname()[1]

    orig_port = srv.ENGINE_PORT
    srv.ENGINE_PORT = isolated_port
    try:
        async def _run():
            async with srv.lifespan(app):
                await asyncio.sleep(0.05)
                assert srv._ipc_server is not None
                assert srv._ipc_server.is_serving()
                # Connect an active engine client to verify shutdown does not deadlock
                reader, writer = await asyncio.open_connection("127.0.0.1", isolated_port)
                await asyncio.sleep(0.05)
                assert len(srv._active_engine_conns) == 1
            assert srv._ipc_server is None
            assert len(srv._active_engine_conns) == 0
            assert await asyncio.wait_for(reader.read(1), timeout=1.0) == b""
            writer.close()

            # Immediate restart should bind cleanly without port conflict
            async with srv.lifespan(app):
                await asyncio.sleep(0.05)
                assert srv._ipc_server is not None
                assert srv._ipc_server.is_serving()
            assert srv._ipc_server is None

        asyncio.run(asyncio.wait_for(_run(), timeout=5.0))
    finally:
        srv.ENGINE_PORT = orig_port


# ============================================================================
# 11. Issue #18 Verification: WebSocket Push Alerts
# ============================================================================

def test_issue_18_ws_broadcasts_anomaly_and_security_alert():
    """Verify Issue #18: anomaly and security_alert frames are broadcast immediately over WS."""
    from dashboard.server import manager

    sent_frames: list[dict] = []

    class DummyWS:
        async def send_json(self, data: dict):
            sent_frames.append(data)

    dummy_ws = DummyWS()

    async def _run():
        manager._clients.add(dummy_ws)
        try:
            events = [
                {
                    "event": "anomaly",
                    "ts": 1710000010.0,
                    "type": "PORT_SCAN",
                    "detail": {"src_ip": "10.0.0.66", "target": "10.0.0.1"},
                },
                {
                    "event": "security_alert",
                    "ts": 1710000011.0,
                    "alert_type": "MALICIOUS",
                    "detail": "URLhaus match: bad.example",
                    "app_or_domain": "bad.example",
                    "blocked": True,
                    "reason": "MALICIOUS",
                },
                {
                    "event": "security_alert",
                    "ts": 1710000012.0,
                    "alert_type": "VPN_DETECTED",
                    "detail": "WireGuard detected",
                    "app_or_domain": "WireGuard",
                    "blocked": False,
                    "reason": "",
                },
            ]
            raw = "\n".join(json.dumps(e) for e in events).encode("utf-8") + b"\n"
            reader = asyncio.StreamReader()
            reader.feed_data(raw)
            reader.feed_eof()

            class MockWriter:
                def get_extra_info(self, name):
                    return ("127.0.0.1", 9000)
                def close(self):
                    pass
                async def wait_closed(self):
                    pass

            await handle_engine_connection(reader, MockWriter())
        finally:
            manager._clients.discard(dummy_ws)

    asyncio.run(_run())

    assert len(sent_frames) == 3
    assert [f["event"] for f in sent_frames] == ["anomaly", "security_alert", "security_alert"]
    assert all("id" in f for f in sent_frames)
    assert len({f["id"] for f in sent_frames}) == 3


def test_issue_18_ws_reconnect_and_app_js_dedup():
    """Verify WS reconnect resumes cleanly and app.js uses pollEvents as reconnect/fallback."""
    client = TestClient(app)

    with client.websocket_connect("/ws") as ws1:
        snap1 = ws1.receive_json()
        assert snap1["total_packets"] == 0

    # Alert arrives while socket is dropped
    state.ingest({
        "event": "security_alert",
        "alert_type": "MALICIOUS",
        "detail": "c2.bad.xyz",
        "app_or_domain": "c2.bad.xyz",
        "blocked": True,
        "reason": "MALICIOUS",
    })

    # Reconnect receives updated snapshot and /api/events exposes stable id for dedup
    with client.websocket_connect("/ws") as ws2:
        snap2 = ws2.receive_json()
        assert snap2["malicious_domain_blocks"] == 1

    events = client.get("/api/events").json()
    assert len(events) == 1
    assert "id" in events[0]

    app_js = os.path.join(os.path.dirname(__file__), "static", "app.js")
    with open(app_js, encoding="utf-8") as f:
        src = f.read()
    assert "seenAlertKeys" in src  # issue-20 renamed seenEventKeys → seenAlertKeys
    # Issue-20 architecture uses fetchInitialEvents() on reconnect; dedup via seenAlertKeys
    assert "fetchInitialEvents" in src


# ============================================================================
# 12. Issue #19 Verification: Stage 04 Cards and Badge Styles
# ============================================================================

def test_issue_19_stage04_cards_and_badge_styles():
    """Verify Stage 04 stat cards, pills, and MALICIOUS/VPN_DETECTED badge styles exist cleanly."""
    client = TestClient(app)
    res = client.get("/")
    assert res.status_code == 200
    body = res.text

    assert "<<<<<<<" not in body
    assert ">>>>>>>" not in body
    assert 'id="s-malicious"' in body
    assert 'id="s-vpn"' in body
    assert 'id="pill-malicious"' in body
    assert 'id="pill-vpn"' in body
    assert ".badge.MALICIOUS" in body
    assert ".badge.VPN_DETECTED" in body
    assert ".badge.VPN_FLAGGED" in body

