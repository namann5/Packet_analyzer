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

    res = client.get("/api/report?format=html")
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    assert "DPI Report" in res.text
    assert "Google" in res.text


def test_api_report_pdf():
    client = TestClient(app)
    state.ingest({
        "event": "app_classified",
        "app": "Google",
        "bytes": 1000,
        "blocked": True,
        "reason": "DOMAIN",
    })

    res = client.get("/api/report?format=pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF")


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

    pkt = generate_packet_event()
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
# 7. Issue #9 Verification: Engine Anomaly & Block Events IPC Propagation
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


@pytest.mark.asyncio
async def test_issue_9_handle_engine_connection_streaming():
    """Verify handle_engine_connection parses streaming JSON lines and broadcasts."""
    from dashboard.server import handle_engine_connection
    from unittest.mock import MagicMock

    reader = asyncio.StreamReader()
    mock_writer = MagicMock()
    mock_writer.get_extra_info.return_value = ("127.0.0.1", 12345)
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = MagicMock()

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

    assert state.scan_alerts == 1
    assert state.blocked_total == 1
    assert len(state.events) == 1
    assert len(state.connections) == 1
    assert state.connections[0]["blocked"] is True
    assert state.connections[0]["reason"] == "MALICIOUS"


