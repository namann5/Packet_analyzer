#!/usr/bin/env python3
"""
Track C — Standalone Traffic & Security Anomaly Simulator
Streams contract-compliant JSON events (§4.2 & §4.3) over TCP to the Dashboard IPC server (127.0.0.1:9000).
Enables full live UI demonstrations, testing, and verification without requiring live NIC capture or C++ builds.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import sys
import time


APPS = [
    ("Google", 443, "TCP", 0.22),
    ("YouTube", 443, "TCP", 0.18),
    ("Netflix", 443, "TCP", 0.14),
    ("GitHub", 443, "TCP", 0.10),
    ("Spotify", 443, "TCP", 0.08),
    ("WireGuard", 51820, "UDP", 0.06),
    ("OpenVPN", 1194, "UDP", 0.05),
    ("Zoom", 8801, "UDP", 0.06),
    ("DNS", 53, "UDP", 0.06),
    ("Cloudflare", 443, "TCP", 0.03),
    ("Unknown", 8080, "TCP", 0.02),
]

BLOCK_REASONS = ["DOMAIN", "APP", "IP", "MALICIOUS"]
ANOMALY_TYPES = ["PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"]


def generate_packet_event(vpn_action: str = "flag-only") -> tuple[dict, dict | None]:
    # Pick app based on weight
    r = random.random()
    cumulative = 0.0
    chosen_app, dst_port, proto, _ = APPS[0]
    for app_name, port, protocol, weight in APPS:
        cumulative += weight
        if r <= cumulative:
            chosen_app = app_name
            dst_port = port
            proto = protocol
            break

    src_host = random.randint(2, 254)
    dst_a, dst_b = random.randint(1, 200), random.randint(1, 254)
    pkt_len = random.randint(64, 1514)

    is_vpn = chosen_app in ("WireGuard", "OpenVPN")
    is_malicious = random.random() < 0.04

    security_alert = None

    if is_vpn:
        block_vpn = (vpn_action.lower() in ("block", "1", "true"))
        blocked = block_vpn
        reason = "VPN_DETECTED" if block_vpn else None

        security_alert = {
            "event": "security_alert",
            "ts": round(time.time(), 3),
            "alert_type": "VPN_DETECTED",
            "five_tuple": {
                "src_ip": f"192.168.1.{src_host}",
                "src_port": random.randint(1024, 65535),
                "dst_ip": f"{dst_a}.{dst_b}.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "dst_port": dst_port,
                "proto": proto,
            },
            "app_or_domain": chosen_app,
            "blocked": block_vpn,
            "reason": "VPN_DETECTED",
            "detail": f"{chosen_app} tunnel (policy: {vpn_action})",
        }
    elif is_malicious:
        blocked = True
        reason = "MALICIOUS"
        malicious_domain = random.choice([
            "bad-malware-domain.com", "c2-server.evilcorp.biz",
            "ransomware-distrib.net", "urlhaus-test-malware.org"
        ])
        security_alert = {
            "event": "security_alert",
            "ts": round(time.time(), 3),
            "alert_type": "MALICIOUS",
            "five_tuple": {
                "src_ip": f"192.168.1.{src_host}",
                "src_port": random.randint(1024, 65535),
                "dst_ip": f"{dst_a}.{dst_b}.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "dst_port": dst_port,
                "proto": proto,
            },
            "app_or_domain": malicious_domain,
            "blocked": True,
            "reason": "MALICIOUS",
            "detail": f"Matched URLhaus blocklist: {malicious_domain}",
        }
    else:
        blocked = random.random() < 0.08  # ~8% general rule block
        reason = random.choice(BLOCK_REASONS) if blocked else None

    pkt_event = {
        "event": "app_classified",
        "ts": round(time.time(), 3),
        "five_tuple": {
            "src_ip": f"192.168.1.{src_host}",
            "src_port": random.randint(1024, 65535),
            "dst_ip": f"{dst_a}.{dst_b}.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "dst_port": dst_port,
            "proto": proto,
        },
        "app": chosen_app,
        "bytes": pkt_len,
        "blocked": blocked,
        "reason": reason,
    }

    return pkt_event, security_alert


def generate_anomaly_event() -> dict:
    atype = random.choice(ANOMALY_TYPES)
    src_ip = f"192.168.1.{random.randint(50, 150)}"
    target_ip = f"10.0.0.{random.randint(1, 20)}"

    detail: dict = {"src_ip": src_ip, "target": target_ip}
    if atype == "PORT_SCAN":
        detail["ports_seen"] = random.randint(18, 120)
        detail["window_sec"] = 5
    elif atype == "SYN_FLOOD":
        detail["syn_rate_pps"] = random.randint(600, 2500)
        detail["action"] = "ALERT_EMITTED"
    elif atype == "DNS_TUNNEL":
        detail["domain"] = f"x{random.randint(100000, 999999)}.sub.tunnel-exfil.xyz"
        detail["entropy"] = round(random.uniform(4.2, 5.8), 2)

    return {
        "event": "anomaly",
        "ts": round(time.time(), 3),
        "type": atype,
        "detail": detail,
    }


def main() -> None:
    default_vpn_action = os.getenv("VPN_ACTION", "").lower().strip()
    if not default_vpn_action:
        dash_block = os.getenv("DASHBOARD_BLOCK_VPN", "").lower().strip()
        if dash_block in ("1", "true", "block", "yes"):
            default_vpn_action = "block"
        else:
            default_vpn_action = "flag-only"

    parser = argparse.ArgumentParser(
        description="Packet Analyzer — Live Traffic & Security Feed Simulator"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Dashboard IPC host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="Dashboard IPC port (default: 9000)")
    parser.add_argument("--rate", type=float, default=25.0, help="Packets per second (default: 25)")
    parser.add_argument("--anomalies", type=float, default=0.08, help="Anomaly trigger chance per sec (default: 0.08)")
    parser.add_argument("--duration", type=int, default=0, help="Duration in seconds (0 = infinite)")
    parser.add_argument(
        "--vpn-action",
        default=default_vpn_action,
        choices=["block", "flag-only"],
        help="Action on detected VPN: 'block' or 'flag-only' (default from env or flag-only)",
    )

    args = parser.parse_args()

    print("=" * 65)
    print("📡  PACKET ANALYZER — TRACK C FEED SIMULATOR")
    print(f"    Target Server: {args.host}:{args.port}")
    print(f"    Packet Rate:   {args.rate} pkts/sec")
    print(f"    VPN Action:    {args.vpn_action.upper()}")
    print(f"    Anomaly Rate:  {args.anomalies * 100:.1f}% per sec")
    print(f"    Duration:      {'Infinite' if args.duration == 0 else f'{args.duration}s'}")
    print("=" * 65)

    delay = 1.0 / max(1.0, args.rate)
    start_time = time.time()
    total_sent = 0
    anomalies_sent = 0

    while True:
        try:
            print(f"[+] Connecting to dashboard at {args.host}:{args.port}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((args.host, args.port))
            print(f"[✓] Connected successfully! Streaming events...\n")
            break
        except ConnectionRefusedError:
            print("[-] Connection refused. Ensure dashboard server is running (uvicorn dashboard.server:app).")
            print("    Retrying in 2 seconds (Ctrl+C to abort)...")
            time.sleep(2.0)
        except KeyboardInterrupt:
            print("\nAborted.")
            sys.exit(0)

    try:
        last_stat_time = time.time()
        while True:
            now = time.time()
            if args.duration > 0 and (now - start_time) >= args.duration:
                print(f"\n[✓] Finished simulation duration of {args.duration}s.")
                break

            # 1. Send packet event and optional security alert (VPN/Malicious)
            pkt, sec_alert = generate_packet_event(vpn_action=args.vpn_action)
            raw_pkt = (json.dumps(pkt) + "\n").encode("utf-8")
            sock.sendall(raw_pkt)
            total_sent += 1

            if sec_alert:
                raw_alert = (json.dumps(sec_alert) + "\n").encode("utf-8")
                sock.sendall(raw_alert)
                anomalies_sent += 1
                action_tag = "BLOCKED" if sec_alert.get("blocked") else "FLAGGED"
                print(f" [!] Injected Security Alert: {sec_alert['alert_type']} [{action_tag}] ({sec_alert['app_or_domain']})")

            # 2. Maybe send anomaly event
            if random.random() < (args.anomalies * delay):
                anomaly = generate_anomaly_event()
                raw_anomaly = (json.dumps(anomaly) + "\n").encode("utf-8")
                sock.sendall(raw_anomaly)
                anomalies_sent += 1
                print(f" [!] Injected Security Anomaly: {anomaly['type']} from {anomaly['detail'].get('src_ip')}")

            # Status heartbeat in terminal
            if now - last_stat_time >= 2.0:
                elapsed = now - start_time
                pps = total_sent / max(1.0, elapsed)
                print(f" -> Sent {total_sent:,} packets ({pps:.1f} pps) | {anomalies_sent} anomalies", end="\r")
                last_stat_time = now

            time.sleep(delay)

    except KeyboardInterrupt:
        print(f"\n\n[!] Stopped by user.")
    except (BrokenPipeError, ConnectionResetError, OSError) as e:
        print(f"\n[-] Socket disconnected: {e}")
    finally:
        sock.close()
        elapsed = round(time.time() - start_time, 2)
        print(f"[✓] Summary: {total_sent:,} packet events and {anomalies_sent} anomalies sent in {elapsed}s.")


if __name__ == "__main__":
    main()
