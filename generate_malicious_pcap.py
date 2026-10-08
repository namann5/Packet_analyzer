#!/usr/bin/env python3
"""
Generate a malicious PCAP with crafted attack traffic for Track B testing:
- Port scan (20+ ports)
- SYN flood (600+ SYN-only packets)
- DNS tunneling queries (high entropy, depth >= 4)
- URLhaus malicious domain queries and SNIs
- WireGuard VPN handshake initiation (UDP 51820, type 1)
- OpenVPN reset (UDP 1194, opcode 0x38)
- IPSec ESP/AH (IP protocols 50 & 51)
- Known VPN CIDR range traffic (10.8.0.0/24)
"""

import struct
import random

class PCAPWriter:
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        self.write_global_header()
        self.timestamp = 1710000000

    def write_global_header(self):
        # Magic: 0xa1b2c3d4, version 2.4, timezone 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)

    def write_packet(self, data, ts_sec=None, ts_usec=None):
        if ts_sec is None:
            ts_sec = self.timestamp
        if ts_usec is None:
            ts_usec = random.randint(0, 999999)
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)

    def close(self):
        self.file.close()

def create_ethernet_header(src_mac='00:11:22:33:44:55', dst_mac='aa:bb:cc:dd:ee:ff', ethertype=0x0800):
    return bytes.fromhex(dst_mac.replace(':', '')) + \
           bytes.fromhex(src_mac.replace(':', '')) + \
           struct.pack('>H', ethertype)

def _ones_complement_checksum(data):
    """RFC 1071 Internet checksum over a byte string."""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

def create_ip_header(src_ip, dst_ip, protocol, payload_len):
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(1, 65535)
    flags_frag = 0x4000
    ttl = 64
    header = struct.pack('>BBHHHBBH', version_ihl, tos, total_len, ident, flags_frag, ttl, protocol, 0)
    header += bytes([int(x) for x in src_ip.split('.')])
    header += bytes([int(x) for x in dst_ip.split('.')])
    checksum = _ones_complement_checksum(header)
    header = header[:10] + struct.pack('>H', checksum) + header[12:]
    return header

def create_tcp_header(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b''):
    data_offset = 5 << 4
    window = 65535
    urgent = 0
    header = struct.pack('>HHIIBBHHH', src_port, dst_port, seq, ack, data_offset, flags, window, 0, urgent)
    checksum = _l4_checksum(src_ip, dst_ip, 6, header, payload)
    header = header[:16] + struct.pack('>H', checksum) + header[18:]
    return header

def _l4_checksum(src_ip, dst_ip, protocol, l4_header, payload):
    pseudo = bytes([int(x) for x in src_ip.split('.')]) + \
             bytes([int(x) for x in dst_ip.split('.')]) + \
             struct.pack('>BBH', 0, protocol, len(l4_header) + len(payload))
    return _ones_complement_checksum(pseudo + l4_header + payload)

def create_udp_header(src_ip, dst_ip, src_port, dst_port, payload=b''):
    length = 8 + len(payload)
    header = struct.pack('>HHHH', src_port, dst_port, length, 0)
    checksum = _l4_checksum(src_ip, dst_ip, 17, header, payload)
    if checksum == 0:
        checksum = 0xFFFF
    header = header[:6] + struct.pack('>H', checksum) + header[8:]
    return header

def create_dns_query(domain):
    txid = struct.pack('>H', random.randint(1, 65535))
    flags = struct.pack('>H', 0x0100)
    counts = struct.pack('>HHHH', 1, 0, 0, 0)
    question = b''
    for label in domain.split('.'):
        question += struct.pack('B', len(label)) + label.encode('ascii')
    question += struct.pack('B', 0)
    question += struct.pack('>HH', 1, 1)
    return txid + flags + counts + question

def create_tls_client_hello(sni):
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack('>BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0x0000, len(sni_list)) + sni_list
    extensions_data = struct.pack('>H', len(sni_ext)) + sni_ext

    client_version = struct.pack('>H', 0x0303)
    random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
    session_id = struct.pack('B', 0)
    cipher_suites = struct.pack('>H', 4) + struct.pack('>HH', 0x1301, 0x1302)
    compression = struct.pack('BB', 1, 0)
    body = client_version + random_bytes + session_id + cipher_suites + compression + extensions_data

    handshake = struct.pack('B', 0x01) + struct.pack('>I', len(body))[1:] + body
    record = struct.pack('B', 0x16) + struct.pack('>H', 0x0301) + struct.pack('>H', len(handshake)) + handshake
    return record

def main(output_file='test_malicious.pcap'):
    writer = PCAPWriter(output_file)
    eth = create_ethernet_header()
    base_ts = 1710000000

    print(f"Generating crafted attack traffic into '{output_file}'...")

    # 1. Normal traffic baseline
    dns_normal = create_dns_query('www.google.com')
    udp_dns = create_udp_header('192.168.1.100', '8.8.8.8', 53123, 53, dns_normal)
    ip_dns = create_ip_header('192.168.1.100', '8.8.8.8', 17, len(udp_dns) + len(dns_normal))
    writer.write_packet(eth + ip_dns + udp_dns + dns_normal, ts_sec=base_ts, ts_usec=100000)

    # 2. Port Scan: 192.168.1.105 scans 20 different ports on target 10.0.0.1 within 2 seconds
    scan_src = '192.168.1.105'
    scan_dst = '10.0.0.1'
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080]
    for i, port in enumerate(scan_ports):
        tcp = create_tcp_header(scan_src, scan_dst, 50000 + i, port, 1000 + i, 0, 0x02) # SYN
        ip = create_ip_header(scan_src, scan_dst, 6, len(tcp))
        writer.write_packet(eth + ip + tcp, ts_sec=base_ts + 1, ts_usec=i * 20000)
    print(f"  [+] Port scan: 20 ports probed on {scan_dst} by {scan_src}")

    # 3. SYN Flood: 600 SYN-only packets targeting 10.0.0.50:80 within a 1-second window
    flood_dst = '10.0.0.50'
    for i in range(600):
        fake_src = f"172.16.{i // 250}.{(i % 250) + 1}"
        tcp = create_tcp_header(fake_src, flood_dst, 10000 + (i % 50000), 80, i * 100, 0, 0x02) # SYN-only, 0 payload
        ip = create_ip_header(fake_src, flood_dst, 6, len(tcp))
        writer.write_packet(eth + ip + tcp, ts_sec=base_ts + 2, ts_usec=(i * 1500) % 999999)
    print(f"  [+] SYN flood: 600 SYN packets targeting {flood_dst}")

    # 4. DNS Tunneling: Queries with depth >= 4 and high-entropy base64/hex label > 20 chars
    tunnel_queries = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4.v1.data.tunnel.evilcorp.com",
        "a9f8b7c6d5e4f3a2b1c0d9e8f7a6b5c43210fe.v2.data.tunnel.evilcorp.com",
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1f.exfil.dns.badactor.net"
    ]
    for i, tq in enumerate(tunnel_queries):
        dns_tunnel = create_dns_query(tq)
        udp_t = create_udp_header('192.168.1.120', '8.8.8.8', 55000 + i, 53, dns_tunnel)
        ip_t = create_ip_header('192.168.1.120', '8.8.8.8', 17, len(udp_t) + len(dns_tunnel))
        writer.write_packet(eth + ip_t + udp_t + dns_tunnel, ts_sec=base_ts + 3, ts_usec=i * 50000)
    print(f"  [+] DNS tunneling: {len(tunnel_queries)} deep/high-entropy queries")

    # 5. Malicious URLhaus domains:
    # 5a. DNS query for bad-malware-domain.com
    mal_dns = create_dns_query('bad-malware-domain.com')
    udp_m = create_udp_header('192.168.1.130', '8.8.8.8', 54001, 53, mal_dns)
    ip_m = create_ip_header('192.168.1.130', '8.8.8.8', 17, len(udp_m) + len(mal_dns))
    writer.write_packet(eth + ip_m + udp_m + mal_dns, ts_sec=base_ts + 4, ts_usec=10000)

    # 5b. TLS SNI for c2-server.evilcorp.biz
    tls_mal = create_tls_client_hello('c2-server.evilcorp.biz')
    tcp_mal = create_tcp_header('192.168.1.130', '198.51.100.99', 54002, 443, 2000, 0, 0x18, tls_mal)
    ip_mal = create_ip_header('192.168.1.130', '198.51.100.99', 6, len(tcp_mal) + len(tls_mal))
    writer.write_packet(eth + ip_mal + tcp_mal + tls_mal, ts_sec=base_ts + 4, ts_usec=20000)
    print(f"  [+] URLhaus matches: bad-malware-domain.com (DNS) & c2-server.evilcorp.biz (TLS SNI)")

    # 6. WireGuard Handshake Initiation packet: UDP 51820, Type 1, 3 zero reserved bytes, 148 bytes
    wg_payload = bytearray(148)
    wg_payload[0] = 0x01 # Handshake Initiation
    wg_payload[1] = 0x00 # Reserved
    wg_payload[2] = 0x00 # Reserved
    wg_payload[3] = 0x00 # Reserved
    for j in range(4, 148):
        wg_payload[j] = random.randint(0, 255)
    udp_wg = create_udp_header('192.168.1.140', '198.51.100.20', 51820, 51820, bytes(wg_payload))
    ip_wg = create_ip_header('192.168.1.140', '198.51.100.20', 17, len(udp_wg) + len(wg_payload))
    writer.write_packet(eth + ip_wg + udp_wg + bytes(wg_payload), ts_sec=base_ts + 5, ts_usec=10000)
    print(f"  [+] WireGuard VPN: UDP 51820 Type 1 message")

    # 7. OpenVPN packet: UDP 1194, Opcode 0x38 (P_CONTROL_HARD_RESET_CLIENT_V1 / V2)
    ovpn_payload = bytearray([0x38, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]) + bytes(40)
    udp_ovpn = create_udp_header('192.168.1.145', '198.51.100.21', 1194, 1194, bytes(ovpn_payload))
    ip_ovpn = create_ip_header('192.168.1.145', '198.51.100.21', 17, len(udp_ovpn) + len(ovpn_payload))
    writer.write_packet(eth + ip_ovpn + udp_ovpn + bytes(ovpn_payload), ts_sec=base_ts + 5, ts_usec=20000)
    print(f"  [+] OpenVPN: UDP 1194 Opcode 0x38")

    # 8. IPSec: IP Protocol 50 (ESP) & 51 (AH)
    esp_payload = bytes([0x00, 0x01, 0x02, 0x03]) + bytes(32) # SPI + seq
    ip_esp = create_ip_header('192.168.1.150', '198.51.100.22', 50, len(esp_payload))
    writer.write_packet(eth + ip_esp + esp_payload, ts_sec=base_ts + 5, ts_usec=30000)

    ah_payload = bytes([0x00, 0x04, 0x00, 0x00]) + bytes(20)
    ip_ah = create_ip_header('192.168.1.151', '198.51.100.23', 51, len(ah_payload))
    writer.write_packet(eth + ip_ah + ah_payload, ts_sec=base_ts + 5, ts_usec=40000)
    print(f"  [+] IPSec: Protocols 50 (ESP) & 51 (AH)")

    # 9. Known VPN IP Range match: 10.8.0.50 (in 10.8.0.0/24)
    tcp_cidr = create_tcp_header('10.8.0.50', '142.250.185.206', 49152, 443, 5000, 0, 0x02)
    ip_cidr = create_ip_header('10.8.0.50', '142.250.185.206', 6, len(tcp_cidr))
    writer.write_packet(eth + ip_cidr + tcp_cidr, ts_sec=base_ts + 5, ts_usec=50000)
    print(f"  [+] VPN IP range: 10.8.0.50 (matches 10.8.0.0/24)")

    writer.close()
    print(f"Done! Created '{output_file}'.")

if __name__ == '__main__':
    main()
