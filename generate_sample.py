# ============================================================================
# Script tạo file pcap mẫu chứa traffic DDoS giả lập
# Sử dụng để test công cụ DDoS PCAP Analyzer
# ============================================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scapy.all import (
    IP, TCP, UDP, ICMP, Raw, Ether,
    wrpcap, RandShort
)
import random
import time


def generate_sample_pcap(output_file="sample_ddos.pcap"):
    """
    Tạo file pcap mẫu chứa các loại traffic DDoS:
    - SYN Flood
    - UDP Flood
    - ICMP Flood
    - HTTP Flood
    - Traffic bình thường
    """
    packets = []
    base_time = time.time()

    # IP đích (server bị tấn công)
    target_ip = "192.168.1.100"

    # ── 1. Traffic bình thường (background) ──
    print("[*] Tao traffic binh thuong...")
    normal_ips = [f"10.0.0.{i}" for i in range(1, 20)]
    for i in range(200):
        src = random.choice(normal_ips)
        # TCP connection bình thường
        pkt = IP(src=src, dst=target_ip) / TCP(
            sport=RandShort(), dport=random.choice([80, 443, 8080, 22, 3306]),
            flags="S"
        )
        pkt.time = base_time + i * 0.05
        packets.append(pkt)

        # ACK response
        ack = IP(src=src, dst=target_ip) / TCP(
            sport=RandShort(), dport=80, flags="A"
        )
        ack.time = base_time + i * 0.05 + 0.01
        packets.append(ack)

    # ── 2. SYN Flood Attack ──
    print("[*] Tao SYN Flood attack...")
    attacker_syn = "172.16.0.50"
    attacker_syn2 = "172.16.0.51"
    for i in range(800):
        pkt = IP(src=attacker_syn, dst=target_ip) / TCP(
            sport=RandShort(), dport=80, flags="S"
        )
        # 800 SYN packets trong 3 giây = ~267 pkt/s
        pkt.time = base_time + 5.0 + i * 0.00375
        packets.append(pkt)

    for i in range(500):
        pkt = IP(src=attacker_syn2, dst=target_ip) / TCP(
            sport=RandShort(), dport=443, flags="S"
        )
        pkt.time = base_time + 5.0 + i * 0.005
        packets.append(pkt)

    # ── 3. UDP Flood Attack ──
    print("[*] Tao UDP Flood attack...")
    attacker_udp = "172.16.0.100"
    for i in range(1200):
        pkt = IP(src=attacker_udp, dst=target_ip) / UDP(
            sport=RandShort(), dport=random.randint(1, 65535)
        ) / Raw(load=b"X" * random.randint(64, 1400))
        # 1200 packets trong 3 giây = 400 pkt/s
        pkt.time = base_time + 10.0 + i * 0.0025
        packets.append(pkt)

    # ── 4. ICMP Flood Attack ──
    print("[*] Tao ICMP Flood attack...")
    attacker_icmp = "172.16.0.200"
    for i in range(400):
        pkt = IP(src=attacker_icmp, dst=target_ip) / ICMP(
            type=8, code=0
        ) / Raw(load=b"P" * 56)
        # 400 packets trong 3 giây = ~133 pkt/s
        pkt.time = base_time + 15.0 + i * 0.0075
        packets.append(pkt)

    # ── 5. HTTP Flood Attack ──
    print("[*] Tao HTTP Flood attack...")
    attacker_http = "172.16.0.150"
    http_methods = [
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
        b"GET /search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
    ]
    for i in range(500):
        payload = random.choice(http_methods)
        pkt = IP(src=attacker_http, dst=target_ip) / TCP(
            sport=RandShort(), dport=80, flags="PA"
        ) / Raw(load=payload)
        # 500 packets trong 3 giây = ~167 pkt/s
        pkt.time = base_time + 20.0 + i * 0.006
        packets.append(pkt)

    # ── 6. Thêm traffic ICMP bình thường ──
    print("[*] Tao ICMP binh thuong...")
    for i in range(50):
        src = random.choice(normal_ips)
        pkt = IP(src=src, dst=target_ip) / ICMP(type=8) / Raw(load=b"ping")
        pkt.time = base_time + 25.0 + i * 0.5
        packets.append(pkt)

    # Sắp xếp packets theo thời gian
    packets.sort(key=lambda p: float(p.time))

    # Ghi file pcap
    print(f"\n[*] Dang ghi {len(packets)} packets vao {output_file}...")
    wrpcap(output_file, packets)
    
    file_size = os.path.getsize(output_file)
    print(f"[+] Hoan tat! File: {output_file} ({file_size / 1024:.1f} KB)")
    print(f"[+] Tong packets: {len(packets)}")
    print()
    print("Cac cuoc tan cong trong file:")
    print(f"  - SYN Flood:  {attacker_syn}, {attacker_syn2} -> {target_ip}:80,443")
    print(f"  - UDP Flood:  {attacker_udp} -> {target_ip}:random")
    print(f"  - ICMP Flood: {attacker_icmp} -> {target_ip}")
    print(f"  - HTTP Flood: {attacker_http} -> {target_ip}:80")


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "sample_ddos.pcap"
    generate_sample_pcap(output)
