#!/usr/bin/env python3
import time
from scapy.all import IP, TCP, UDP, ICMP, wrpcap
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.dns import DNS, DNSQR

def create_malicious_pcap(output_filename="test_web_attacks.pcap"):
    print("[*] Fabricando paquetes maliciosos artificiales (Web + DNS + ICMP)...")
    packets = []

    # ==========================================
    # 🔥 SECCIÓN 1: TRÁFICO WEB (HTTP)
    # ==========================================
    pkt_normal = (
        IP(src="192.168.1.50", dst="10.0.0.5") /
        TCP(sport=49152, dport=80) /
        HTTP() /
        HTTPRequest(Method=b"GET", Path=b"/index.html", User_Agent=b"Mozilla/5.0")
    )
    packets.append(pkt_normal)

    pkt_sqli = (
        IP(src="192.168.1.100", dst="10.0.0.5") /
        TCP(sport=49153, dport=80) /
        HTTP() /
        HTTPRequest(Method=b"GET", Path=b"/products.php?id=1%20union%20select%20null,username,password%20from%20users", User_Agent=b"Mozilla/5.0")
    )
    packets.append(pkt_sqli)

    pkt_xss = (
        IP(src="192.168.1.120", dst="10.0.0.5") /
        TCP(sport=49154, dport=80) /
        HTTP() /
        HTTPRequest(Method=b"GET", Path=b"/search?q=<script>alert(document.cookie)</script>", User_Agent=b"sqlmap/1.8.4#stable")
    )
    packets.append(pkt_xss)

    print("[*] Generando ráfaga para simular HTTP Flood/Fuzzing...")
    base_time = time.time()
    for i in range(25):
        pkt_flood = (
            IP(src="10.200.10.5", dst="10.0.0.5") /
            TCP(sport=50000 + i, dport=80) /
            HTTP() /
            HTTPRequest(Method=b"GET", Path=f"/page_{i}.html".encode(), User_Agent=b"Go-http-client/1.1")
        )
        pkt_flood.time = base_time
        packets.append(pkt_flood)

    # ==========================================
    # 🆕 SECCIÓN 2: TRÁFICO DNS
    # ==========================================
    print("[*] Generando tráfico DNS malicioso...")
    pkt_dns_tunnel = (
        IP(src="192.168.1.150", dst="8.8.8.8") /
        UDP(sport=5353, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=b"a41f69b2c3d9e8f01a2b3c4d5e6f.malicious-c2-server.com"))
    )
    packets.append(pkt_dns_tunnel)

    for i in range(20):
        pkt_dns_flood = (
            IP(src="10.100.50.4", dst="8.8.8.8") /
            UDP(sport=6000 + i, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=f"target-domain-{i}.com".encode()))
        )
        pkt_dns_flood.time = base_time
        packets.append(pkt_dns_flood)

    # ==========================================
    # 🆕 SECCIÓN 3: TRÁFICO ICMP
    # ==========================================
    print("[*] Generando tráfico ICMP (Reconocimiento y Tunneling)...")
    
    # Barrido de red (Ping Sweep)
    for i in range(1, 6):
        pkt_ping = IP(src="192.168.1.50", dst=f"10.0.0.{i}") / ICMP(type=8)
        packets.append(pkt_ping)

    # Tunneling ICMP con payload malicioso
    pkt_tunnel = (
        IP(src="192.168.1.150", dst="10.0.0.1") / 
        ICMP(type=8) / b"root:password123;exec(cmd_c2_backdoor)"
    )
    packets.append(pkt_tunnel)

    wrpcap(output_filename, packets)
    print(f"[+] Archivo de prueba generado con éxito: {output_filename}\n")

if __name__ == "__main__":
    create_malicious_pcap()
