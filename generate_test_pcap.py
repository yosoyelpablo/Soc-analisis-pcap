#!/usr/bin/env python3
import time
from scapy.all import IP, TCP, wrpcap
from scapy.layers.http import HTTP, HTTPRequest

def create_malicious_pcap(output_filename="test_web_attacks.pcap"):
    print("[*] Fabricando paquetes maliciosos artificiales...")
    packets = []

    # 1. Petición Normal (Línea base)
    pkt_normal = (
        IP(src="192.168.1.50", dst="10.0.0.5") /
        TCP(sport=49152, dport=80) /
        HTTPRequest(Method=b"GET", Path=b"/index.html", Http_User_Agent=b"Mozilla/5.0")
    )
    packets.append(pkt_normal)

    # 2. Inyección SQL (SQLi)
    pkt_sqli = (
        IP(src="192.168.1.100", dst="10.0.0.5") /
        TCP(sport=49153, dport=80) /
        HTTPRequest(Method=b"GET", Path=b"/products.php?id=1%20union%20select%20null,username,password%20from%20users", Http_User_Agent=b"Mozilla/5.0")
    )
    packets.append(pkt_sqli)

    # 3. Ataque XSS + User-Agent Malicioso (sqlmap)
    pkt_xss = (
        IP(src="192.168.1.120", dst="10.0.0.5") /
        TCP(sport=49154, dport=80) /
        HTTPRequest(Method=b"GET", Path=b"/search?q=<script>alert(document.cookie)</script>", Http_User_Agent=b"sqlmap/1.8.4#stable")
    )
    packets.append(pkt_xss)

    # 4. Anomalía de Comportamiento: HTTP Flood (25 peticiones en el mismo segundo)
    print("[*] Generando ráfaga para simular HTTP Flood/Fuzzing...")
    base_time = time.time()
    for i in range(25):
        pkt_flood = (
            IP(src="10.200.10.5", dst="10.0.0.5") /
            TCP(sport=50000 + i, dport=80) /
            HTTPRequest(Method=b"GET", Path=f"/page_{i}.html".encode(), Http_User_Agent=b"Go-http-client/1.1")
        )
        # Asignamos el timestamp de forma manual para asegurar que caigan en la ventana de 1 segundo
        pkt_flood.time = base_time
        packets.append(pkt_flood)

    # Guardamos todos los paquetes en el archivo de salida
    wrpcap(output_filename, packets)
    print(f"[+] Archivo de prueba generado con éxito: {output_filename}\n")

if __name__ == "__main__":
    create_malicious_pcap()
