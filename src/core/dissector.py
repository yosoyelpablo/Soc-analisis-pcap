#!/usr/bin/env python3
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
# Importamos las capas necesarias para el parseo automático
try:
    from scapy.layers.http import HTTPRequest
except ImportError:
    pass

try:
    from scapy.layers.dns import DNS, DNSQR
except ImportError:
    pass

from collections import defaultdict

def dissect_pcap(pcap_path):
    """
    Lee un archivo PCAP/PCAPNG y clasifica los paquetes de forma 100% dinámica
    en diferentes canales basados en protocolos de red y puertos de aplicación.
    """
    traffic_channels = defaultdict(list)
    
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        return None, f"Error crítico al leer el archivo de red: {str(e)}"

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
            
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        channel_name = "UNKNOWN"
        payload_len = 0
        
        # --- CAMPOS POR DEFECTO ---
        method = "UNKNOWN"
        uri = "/"
        user_agent = "No Presente"
        payload = ""
        dns_qname = "N/A"
        dns_qtype = 0
        icmp_type = -1     # 🆕 Campo ICMP
        icmp_code = -1     # 🆕 Campo ICMP
        
        # 1. Identificación Dinámica del Canal
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            port = min(tcp_layer.sport, tcp_layer.dport)
            well_known_ports = {
                21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 
                80: "HTTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 
                3306: "MYSQL", 3389: "RDP", 5432: "POSTGRES"
            }
            channel_name = well_known_ports.get(port, f"TCP/Port-{port}")
            payload_len = len(tcp_layer.payload)
            
            if channel_name == "HTTP" or pkt.haslayer('HTTPRequest'):
                channel_name = "HTTP"
                if pkt.haslayer('HTTPRequest'):
                    http_layer = pkt['HTTPRequest']
                    method = http_layer.Method.decode(errors='ignore') if http_layer.Method else "GET"
                    uri = http_layer.Path.decode(errors='ignore') if http_layer.Path else "/"
                    user_agent = http_layer.User_Agent.decode(errors='ignore') if http_layer.User_Agent else "No Presente"
                if pkt.haslayer('Raw'):
                    payload = pkt['Raw'].load.decode(errors='ignore')
            
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            port = min(udp_layer.sport, udp_layer.dport)
            well_known_ports = {53: "DNS", 67: "DHCP", 68: "DHCP", 161: "SNMP"}
            channel_name = well_known_ports.get(port, f"UDP/Port-{port}")
            payload_len = len(udp_layer.payload)
            
            if channel_name == "DNS" or pkt.haslayer('DNS'):
                channel_name = "DNS"
                if pkt.haslayer('DNSQR'):
                    dns_layer = pkt['DNSQR']
                    dns_qname = dns_layer.qname.decode(errors='ignore') if dns_layer.qname else "N/A"
                    dns_qtype = dns_layer.qtype
            
        elif pkt.haslayer(ICMP):
            channel_name = "ICMP"
            icmp_layer = pkt[ICMP]
            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code
            payload_len = len(icmp_layer.payload)
            if pkt.haslayer('Raw'):
                payload = pkt['Raw'].load.decode(errors='ignore')
        
        # 2. Extracción de Metadatos
        packet_meta = {
            "src": src_ip,
            "dst": dst_ip,
            "length": len(pkt),
            "payload_len": payload_len,
            "time": float(pkt.time),
            "method": method,
            "uri": uri,
            "user_agent": user_agent,
            "payload": payload,
            "dns_qname": dns_qname,
            "dns_qtype": dns_qtype,
            "icmp_type": icmp_type,  # 🆕
            "icmp_code": icmp_code   # 🆕
        }
        
        traffic_channels[channel_name].append(packet_meta)
        
    return dict(traffic_channels), None
