#!/usr/bin/env python3
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
# Importamos la capa HTTP para que Scapy sepa parsear esos encabezados automáticamente
try:
    from scapy.layers.http import HTTPRequest
except ImportError:
    pass
from collections import defaultdict

def dissect_pcap(pcap_path):
    """
    Lee un archivo PCAP/PCAPNG y clasifica los paquetes de forma 100% dinámica
    en diferentes canales basados en protocolos de red y puertos de aplicación.
    """
    # Usamos defaultdict para que cree canales dinámicamente a medida que aparezcan
    traffic_channels = defaultdict(list)
    
    try:
        # rdpcap carga el pcap para poder iterarlo
        packets = rdpcap(pcap_path)
    except Exception as e:
        return None, f"Error crítico al leer el archivo de red: {str(e)}"

    for pkt in packets:
        # Filtrar solo tráfico IP por el momento (Capa 3)
        if not pkt.haslayer(IP):
            continue
            
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        channel_name = "UNKNOWN"
        payload_len = 0
        
        # --- NUEVOS CAMPOS PARA ANÁLISIS WEB PROFUNDO ---
        # Se inicializan por defecto para no romper los otros protocolos (DNS, ICMP, etc.)
        method = "UNKNOWN"
        uri = "/"
        user_agent = "No Presente"
        payload = ""
        
        # 1. Identificación Dinámica del Canal (Capa 4 + Aplicación)
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            # Tomamos el puerto menor asumiendo que es el puerto del servicio remoto
            port = min(tcp_layer.sport, tcp_layer.dport)
            
            # Mapeo de puertos comunes para etiquetar el canal con nombre
            well_known_ports = {
                21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 
                80: "HTTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 
                3306: "MYSQL", 3389: "RDP", 5432: "POSTGRES"
            }
            channel_name = well_known_ports.get(port, f"TCP/Port-{port}")
            payload_len = len(tcp_layer.payload)
            
            # 🚀 EXTRACCIÓN ESPECIAL SI ES TRÁFICO WEB (HTTP)
            if channel_name == "HTTP" or pkt.haslayer('HTTPRequest'):
                channel_name = "HTTP" # Forzamos el nombre por si entró por inspección de capa
                
                if pkt.haslayer('HTTPRequest'):
                    http_layer = pkt['HTTPRequest']
                    # Traducimos de bytes a string ignorando caracteres extraños de payloads maliciosos
                    method = http_layer.Method.decode(errors='ignore') if http_layer.Method else "GET"
                    uri = http_layer.Path.decode(errors='ignore') if http_layer.Path else "/"
                    user_agent = http_layer.Http_User_Agent.decode(errors='ignore') if http_layer.Http_User_Agent else "No Presente"
                
                # Extraemos el cuerpo de la petición (POST data, inyecciones, forms)
                if pkt.haslayer('Raw'):
                    payload = pkt['Raw'].load.decode(errors='ignore')
            
        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            port = min(udp_layer.sport, udp_layer.dport)
            
            well_known_ports = {53: "DNS", 67: "DHCP", 68: "DHCP", 161: "SNMP"}
            channel_name = well_known_ports.get(port, f"UDP/Port-{port}")
            payload_len = len(udp_layer.payload)
            
        elif pkt.haslayer(ICMP):
            channel_name = "ICMP"
            payload_len = len(pkt[ICMP].payload)
        
        # 2. Extracción de Metadatos (Estructura expandida compatible con la IA y reglas)
        packet_meta = {
            "src": src_ip,
            "dst": dst_ip,
            "length": len(pkt),
            "payload_len": payload_len,
            "time": float(pkt.time),
            # Enviamos estas llaves siempre. Si no es HTTP, irán con sus valores por defecto.
            "method": method,
            "uri": uri,
            "user_agent": user_agent,
            "payload": payload
        }
        
        # Guardar el paquete procesado en su respectivo canal
        traffic_channels[channel_name].append(packet_meta)
        
    return dict(traffic_channels), None
