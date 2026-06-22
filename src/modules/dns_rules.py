#!/usr/bin/env python3
from collections import defaultdict

def analyze_dns_traffic(dns_packets, max_queries_per_sec=15):
    """
    Analiza el canal DNS buscando anomalías volumétricas y sospechas de DNS Tunneling / DGA.
    """
    alerts = []
    time_windows = defaultdict(int)
    
    for pkt in dns_packets:
        attacker = pkt["src"]
        qname = pkt["dns_qname"]
        timestamp = int(pkt["time"])
        
        # 1. Detección de DNS Tunneling / DGA (Heurística por longitud de dominio)
        # Dominios legítimos raramente tienen subdominios limpios de más de 45 caracteres enfocados en queries estructuradas
        if qname != "N/A" and len(qname) > 50:
            alerts.append({
                "type": "Sospecha de DNS Tunneling / DGA",
                "severity": "ALTA",
                "attacker": attacker,
                "details": f"Consulta sospechosamente larga ({len(qname)} caracteres): '{qname}'"
            })
            
        # 2. Anomalía de Comportamiento: DNS Flood
        if qname != "N/A":
            window_key = f"{attacker}_{timestamp}"
            time_windows[window_key] += 1

    # Validar umbrales volumétricos
    detected_floods = set()
    for key, count in time_windows.items():
        if count > max_queries_per_sec:
            attacker_ip = key.split("_")[0]
            if attacker_ip not in detected_floods:
                alerts.append({
                    "type": "Anomalía de Comportamiento: DNS Flood",
                    "severity": "ALTA",
                    "attacker": attacker_ip,
                    "details": f"Se registraron {count} consultas DNS en un único segundo (Umbral: {max_queries_per_sec}/s)."
                })
                detected_floods.add(attacker_ip)

    return alerts
