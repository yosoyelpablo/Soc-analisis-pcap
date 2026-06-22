#!/usr/bin/env python3
from collections import defaultdict

def analyze_icmp_traffic(icmp_packets):
    """
    Analiza el canal ICMP buscando barridos de red (Ping Sweeps) y payloads anómalos (Tunneling).
    """
    alerts = []
    
    # Estructuras para Ping Sweep
    ping_targets = defaultdict(set)
    
    for pkt in icmp_packets:
        attacker = pkt["src"]
        target = pkt["dst"]
        itype = pkt["icmp_type"]
        payload = pkt["payload"]
        
        # 1. Detección de Ping Sweep (Reconocimiento / Discovery)
        # type == 8 es un Echo Request (petición de ping)
        if itype == 8:
            ping_targets[attacker].add(target)
            
        # 2. Detección de ICMP Tunneling / Payload Anómalo
        # Un ping estándar (como el de Linux o Windows) lleva un patrón fijo de bytes.
        # Si vemos strings legibles sospechosas o texto plano de comandos, hay tongo.
        if pkt["payload_len"] > 20:
            keywords = ["root:", "admin", "c2", "exec", "shell", "shadow"]
            if any(kw in payload.lower() for kw in keywords):
                alerts.append({
                    "type": "Sospecha de ICMP Tunneling / C2",
                    "severity": "CRÍTICA",
                    "attacker": attacker,
                    "details": f"Paquete ICMP con payload anómalo de {pkt['payload_len']} bytes detectado hacia {target}. Datos: '{payload[:40]}...'"
                })

    # Validar si alguna IP escaneó demasiados objetivos diferentes
    for attacker, targets in ping_targets.items():
        if len(targets) >= 5:  # Si le pegó a 5 o más IPs distintas
            alerts.append({
                "type": "Reconocimiento: Barrido de Red (Ping Sweep)",
                "severity": "ALTA",
                "attacker": attacker,
                "details": f"El host realizó un barrido ICMP Echo Request contra {len(targets)} direcciones IP distintas."
            })

    return alerts
