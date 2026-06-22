#!/usr/bin/env python3
from collections import defaultdict

def analyze_http_rate(http_packets, max_requests_per_sec=15):
    """
    Analiza el canal HTTP buscando ráfagas sospechosas de peticiones
    desde una misma IP de origen en lapsos de tiempo ultra cortos.
    """
    alerts = []
    # Agrupamos los timestamps de los paquetes por IP de origen
    ip_timeline = defaultdict(list)
    
    for pkt in http_packets:
        ip_timeline[pkt["src"]].append(pkt["time"])
    
    # Analizamos la frecuencia para cada IP
    for src_ip, timestamps in ip_timeline.items():
        # Ordenamos los tiempos por las dudas
        timestamps.sort()
        
        # Algoritmo de ventana deslizante de 1 segundo
        for i in range(len(timestamps)):
            start_time = timestamps[i]
            count = 0
            
            # Contamos cuántos paquetes entran en la ventana de 1 segundo desde 'start_time'
            for t in timestamps[i:]:
                if t - start_time <= 1.0:
                    count += 1
                else:
                    break
            
            # Si supera el umbral, disparamos la alerta de Python
            if count >= max_requests_per_sec:
                alerts.append({
                    "attacker": src_ip,
                    "type": "HTTP Flood / Web Fuzzing Detectado",
                    "details": f"Se detectaron {count} peticiones en un lapso de 1 segundo.",
                    "severity": "ALTA" if count > 30 else "MEDIA"
                })
                # Rompemos el bucle interno para esta IP para no duplicar alertas del mismo ataque
                break
                
    return alerts
