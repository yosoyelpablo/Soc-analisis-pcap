#!/usr/bin/env python3
from collections import defaultdict

def analyze_access_traffic(tcp_packets, max_attempts_per_window=10, window_size=3.0):
    """
    Detecta ataques de Fuerza Bruta, Password Guessing y Credential Stuffing
    en canales de autenticación críticos como SSH (Puerto 22) y FTP (Puerto 21).
    """
    alerts = []
    
    # Timelines para análisis volumétrico
    ssh_timeline = defaultdict(list)
    ftp_timeline = defaultdict(list)
    
    # Diccionarios para rastrear comandos específicos de FTP (Texto plano)
    ftp_user_tracking = defaultdict(set)
    ftp_pass_tracking = defaultdict(set)
    
    alerted_hosts = set()

    for pkt in tcp_packets:
        src_ip = pkt.get("src", "Desconocida")
        dst_ip = pkt.get("dst", "Desconocida")
        timestamp = pkt.get("time", 0)
        payload = pkt.get("payload", "")
        
        # Reconstruimos los puertos desde el nombre del canal si es un puerto dinámico
        # O evaluamos si el payload/canal están asociados a SSH/FTP
        method = pkt.get("method", "UNKNOWN")
        uri = pkt.get("uri", "/")
        
        # Nota: En dissector.py, los paquetes TCP se etiquetan por su puerto menor.
        # Buscaremos si el paquete pertenece al flujo de SSH o FTP.
        
        # --- ANALISIS CANAL FTP (Puerto 21) ---
        if "FTP" in pkt.get("_channel", "") or "Port-21" in pkt.get("_channel", ""):
            ftp_timeline[src_ip].append(timestamp)
            
            # Inspección forense de comandos FTP en texto plano
            if payload:
                # El atacante envía el usuario
                if "USER" in payload.upper():
                    user_line = payload.replace("\r\n", "").strip()
                    ftp_user_tracking[src_ip].add(user_line)
                # El atacante envía la contraseña
                elif "PASS" in payload.upper():
                    pass_line = payload.replace("\r\n", "").strip()
                    ftp_pass_tracking[src_ip].add(pass_line)

        # --- ANÁLISIS CANAL SSH (Puerto 22) ---
        elif "SSH" in pkt.get("_channel", "") or "Port-22" in pkt.get("_channel", ""):
            # Como SSH viaja cifrado, dependemos 100% de la volumetría de establecimiento de conexión
            # Cada paquete SYN o ráfaga de paquetes de intercambio inicial suma al timeline
            ssh_timeline[src_ip].append(timestamp)

    # 1. Evaluación de alertas FTP (Inspección de Comportamiento + Volumetría)
    for src_ip, user_set in ftp_user_tracking.items():
        # Si una IP intenta loguearse con más de 4 usuarios distintos, es Credential Stuffing
        if len(user_set) >= 4:
            alerts.append({
                "attacker": src_ip,
                "type": "Identificación de Ataque: Credential Stuffing (FTP)",
                "details": f"El host intentó autenticarse alternando múltiples usuarios ({len(user_set)} usuarios distintos detectados en texto plano).",
                "severity": "CRÍTICA"
            })
            alerted_hosts.add(src_ip)

    for src_ip, timestamps in ftp_timeline.items():
        if src_ip in alerted_hosts:
            continue
        timestamps.sort()
        for i in range(len(timestamps)):
            start_time = timestamps[i]
            count = sum(1 for t in timestamps[i:] if t - start_time <= window_size)
            
            if count >= max_attempts_per_window:
                alerts.append({
                    "attacker": src_ip,
                    "type": "Anomalía de Acceso: Fuerza Bruta FTP",
                    "details": f"Ráfaga de {count} solicitudes de conexión FTP en una ventana de {window_size}s (Umbral: {max_attempts_per_window}).",
                    "severity": "ALTA"
                })
                break

    # 2. Evaluación de alertas SSH (Volumetría pura por cifrado)
    for src_ip, timestamps in ssh_timeline.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            start_time = timestamps[i]
            count = sum(1 for t in timestamps[i:] if t - start_time <= window_size)
            
            if count >= max_attempts_per_window:
                alerts.append({
                    "attacker": src_ip,
                    "type": "Anomalía de Acceso: Sospecha de Fuerza Bruta SSH",
                    "details": f"Se detectaron {count} paquetes de negociación SSH en una ventana de {window_size}s. Patrón típico de password guessing.",
                    "severity": "ALTA"
                })
                break

    return alerts
