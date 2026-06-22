#!/usr/bin/env python3
import re
from collections import defaultdict

def analyze_web_traffic(http_packets, max_requests_per_sec=20):
    """
    Motor avanzado de detección de amenazas web (OWASP Top 10, Herramientas de Hacking,
    Exposición de Archivos, Deserialización, Web Shells y Anomalías de Comportamiento).
    """
    alerts = []
    ip_timeline = defaultdict(list)
    
    # --- MATRIZ DE FIRMAS AVANZADAS (EXPRESIONES REGULARES) ---
    signatures = {
        "SQL Injection (SQLi)": [
            r"union\s+select",              # Inyección clásica UNION
            r"'\s*or\s+1\s*=\s*1",          # Bypass de autenticación clásico
            r"select\s+.*\s+from",          # Consultas arbitrarias a tablas
            r"'\s*--",                      # Comentarios SQL para truncar queries
            r"/\*.*\*/",                    # Comentarios multilínea (evasión WAF)
            r"exec\(\s*char\("              # Ejecución de comandos ofuscados (MSSQL)
        ],
        "Cross-Site Scripting (XSS)": [
            r"<script>",                    # Inyección de scripts directos
            r"javascript:",                 # Pseudo-protocolo malicioso
            r"onerror\s*=",                 # Manipulación de eventos DOM
            r"onload\s*=",
            r"alert\s*\(.*\)",              # PoC clásica de alerta
            r"document\.cookie"             # Intento de robo de sesiones/cookies
        ],
        "Path Traversal / LFI / RFI": [
            r"\.\./",                       # Salto de directorio clásico
            r"\.\.%2f",                     # Codificación URL simple para evadir
            r"\.\.%5c",                     # Salto de directorios en entornos Windows
            r"/etc/passwd",                 # Target crítico de lectura en Linux
            r"boot\.ini",                   # Target crítico de lectura en Windows antiguo
            r"win\.ini",
            r"=http[s]?://"                # Remote File Inclusion (RFI) - inclusión de scripts remotos
        ],
        "Server-Side Request Forgery (SSRF)": [
            r"url=http://169\.254\.169\.254", # Target de Metadatos Cloud (AWS, Azure, GCP)
            r"url=http://localhost",         # Forzar escaneo o peticiones internas
            r"url=http://127\.0\.0\.1",
            r"url=http://10\.",              # Intento de pivoteo a rangos privados clase A
            r"url=http://192\.168\."         # Intento de pivoteo a rangos privados clase C
        ],
        "Command Injection / RCE": [
            r";\s*whoami",                  # Inyección de comandos encadenados por punto y coma
            r"\|\s*id",                     # Inyección encadenada por tubería (Linux ID)
            r"&&\s*cat\s+",                 # Intento de lectura concatenada
            r"cmd\.exe",                    # Invocación de consola Windows
            r"/bin/(sh|bash|zsh)",          # Invocación de shells en Linux
            r"powershell\s+"                # Ejecución de PowerShell
        ],
        "XML External Entity (XXE)": [
            r"<!entity",                    # Declaración de entidades XML maliciosas
            r"<!doctype",                   # Definición de tipos de documento para manipulación
            r"system\s+[\"']http"           # Forzar resolución externa vía XML
        ],
        "Web Shell / Backdoor Activity": [
            r"c99sh",                       # Firmas de web shells históricas famosas
            r"r57sh",
            r"wso\.php",
            r"\?(cmd|shell|exec|passthru)="  # Parámetros típicos de ejecución en backdoors PHP
        ],
        "Insecure Deserialization / JWT Anomalies": [
            r"\xac\xed\x00\x05",            # Magic bytes de Java Serialized Objects
            r"o:[0-9]+:\"[a-z_]",           # Estructura de objetos serializados en PHP
            r"\"alg\"\s*:\s*\"none\""        # Vulnerabilidad crítica en firmas JWT (Algoritmo none)
        ],
        "Sensitive File Exposure (Information Leakage)": [
            r"\.env",                       # Intento de descarga de credenciales de entorno
            r"\.git/",                      # Exposición del repositorio de desarrollo
            r"config\.php",                 # Archivos de configuración locales comunes
            r"wp-config\.php",              # Configuración base de WordPress (base de datos)
            r"backup[s]?\.(zip|tar|gz|bak)",# Descarga de respaldos de servidores
            r"\.(sql|dump)"                 # Descarga directa de bases de datos expuestas
        ]
    }

    # --- LISTA NEGRA DE ESCANERES AUTOMÁTICOS (USER-AGENTS) ---
    malicious_user_agents = [
        "sqlmap", "nikto", "dirbuster", "gobuster", "nmap", 
        "w3af", "hydra", "acunetix", "nessus", "netsparker"
    ]

    # 1. ANÁLISIS FORENSE CAPA POR CAPA
    for pkt in http_packets:
        src_ip = pkt.get("src", "Desconocida")
        timestamp = pkt.get("time", 0)
        
        # Almacenamos marcas de tiempo para el análisis de comportamiento (fuzzing)
        ip_timeline[src_ip].append(timestamp)
        
        # Extracción y normalización de campos clave (pasados a minúsculas)
        uri = str(pkt.get("uri", "")).lower()
        payload = str(pkt.get("payload", "")).lower()
        user_agent = str(pkt.get("user_agent", "")).lower()
        method = str(pkt.get("method", "")).upper()
        
        # --- DETECCIÓN A: Firmas Temáticas (OWASP / RCE / SSRF) ---
        for attack_type, patterns in signatures.items():
            for pattern in patterns:
                if re.search(pattern, uri) or re.search(pattern, payload):
                    severity = "CRÍTICA" if attack_type in ["SQL Injection (SQLi)", "Command Injection / RCE", "Path Traversal / LFI / RFI", "Web Shell / Backdoor Activity"] else "ALTA"
                    alerts.append({
                        "attacker": src_ip,
                        "type": f"Firma Web: {attack_type}",
                        "details": f"Match con patrón '{pattern}' usando método {method} hacia la URI: {pkt.get('uri')}",
                        "severity": severity
                    })
                    break

        # --- DETECCIÓN B: Escáneres Automatizados (User-Agent Sniffing) ---
        for scanner in malicious_user_agents:
            if scanner in user_agent:
                alerts.append({
                    "attacker": src_ip,
                    "type": "Herramienta de Hacking Automatizada",
                    "details": f"Se detectó tráfico firmado por el escáner/herramienta: '{scanner}' (User-Agent: {pkt.get('user_agent')})",
                    "severity": "ALTA"
                })
                break

        # --- DETECCIÓN C: Intento de Arbitrary File Upload (Subida de Web Shells) ---
        if method == "POST" and "multipart/form-data" in payload:
            # Buscamos si dentro del multipart intentan subir extensiones ejecutables peligrosas
            if re.search(r"filename=.*\.(php|phtml|php5|asp|aspx|jsp|jspx|exe|sh|pl|py)", payload):
                alerts.append({
                    "attacker": src_ip,
                    "type": "Intento de File Upload Malicioso",
                    "details": f"Subida de archivo sospechosa detectada en un cuerpo multipart/form-data hacia {pkt.get('uri')}",
                    "severity": "CRÍTICA"
                })

    # 2. ANÁLISIS DE COMPORTAMIENTO (Algoritmo de Ventana Deslizante)
    for src_ip, timestamps in ip_timeline.items():
        timestamps.sort()
        for i in range(len(timestamps)):
            start_time = timestamps[i]
            count = 0
            
            for t in timestamps[i:]:
                if t - start_time <= 1.0:
                    count += 1
                else:
                    break
            
            if count >= max_requests_per_sec:
                # Si una IP tira demasiadas peticiones, determinamos si es DoS o Fuzzing intensivo
                severity = "CRÍTICA" if count >= 50 else "ALTA"
                alerts.append({
                    "attacker": src_ip,
                    "type": "Anomalía de Comportamiento: HTTP Flood / Fuzzing",
                    "details": f"Se registraron {count} solicitudes HTTP en un único segundo (Umbral: {max_requests_per_sec}/s).",
                    "severity": severity
                })
                break # Evita duplicar alertas idénticas para la misma IP
                
    return alerts
