#!/usr/bin/env python3
import argparse
import os
import sys
from colorama import init, Fore, Style

# --- PARCHE DE RUTAS AUTOMÁTICO ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from core.dissector import dissect_pcap
# Importamos el nuevo módulo heurístico web
from modules.web_rules.py_o_directo import analyze_http_rate 
# Nota: Como está en la misma carpeta sys.path, importamos directo:
from modules.web_rules import analyze_http_rate

init(autoreset=True)

def parse_arguments():
    parser = argparse.ArgumentParser(description="DarkBear-Dissector")
    parser.add_argument("-p", "--pcap", required=True, help="Ruta del archivo .pcap")
    parser.add_argument("--ai", action="store_true", help="Activa el motor de IA")
    return parser.parse_args()

def main():
    args = parse_arguments()
    print(f"\n{Fore.GREEN}[*] Iniciando DarkBear-Dissector...{Style.RESET_ALL}")
    
    if not os.path.exists(args.pcap):
        print(f"{Fore.RED}[X] Error: El archivo '{args.pcap}' no existe.{Style.RESET_ALL}")
        sys.exit(1)
        
    # 1. Desmembramiento
    channels, error = dissect_pcap(args.pcap)
    if error:
        print(f"{Fore.RED}[X] {error}{Style.RESET_ALL}")
        sys.exit(1)
        
    print(f"{Fore.GREEN}[+] Canales desmembrados con éxito.{Style.RESET_ALL}")
    
    # --- CORRECCIÓN/ANÁLISIS DE HEURÍSTICA EN PYTHON ---
    all_alerts = []
    
    # Si el desmembrador encontró tráfico HTTP, lo analizamos
    if "HTTP" in channels:
        print(f"{Fore.YELLOW}[*] Analizando firmas y anomalías en Canal HTTP...{Style.RESET_ALL}")
        web_alerts = analyze_http_rate(channels["HTTP"], max_requests_per_sec=20)
        all_alerts.extend(web_alerts)
        
    # 2. Mostrar Alertas de Python en Consola
    print(f"\n{Fore.WHITE}=== REPORTE DE ANOMALÍAS DE PYTHON ==={Style.RESET_ALL}")
    if not all_alerts:
        print(f"{Fore.GREEN}[+] No se detectaron anomalías estructurales en los canales.{Style.RESET_ALL}")
    else:
        for alert in all_alerts:
            color = Fore.RED if alert["severity"] == "ALTA" else Fore.YELLOW
            print(f"{color}[!] ALERT [{alert['type']}]{Style.RESET_ALL}")
            print(f"    Origen Sospechoso: {alert['attacker']}")
            print(f"    Detalle: {alert['details']}")
            print(f"    Severidad: {alert['severity']}\n")

    print(f"{Fore.YELLOW}[!] Modo de IA: {'ACTIVADO' if args.ai else 'DESACTIVADO'}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
