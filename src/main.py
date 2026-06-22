#!/usr/bin/env python3
import argparse
import os
import sys
from colorama import init, Fore, Style
from dotenv import load_dotenv  # <-- Importamos dotenv

# --- PARCHE DE RUTAS AUTOMÁTICO ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# Cargamos el archivo .env automáticamente desde la raíz del proyecto
# Busca el archivo .env un nivel arriba de la carpeta 'src'
load_dotenv(os.path.join(BASE_DIR, '..', '.env'))

from core.dissector import dissect_pcap
from modules.web_rules import analyze_http_rate
from core.ai_engine import generate_threat_hypothesis

init(autoreset=True)

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}DarkBear-Dissector: Framework modular de análisis de tráfico de red y triaje con IA.{Style.RESET_ALL}"
    )
    parser.add_argument("-p", "--pcap", required=True, help="Ruta del archivo .pcap")
    parser.add_argument("--ai", action="store_true", help="Activa el motor de IA")
    return parser.parse_args()

def main():
    args = parse_arguments()
    print(f"\n{Fore.GREEN}[*] Iniciando DarkBear-Dissector...{Style.RESET_ALL}")
    
    if not os.path.exists(args.pcap):
        print(f"{Fore.RED}[X] Error: El archivo '{args.pcap}' no existe.{Style.RESET_ALL}")
        sys.exit(1)
        
    # 1. Desmembramiento de canales
    channels, error = dissect_pcap(args.pcap)
    if error:
        print(f"{Fore.RED}[X] {error}{Style.RESET_ALL}")
        sys.exit(1)
        
    print(f"{Fore.GREEN}[+] Canales desmembrados con éxito.{Style.RESET_ALL}")
    
    # 2. Análisis de Heurística en Python
    all_alerts = []
    if "HTTP" in channels:
        print(f"{Fore.YELLOW}[*] Analizando firmas y anomalías en Canal HTTP...{Style.RESET_ALL}")
        web_alerts = analyze_http_rate(channels["HTTP"], max_requests_per_sec=20)
        all_alerts.extend(web_alerts)
        
    # 3. Reporte Local de Python
    print(f"\n{Fore.WHITE}=== REPORTE DE ANOMALÍAS DE PYTHON ==={Style.RESET_ALL}")
    if not all_alerts:
        print(f"{Fore.GREEN}[+] No se detectaron anomalías estructurales en los canales.{Style.RESET_ALL}")
    else:
        for alert in all_alerts:
            color = Fore.RED if alert["severity"] == "ALTA" else Fore.YELLOW
            print(f"{color}[!] ALERT [{alert['type']}]{Style.RESET_ALL}")
            print(f"    Origen Sospechoso: {alert['attacker']}")
            print(f"    Detalle: {alert['details']}\n")

    # 4. Motor de Inteligencia Artificial
    if args.ai:
        print(f"{Fore.CYAN}=== INICIANDO TRIAJE CON INTELIGENCIA ARTIFICIAL ==={Style.RESET_ALL}")
        hypothesis = generate_threat_hypothesis(channels, all_alerts)
        print(f"\n{Fore.MAGENTA}🤖 HIPÓTESIS DEL ANALISTA DE IA:{Style.RESET_ALL}")
        print(hypothesis)
    else:
        print(f"{Fore.YELLOW}[!] Modo de IA desactivado. Usá '--ai' para generar una hipótesis con Gemini.{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
