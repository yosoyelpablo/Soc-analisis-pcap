#!/usr/bin/env python3
import argparse
import os
import sys
from colorama import init, Fore, Style

# Inicializar colores en la terminal
init(autoreset=True)

def parse_arguments():
    """Maneja los argumentos de la línea de comandos."""
    parser = argparse.ArgumentParser(
        description=f"{Fore.CYAN}DarkBear-Dissector: Framework modular de análisis de tráfico de red y triaje con IA.{Style.RESET_ALL}"
    )
    parser.add_argument(
        "-p", "--pcap", 
        required=True, 
        help="Ruta absoluta o relativa del archivo .pcap / .pcapng a analizar."
    )
    parser.add_argument(
        "--ai", 
        action="store_true", 
        help="Activa el motor de Inteligencia Artificial para la formulación de hipótesis de ataque."
    )
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    print(f"\n{Fore.GREEN}[*] Iniciando DarkBear-Dissector...{Style.RESET_ALL}")
    
    # Validar que el archivo exista
    if not os.path.exists(args.pcap):
        print(f"{Fore.RED}[X] Error: El archivo '{args.pcap}' no existe.{Style.RESET_ALL}")
        sys.exit(1)
        
    print(f"{Fore.BLUE}[+] Archivo cargado correctamente: {args.pcap}{Style.RESET_ALL}")
    
    # ---------------------------------------------------------------------------
    # PASO SIGUIENTE: Acá vamos a orquestar el flujo llamando a los módulos
    # 1. dissector.py (Desmembramiento de canales)
    # 2. modules/ (Reglas heurísticas de Python)
    # 3. ai_engine.py (Si args.ai está activo, llama a Gemini)
    # ---------------------------------------------------------------------------
    
    print(f"{Fore.YELLOW}[!] Modo de IA: {'ACTIVADO' if args.ai else 'DESACTIVADO'}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
