#!/usr/bin/env python3
import argparse
import os
import sys
from colorama import init, Fore, Style

# Importamos el desmembrador que acabamos de crear
from core.dissector import dissect_pcap

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
        
    print(f"{Fore.BLUE}[+] Archivo cargado correctamente: {args.pcap}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Desmembrando canales de tráfico...{Style.RESET_ALL}")
    
    # Ejecutar el desmembrador
    channels, error = dissect_pcap(args.pcap)
    
    if error:
        print(f"{Fore.RED}[X] {error}{Style.RESET_ALL}")
        sys.exit(1)
        
    # Mostrar un resumen en consola de los canales encontrados
    print(f"\n{Fore.GREEN}[+] Análisis de canales completado con éxito:{Style.RESET_ALL}")
    for channel, pkts in channels.items():
        print(f"  {Fore.CYAN}• Canal [{channel}]:{Style.RESET_ALL} {len(pkts)} paquetes detectados.")
        
    print(f"\n{Fore.YELLOW}[!] Modo de IA: {'ACTIVADO' if args.ai else 'DESACTIVADO'}{Style.RESET_ALL}\n")

if __name__ == "__main__":
    main()
