#!/usr/bin/env python3
import os
from google import genai
from google.genai import errors
from colorama import Fore, Style

def generate_threat_hypothesis(channels_summary, python_alerts):
    """
    Se conecta con la API de Gemini para generar una hipótesis de amenaza
    basada en el desmembramiento de canales y alertas previas de Python.
    """
    # El SDK busca automáticamente la variable de entorno GEMINI_API_KEY
    if not os.environ.get("GEMINI_API_KEY"):
        return f"{Fore.RED}[X] Error: La variable de entorno GEMINI_API_KEY no está configurada.{Style.RESET_ALL}"

    try:
        # Inicializamos el cliente oficial de google-genai
        client = genai.Client()
        
        # Formateamos la data para el modelo
        channels_text = "\n".join([f"- Canal [{k}]: {len(v)} paquetes" for k, v in channels_summary.items()])
        alerts_text = "\n".join([f"- {a['type']} de la IP {a['attacker']} ({a['details']})" for a in python_alerts]) if python_alerts else "Ninguna alerta estructural gatillada por Python."

        # Construimos un prompt de rol estricto para perfil SOC/Blue Team
        prompt = f"""
        Actúa como un Ingeniero Principal de un SOC (Security Operations Center) y experto en Análisis de Tráfico de Red.
        Se ha procesado una captura de tráfico (.pcap) y el script heurístico ha extraído los siguientes datos:

        DISTRIBUCIÓN DE CANALES DETECTADOS:
        {channels_text}

        ALERTAS PREVIAS DETECTADAS POR PYTHON:
        {alerts_text}

        TAREA:
        Por favor, analiza la relación entre el volumen de los canales y las alertas. Formula una hipótesis técnica, concisa y profesional sobre lo que podría estar ocurriendo en la red (ej. Exfiltración de datos, navegación normal, escaneo sigiloso, actividad C2, uso de protocolos modernos como QUIC, etc.). Incluye:
        1. Resumen del Análisis de Tráfico.
        2. Hipótesis de Amenaza (¿Qué crees que pasa?).
        3. Próximos pasos recomendados para el analista.
        
        Devuelve tu respuesta formateada en Markdown limpio, directo al grano, sin introducciones corporativas ni saludos.
        """

        print(f"{Fore.BLUE}[*] Enviando telemetría a Gemini para triaje avanzado...{Style.RESET_ALL}")
        
        # Llamamos al modelo estable y rápido para análisis de texto
        response = client.models.generate_content(
            model='gemini-1.5-flash',
            contents=prompt,
        )
        
        return response.text

    except errors.APIError as e:
        return f"{Fore.RED}[X] Error de API de Gemini: {str(e)}{Style.RESET_ALL}"
    except Exception as e:
        return f"{Fore.RED}[X] Error inesperado en el motor de IA: {str(e)}{Style.RESET_ALL}"
