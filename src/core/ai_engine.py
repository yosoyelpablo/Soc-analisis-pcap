#!/usr/bin/env python3
import os
import google.generativeai as genai

def generate_threat_hypothesis(channels, alerts):
    # Configurar API Key desde entorno
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        return "[!] Error: GEMINI_API_KEY no configurada en .env"
    
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-2.5-flash')

    # Preparar el contexto para la IA
    alert_summary = "\n".join([f"- {a['type']} (Severidad: {a['severity']}): {a['details']}" for a in alerts])
    
    prompt = f"""
    Actúa como un Analista de Ciberseguridad Senior de un SOC. Analiza las siguientes alertas detectadas en tráfico de red:
    
    {alert_summary}
    
    Tu salida debe seguir estrictamente este formato:
    
    1. **MATRIZ MITRE ATT&CK**: Mapea las alertas a tácticas conocidas (ej: Reconnaissance, Command and Control, Exfiltration).
    2. **CALIFICACIÓN DE RIESGO**: Asigna un score de 0 a 10 y justifica brevemente.
    3. **ANÁLISIS DE HIPÓTESIS**: Explica la correlación de eventos (¿Es un ataque coordinado? ¿Hay cortinas de humo?).
    4. **PLAN DE ACCIÓN**: Enumera 3 medidas de contención prioritarias (Prioridad Alta, Media, Baja).
    
    Sé conciso, técnico y directo.
    """

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error al consultar con Gemini: {str(e)}"
