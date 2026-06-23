# DarkBear-Dissector 🐻‍💻📡

**DarkBear-Dissector** es un framework modular de análisis forense de red, clasificación y triaje automatizado de tráfico que combina la potencia del análisis heurístico basado en reglas con Inteligencia Artificial generativa (Google Gemini API). 

Diseñado bajo el enfoque de **Alertas de Alta Fidelidad (High-Fidelity)**, este framework mitiga activamente la *fatiga de alertas* en entornos de SOC (Security Operations Center), aislando ruidos comunes de red para priorizar e identificar señales críticas de compromiso, movimientos laterales, exfiltración de datos y ataques volumétricos.

---

## 🚀 Características Principales

- **Desmembramiento Dinámico de Canales:** Inspección profunda de paquetes (DPI) utilizando `Scapy` para separar dinámicamente el tráfico IP en flujos específicos según protocolos de aplicación y capas de transporte.
- **Motor Heurístico Modular (Python Puro):**
  - 🌐 **Módulo Web (`web_rules`):** Detección de ataques por inyección (SQLi), Cross-Site Scripting (XSS) mediante firmas de payloads, y anomalías de comportamiento como HTTP Flood o Fuzzer automatizados.
  - 🔍 **Módulo DNS (`dns_rules`):** Identificación de ataques volumétricos de inundación (DNS Flood) y firmas de algoritmos de generación de dominios sospechosos (DGA) orientados a evadir defensas y detectar DNS Tunneling.
  - 🛠️ **Módulo ICMP (`icmp_rules`):** Detección de tácticas de reconocimiento interno (Ping Sweeps) y payloads anómalos ocultos en peticiones Echo Request (ICMP Tunneling / C2).
  - 🔑 **Módulo de Acceso (`access_rules`):** Correlación cruzada de handshakes y comandos en texto plano para identificar ataques de fuerza bruta volumétrica en SSH y Credential Stuffing secuencial en FTP.
- **Triaje Cognitivo con IA:** Integración nativa con el motor `gemini-2.5-flash` para procesar el contexto de los paquetes desmembrados y las alertas generadas, construyendo una hipótesis formal del incidente correlacionando tácticas de MITRE ATT&CK.

---

## 📂 Arquitectura del Proyecto

El proyecto sigue una estructura limpia, desacoplada y orientada a módulos para facilitar la escalabilidad y el mantenimiento:

```text
darkbear-dissector/
│
├── src/                           # Código fuente principal del framework
│   ├── __init__.py
│   ├── main.py                    # Orquestador central del flujo del programa
│   │
│   ├── core/                      # Componentes nucleares de la herramienta
│   │   ├── __init__.py
│   │   ├── dissector.py           # Parsing forense con Scapy y división de canales
│   │   └── ai_engine.py           # Conector a la API de Gemini, prompts y control de cuotas
│   │
│   └── modules/                   # Módulos heurísticos analíticos en Python
│       ├── __init__.py
│       ├── web_rules.py           # Reglas de firmas y volumetría HTTP
│       ├── dns_rules.py           # Análisis de entropía y longitud de queries DNS
│       ├── icmp_rules.py          # Auditoría de payloads e ICMP Sweeps
│       └── access_rules.py        # Detección de Password Guessing en SSH/FTP
│
├── generate_test_pcap.py          # Script de simulación de ataques y ráfagas para QA
├── requirements.txt               # Librerías y dependencias necesarias
└── .env                           # Configuración de variables de entorno (API Key)
```

---

## 🛠️ Instalación y Configuración

### Prerrequisitos
- Python 3.9 o superior instalado.
- Una API Key válida de Google AI Studio (Gemini API).

### 1. Clonar el repositorio y crear entorno virtual
```bash
# Crear entorno virtual personalizado
python -m venv .venv

# Activar el entorno virtual
# En Linux/macOS:
source .venv/bin/activate
# En Windows:
.venv\Scripts\activate
```

### 2. Instalar dependencias
```bash
pip install -r requirements.txt
```

### 3. Configurar variables de entorno
Crea un archivo `.env` en la raíz del proyecto basándote en la plantilla `.env.example`:
```env
GEMINI_API_KEY=AIzaSyTuClaveRealAquiDeGoogleAIStudio
```

---

## 🕹️ Modo de Uso y Demostración

### Paso A: Generar Tráfico de Prueba (Simulador)
El repositorio cuenta con un script automatizado para fabricar un archivo `.pcap` sintético pero hiperrealista que contiene ataques de SQLi, XSS, HTTP Flood, DNS Tunneling, ICMP Backdoors, Ping Sweeps y Fuerza Bruta de SSH y FTP distribuida en el tiempo:
```bash
python generate_test_pcap.py
```

### Paso B: Ejecutar el Framework Analítico

**1. Análisis Heurístico Local (Sin consumo de API):**
Ideal para triajes veloces en la terminal sin requerir conexión a internet o tokens de la API.
```bash
python src/main.py -p test_web_attacks.pcap
```

**2. Análisis Completo + Triaje de IA con Gemini:**
Procesa las alertas locales y envía la telemetría al motor cognitivo para generar la hipótesis del incidente.
```bash
python src/main.py -p test_web_attacks.pcap --ai
```

---

## 📊 Ejemplo de Salida en Terminal

Al ejecutar el framework contra el archivo de pruebas maliciosas generadas, el motor heurístico local arroja detecciones en tiempo real categorizadas por severidad con códigos de color:

```text
[*] Iniciando DarkBear-Dissector...
[+] Canales desmembrados con éxito.
[*] Analizando firmas y anomalías en Canal HTTP...
[*] Analizando anomalías en Canal DNS...
[*] Analizando anomalías en Canal ICMP...
[*] Analizando intentos de Fuerza Bruta en Canales SSH/FTP...

=== REPORTE DE ANOMALÍAS DE PYTHON ===
[!] ALERT [Firma Web: Cross-Site Scripting (XSS)] (ALTA)
    Origen Sospechoso: 192.168.1.120
    Detalle: Match con patrón '<script>' usando método GET hacia la URI: /search?q=<script>alert(document.cookie)</script>

[!] ALERT [Herramienta de Hacking Automatizada] (ALTA)
    Origen Sospechoso: 192.168.1.120
    Detalle: Se detectó tráfico firmado por el escáner/herramienta: 'sqlmap' (User-Agent: sqlmap/1.8.4#stable)

[!] ALERT [Anomalía de Comportamiento: HTTP Flood / Fuzzing] (ALTA)
    Origen Sospechoso: 10.200.10.5
    Detalle: Se registraron 25 solicitudes HTTP en un único segundo (Umbral: 20/s).

[!] ALERT [Sospecha de DNS Tunneling / DGA] (ALTA)
    Origen Sospechoso: 192.168.1.150
    Detalle: Consulta sospechosamente larga (53 caracteres): 'a41f69b2c3d9e8f01a2b3c4d5e6f.malicious-c2-server.com.'

[!] ALERT [Sospecha de ICMP Tunneling / C2] (CRÍTICA)
    Origen Sospechoso: 192.168.1.150
    Detalle: Paquete ICMP con payload anómalo de 38 bytes detectado hacia 10.0.0.1. Datos: 'root:password123;exec(cmd_c2_backdoor)...'

[!] ALERT [Anomalía de Acceso: Fuerza Bruta FTP] (ALTA)
    Origen Sospechoso: 172.16.5.120
    Detalle: Ráfaga de 12 solicitudes de conexión FTP en una ventana de 3.0s (Umbral: 12).

=== INICIANDO TRIAJE CON INTELIGENCIA ARTIFICIAL ===

🤖 HIPÓTESIS DEL ANALISTA DE IA:
[Aquí se renderiza el reporte de triaje cognitivo estructurado por la API de Gemini]
```
