# VAA: Vulnerability Assessment Agent

[![Python Version](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Operator: N-1000](https://img.shields.io/badge/Operator-N--1000-red.svg)](https://github.com/N-1000)

> Agente de evaluacion de vulnerabilidades en APIs modernas, especializado en fallas de logica de negocio (OWASP API Security Top 10). Disenado para auditorias quirurgicas sobre endpoints especificos, no para fuzzing masivo a ciegas.

---

## Filosofia

La mayoria de los escaneadores de APIs atacan a ciegas: generan miles de payloads y los lanzan contra todos los endpoints esperando que algo suene. VAA parte de una premisa distinta.

Un auditor real selecciona un endpoint que considera sospechoso, lo estudia y lo prueba con precision. VAA automatiza exactamente eso: dado un endpoint concreto, dos sesiones de usuario (atacante y victima), y el contexto de la API, determina si existe una falla de control de acceso explotable.

El enfoque esta en **BOLA/IDOR** (Broken Object Level Authorization), **Mass Assignment**, y **JWT forgery**, que son las vulnerabilidades de mayor impacto real en APIs REST modernas y las que requieren razonamiento logico, no fuerza bruta.

---

## Arquitectura

El motor central (`orchestrator.py`) es un secuenciador de fases. Cada fase es un modulo independiente con responsabilidad unica.

### Modulos activos (core)

| Modulo | Responsabilidad |
| :--- | :--- |
| **M3** `m3_classification` | Clasificador inteligente de respuestas. Jaccard genuino O(N) sobre tokens. Detecta SQLi, SSRF, RCE, fugas de datos, Mass Assignment por diferencia semantica entre respuestas. |
| **M6** `m6_doppelganger` | Motor de analisis IDOR/BOLA. Compara el comportamiento del mismo endpoint bajo dos sesiones distintas (atacante vs victima). Ejecuta el plan de ataque cruzado y valida si hubo acceso no autorizado. |
| **M74P1** `m74p1_navigator` | Ingesta de superficie de ataque. Parsea OpenAPI, Postman Collections y archivos HAR para construir el mapa de endpoints. |
| **M9** `m9_params` | Descubrimiento semantico de parametros ocultos. Prueba 47 nombres comunes con 4 valores heuristicos en paralelo. |
| **M_JWT** `m_jwt_audit` | Auditoria activa de tokens JWT. Prueba alg:none, firma vacia, y escalada de claims (role, isAdmin). |
| **Passive Recon** `m_passive_recon` | Deteccion de documentacion expuesta (Swagger, OpenAPI) y cabeceras de seguridad ausentes o mal configuradas. |
| **Auth Audit** `auth_audit` | Deteccion de BFLA (Broken Function Level Authorization) probando funciones administrativas con tokens de usuario regular. |
| **BOLA Harvest** `bola_harvest` | Variacion automatica de IDs (numericos, UUID, slugs) recolectados durante el recon para probar acceso cruzado a objetos. |
| **Mass Assignment** `mass_assignment` | Inyeccion de campos privilegiados (`isAdmin`, `role`, `verified`) en POST/PUT para detectar asignacion masiva no controlada. |

### Modulos standalone (fuzzing independiente)

Los siguientes modulos fueron separados del core y viven en `standalone_tools/`. No se ejecutan como parte del scan principal pero pueden usarse de forma independiente:

| Modulo | Descripcion |
| :--- | :--- |
| `m1_grammar` | Modelo de gramatica Markov para prediccion de rutas y generacion de Shadow API probes. |
| `m2_generation` | Generador adaptativo de payloads (SQLi, XSS, SSRF, CMDi) con evasion de WAF. |
| `m5_ghost_v2` | Protocolo Ghost: rotacion de User-Agent, spoofing de IP, jitter de timing. |
| `m8_chronos` | Stress testing y deteccion de DoS logico. |
| `m11_graph` | Auditoria de GraphQL: introspection, enumeracion a ciegas, batch attacks. |
| `m12_vesta` | Deduplicacion de superficie de ataque y escalado adaptativo de payloads. |

---

## Instalacion

Requisitos: **Python 3.12+**

```bash
git clone https://github.com/N-1000/vaa_api_scanner.git
cd vaa_api_scanner
pip install -r requirements.txt
```

---

## Uso

### Modo quirurgico (recomendado)

El actor ya identifico el endpoint que quiere auditar. VAA lo evalua directamente sin fase de descubrimiento.

```bash
python vaa_cli.py \
  --target-endpoint "https://api.ejemplo.com/v1/users/1842" \
  --method GET \
  --logic \
  --auth "Bearer TOKEN_ATACANTE" \
  --auth-b "Bearer TOKEN_VICTIMA"
```

### Modo por coleccion (desde OpenAPI / Postman)

VAA descubre los endpoints desde el archivo de especificacion y ejecuta el analisis logico sobre todos.

```bash
python vaa_cli.py coleccion.postman_collection.json \
  --target "https://api.ejemplo.com" \
  --logic \
  --auth "Bearer TOKEN_A" \
  --auth-b "Bearer TOKEN_B"
```

### Modo por HAR (desde trafico capturado)

```bash
python vaa_cli.py \
  --target "https://api.ejemplo.com" \
  --har-a sesion_atacante.har \
  --har-b sesion_victima.har \
  --logic
```

---

## Referencia CLI

### Flags de fase

| Flag | Accion |
| :--- | :--- |
| `--recon` | Fase 1: descubrimiento de endpoints via M74P1. |
| `--logic` | Fase 2: analisis logico IDOR/BOLA via M6 Doppelganger. |
| `--fuzz` | Fase 3: inyecciones (SQLi/XSS/SSRF/RCE) via M3. Requiere `--recon` o coleccion. |

Sin flags de fase, VAA activa todo en modo Auto Pilot.

### Modo quirurgico

| Flag | Accion |
| :--- | :--- |
| `--target-endpoint <url>` | Endpoint especifico a auditar. Omite la fase de descubrimiento. |
| `--method <METHOD>` | Metodo HTTP del endpoint (default: GET). |

### Autenticacion

| Flag | Accion |
| :--- | :--- |
| `--auth <token>` | Token Bearer del atacante. |
| `--auth-b <token>` | Token Bearer de la victima (para M6 IDOR cross-session). |
| `--auth-refresh-cmd <cmd>` | Comando shell para renovar el token cuando expira. VAA lee el stdout. |
| `--har-a <path>` | Trazas HAR del atacante. |
| `--har-b <path>` | Trazas HAR de la victima. |
| `--env <path>` | Archivo de environment de Postman (variables `{{baseUrl}}`, `{{token}}`). |

### Control y evasion

| Flag | Accion |
| :--- | :--- |
| `--safe` | Modo seguro: bloquea metodos destructivos (DELETE, DROP). |
| `--force-destructive` | Permite payloads destructivos. Peligroso en produccion. |
| `--mass-assign` | Activa Mass Assignment activo en POST/PUT. |
| `--no-jwt-audit` | Desactiva la auditoria JWT. |
| `--no-rce` | Desactiva los modulos de command injection y RCE. |
| `--tor` | Rutea todo el trafico via SOCKS5 (TOR). Requiere daemon activo. |
| `--ghost` | Stealth mode: User-Agent aleatorio y delays variables. |
| `--proxy <url>` | Proxy HTTP/HTTPS para el trafico de la sesion. |
| `--delay <segundos>` | Delay base entre peticiones (float). |
| `--report-threshold <0.0-1.0>` | Umbral minimo de confianza para incluir un hallazgo en el reporte (default: 0.6). |
| `--debug-pipeline` | Emite `reports/pipeline_trace_<ts>.jsonl` con el journey de cada hallazgo por capa. |

---

## Controles autonomos

- **Shannon Entropy Oracle:** Si un endpoint responde identico de forma sistematica (mismo status + mismo size), lo descarta silenciosamente para evitar falsos positivos por agotamiento.
- **Circuit Breaker:** Backoff exponencial automatico ante rachas de respuestas 429 o 403 de WAF.
- **Report Degradation:** Los hallazgos con confianza baja (< umbral configurado) se marcan como "Por Revisar" en lugar de descartarse, permitiendo revision manual.

---

### Disclaimer

*VAA es una herramienta ofensiva de uso interno para equipos de seguridad autorizados. Los autores no son responsables por el uso no autorizado contra sistemas de terceros.*
