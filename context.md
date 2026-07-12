# Project Context

This document provides a map and core guidelines for the `vaa_api_scanner` project.

## Tech Stack
- **Language**: Python 3.11+
- **Framework**: FastAPI (endpoints), Uvicorn (server)
- **Data & ML**: scikit-learn, pandas, joblib
- **Testing**: pytest 8, pytest-asyncio (strict mode)
- **HTTP Clients**: httpx, curl_cffi (TLS/JA3 fingerprinting), requests
- **Database**: asyncpg (PostgreSQL async pool via CognitiveMemory)
- **CLI**: typer (`vaa_cli.py`), standalone fuzzer (`vaa_fuzzer.py`)
- **Security analysis**: bandit >= 1.7.8, safety
- **Environment**: python-dotenv (reads .env for VAA_DATABASE_URL)

## Architecture

```
app/
├── config/settings.py          # Centraliza toda la configuración (env vars, timeouts, etc.)
├── core/
│   ├── cognitive_memory.py     # Persistencia PostgreSQL via asyncpg (singleton)
│   ├── engine/
│   │   ├── orchestrator.py     # Orquestador principal del scan
│   │   ├── phases/             # Fases: fuzzer, validation
│   │   ├── specialized/        # Motores: auth_audit, bola_harvest, mass_assignment
│   │   ├── algorithms/         # Jaccard, SimHash, Shannon entropy
│   │   └── models.py           # Pydantic models (EndpointTarget, etc.)
│   ├── m1_grammar.py           # Inferencia gramatical de endpoints
│   ├── m2_generation.py        # Generación de payloads
│   ├── m3_classification.py    # Clasificación ML de respuestas
│   ├── m5_ghost_v2.py          # Ghost Protocol: evasión de WAF / fingerprint
│   ├── m6_doppelganger.py      # Motor IDOR/BOLA quirúrgico (modo actor)
│   ├── m74p1_navigator.py      # Navegador y auto-discovery de specs
│   ├── m8_chronos.py           # Análisis temporal / stress testing
│   ├── m9_params.py            # Descubrimiento de parámetros ocultos
│   ├── m_jwt_audit.py          # Auditoría de JWT (alg:none, weak secrets)
│   ├── m_passive_recon.py      # Reconocimiento pasivo (headers, CORS, docs)
│   ├── m_uuid_oracle.py        # Análisis y predicción de UUIDs
│   ├── network_manager.py      # Sesiones HTTP, circuit breaker, TLS evasion
│   └── modules/
│       ├── openapi_parser.py
│       └── postman_parser.py
├── utils/
│   ├── waf_evasion.py          # Técnicas de ofuscación de payloads
│   ├── similarity.py           # SimHash (usa MD5 con usedforsecurity=False)
│   ├── ingestor.py, reporter.py, logger.py, helpers.py
models/                         # JSONs de conocimiento: payloads, firmas, agentes
tests/
├── unit/                       # 168 tests unitarios (todos en verde en CI)
├── lab_benchmark/              # Benchmarks contra lab_app
└── target_app/                 # App vulnerable local para pruebas E2E
ubuntu_database_setup/          # docker-compose.yml + init.sql para PostgreSQL
tools/                          # MCP server, parser, classifier
.github/workflows/ci.yml        # GitHub Actions: bandit + pytest + safety
```

## Configuration (Environment Variables)
Crea un archivo `.env` en la raíz con:
```
VAA_DATABASE_URL=postgresql://vaa:vaa_secret_change_me@<UBUNTU_IP>:5432/lokitrace_memory
VAA_VERIFY_SSL=true
H1_EMAIL=tu@email.com
```

## Rules
1. **Strict Typing**: Siempre usar type hints completos (incluye `Optional`, `Dict`, `List` desde `typing`).
2. **Security First**: Inputs validados con Pydantic. Queries SQL solo con parámetros (`asyncpg`). Sin `shell=True`.
3. **Async First**: Preferir `async/await` para I/O. Usar `httpx` y `asyncpg`.
4. **Testing**: Features nuevas acompañadas de tests en `tests/unit/`. No modificar tests existentes sin revisar impacto.
5. **Versioning**: Todos los módulos en `v4.0.0`. Tag en los docstrings.
6. **CI Pipeline**: El pipeline en GitHub Actions (`.github/workflows/ci.yml`) debe pasar siempre en verde.
