# Progress

## Completed Tasks (v4.0.0)

### Arquitectura
- [x] Migración de módulos a `app/core/` (eliminación de `standalone_tools/`)
- [x] Estandarización de versiones a `v4.0.0` en todos los módulos
- [x] Limpieza de comentarios y logs innecesarios
- [x] Eliminación de `legacy_vulns/` y payloads duplicados

### Base de Datos
- [x] Creación de `ubuntu_database_setup/docker-compose.yml`
- [x] Creación de `ubuntu_database_setup/init.sql` (esquema validado contra CognitiveMemory)
- [x] Integración de `python-dotenv` en `settings.py` para leer `.env`

### Testing (168 tests en verde)
- [x] `tests/unit/test_cognitive_memory.py` — 10 tests (CRUD, singleton, pool lifecycle)
- [x] `tests/unit/test_algorithms.py` — Jaccard, Shannon, SimHash
- [x] `tests/unit/test_adaptive_backoff.py` — Circuit breaker
- [x] `tests/unit/test_auth_audit.py` — Auditoría de autenticación
- [x] `tests/unit/test_bola_harvest.py` — Detección BOLA/IDOR
- [x] `tests/unit/test_mass_assignment.py` — Mass Assignment
- [x] `tests/unit/test_m3_predict_risk.py` — Clasificación ML
- [x] `tests/unit/test_m6_doppelganger.py` — Motor quirúrgico actor
- [x] `tests/unit/test_m74p1_navigator.py` — Auto-discovery
- [x] `tests/unit/test_m9_params.py` — Descubrimiento de parámetros
- [x] `tests/unit/test_m_jwt_audit.py` — JWT
- [x] `tests/unit/test_m_passive_recon.py` — Reconocimiento pasivo
- [x] `tests/unit/test_network_manager.py` — Sesiones y proxy
- [x] `tests/unit/test_openapi_parser.py` — Parser OpenAPI
- [x] `tests/unit/test_uuid_oracle.py` — UUID Oracle
- [x] `tests/unit/test_vuln_types.py` — Tipos de vulnerabilidades

### CI/CD
- [x] `.github/workflows/ci.yml` — Pipeline en GitHub Actions
- [x] `conftest.py` raíz — Resolución de imports cross-platform
- [x] `pytest.ini` — Configuración de asyncio strict mode
- [x] Fix: `bandit>=1.7.8` para AST de Python 3.11
- [x] Fix: `hashlib.md5(usedforsecurity=False)` en `similarity.py`

### Repositorio
- [x] `.gitignore` actualizado (pycache, coverage, .env)
- [x] Limpieza de `legacy_vulns/`, `standalone_tools/`, `tests/standalone_tools/`
- [x] Eliminación de `.pyre_configuration`

## In Progress
- [ ] Ninguna tarea activa en este momento.

## Pending
- [ ] Auditoría E2E completa contra `lab_app` (modo quirúrgico)
- [ ] Cobertura de `m11_graph.py` y `m12_vesta.py` en `app/core/` (si se migran)

## Known Issues
- Ninguno. Todos los tests en verde en CI.
