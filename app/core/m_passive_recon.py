"""
Modulo de Reconocimiento Pasivo (OWASP API Security Top 10 2023)
================================================================
API9 — Improper Inventory Management:
    Detecta documentacion de API y endpoints de debug accesibles sin autenticacion.

API8 — Security Misconfiguration:
    Detecta CORS mal configurado y ausencia de headers de seguridad criticos.

Sin payloads maliciosos. Solo peticiones GET/HEAD. FP minimizados por verificacion de contenido.
"""

from typing import List, Dict, Any
from app.utils.logger import logger  # pyre-ignore[21]


DOC_PATHS = [

    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/swagger-ui.html", "/swagger-ui/", "/swagger/",
    "/docs", "/redoc", "/api/docs", "/api/swagger",

    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/actuator/mappings", "/_profiler", "/telescope/requests",
    "/metrics", "/env", "/debug", "/__debug__",

    "/.env", "/config.json", "/app/config",

    "/graphql/schema.json",

    "/healthcheck", "/health", "/status",
]


DOC_SIGNATURES = [
    "swagger", "openapi", '"paths"', '"endpoints"', '"info"',
    "actuator", "spring", "DATABASE_URL", "SECRET_KEY", "api_key",
    "password", "private", "internal", '"version"', "schema",
    "x-forwarded", "debug", "environment", "env(",
]


REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
]


CORS_TEST_ORIGIN = "https://evil.lokitrace.com"


async def check_exposed_docs(target: str, network_manager: Any) -> List[Dict]:
    """
    API9 \u2014 Improper Inventory Management.
    """
    findings = []
    base = target.rstrip("/")

    for path in DOC_PATHS:
        url = f"{base}{path}"
        try:

            resp = await network_manager.send_request(
                url, method="GET", use_pool=False, stealth=False
            )

            if not resp or resp.status_code != 200 or len(resp.content) < 50:
                continue

            content_lower = resp.text[:600].lower()
            is_real_doc = any(sig.lower() in content_lower for sig in DOC_SIGNATURES)

            if is_real_doc:
                logger.warning(f"[API9] Documentacion/debug expuesta sin auth: {url}")
                findings.append({
                    "url":               url,
                    "norm_url":          url,
                    "type":              "Exposed_Documentation",
                    "method":            "GET",
                    "payload":           "",
                    "risk":              "Medium",
                    "confidence":        0.95,
                    "verified":          True,
                    "validation_method": "passive_recon_content_match",
                    "report_policy":     "local",
                    "params":            {},
                    "is_json":           False,
                    "response_text":     resp.text[:300],
                    "ai_razonamiento": (
                        f"El path `{path}` devuelve documentacion de API accesible "
                        "sin autenticacion. Expone la superficie de ataque completa "
                        "incluyendo todos los endpoints, parametros y schemas."
                    ),
                    "ai_remediacion": (
                        "Proteger con autenticacion o eliminar de produccion. "
                        "La documentacion solo debe ser accesible en entornos de desarrollo. "
                        "Si es necesaria publicamente, asegurar que no exponga schemas internos."
                    ),
                })

        except Exception as e:
            logger.debug(f"[API9] Error probando {url}: {e}")

    logger.info(f"[API9] Docs expuestas scan: {len(findings)} hallazgo(s).")
    return findings


async def check_security_headers(target: str, network_manager: Any) -> List[Dict]:
    """
    API8 \u2014 Security Misconfiguration.

    Hace una sola peticion al target con un Origin adversario y analiza:
    1. Si la respuesta refleja el Origin adversario en Access-Control-Allow-Origin \u2192 CORS vuln
    2. Que headers de seguridad criticos estan ausentes en la respuesta

    Args:
        target: URL base del target
        network_manager: Instancia de NetworkManager de VAA

    Returns:
        Lista de hallazgos (puede ser 0, 1 o 2 items).
    """
    findings = []
    base = target.rstrip("/")

    try:
        resp = await network_manager.send_request(
            base,
            method="GET",
            custom_headers={"Origin": CORS_TEST_ORIGIN},
            use_pool=False,
            stealth=False
        )
        if not resp:
            return []
            
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}


        acao = resp_headers.get("access-control-allow-origin", "")
        acac = resp_headers.get("access-control-allow-credentials", "")

        cors_reflected = (CORS_TEST_ORIGIN in acao) or (acao == "*")
        if cors_reflected:
            credentials_allowed = "true" in acac.lower()
            risk   = "High" if (credentials_allowed and acao != "*") else "Medium"
            razon  = (
                f"CORS refleja el Origin adversario ({acao}) y permite Credentials. "
                "Un atacante puede hacer que la victima ejecute requests autenticados desde "
                "un sitio malicioso y leer la respuesta completa (Account Takeover)."
                if risk == "High" else
                f"CORS permite cualquier Origin ({acao}). "
                "Un atacante puede leer respuestas de endpoints publicos desde cualquier sitio."
            )
            logger.warning(f"[API8] CORS mal configurado: ACAO={acao}, ACAC={acac}")
            findings.append({
                "url":               base,
                "norm_url":          base,
                "type":              "CORS_Misconfiguration",
                "method":            "GET",
                "payload":           f"Origin: {CORS_TEST_ORIGIN}",
                "risk":              risk,
                "confidence":        1.0,
                "verified":          True,
                "validation_method": "cors_origin_reflection",
                "report_policy":     "local",
                "params":            {},
                "is_json":           False,
                "response_text":     f"ACAO: {acao} | ACAC: {acac}",
                "ai_razonamiento":   razon,
                "ai_remediacion": (
                    "Definir una whitelist explicita de Origins permitidos. "
                    "Nunca combinar 'Access-Control-Allow-Origin: *' con "
                    "'Access-Control-Allow-Credentials: true'. "
                    "Revisar la configuracion del servidor web y el framework."
                ),
            })


        missing = [
            h for h in REQUIRED_SECURITY_HEADERS
            if h.lower() not in resp_headers
        ]
        if missing:
            logger.info(f"[API8] Headers de seguridad ausentes en {base}: {missing}")
            findings.append({
                "url":               base,
                "norm_url":          base,
                "type":              "Missing_Security_Headers",
                "method":            "GET",
                "payload":           "",
                "risk":              "Low",
                "confidence":        0.92,
                "verified":          True,
                "validation_method": "passive_header_audit",
                "report_policy":     "local",
                "params":            {},
                "is_json":           False,
                "response_text":     f"Ausentes: {', '.join(missing)}",
                "ai_razonamiento": (
                    f"La API no incluye los headers de seguridad: {', '.join(missing)}. "
                    "Esto permite ataques de MIME sniffing, clickjacking y downgrade."
                ),
                "ai_remediacion": (
                    "Agregar en la configuracion del servidor: "
                    "Strict-Transport-Security: max-age=31536000; includeSubDomains | "
                    "X-Content-Type-Options: nosniff | X-Frame-Options: DENY. "
                    "En nginx: add_header. En Apache: Header always set."
                ),
            })

    except Exception as e:
        logger.debug(f"[API8] Error en verificacion de headers: {e}")

    logger.info(f"[API8] Security headers scan: {len(findings)} hallazgo(s).")
    return findings
