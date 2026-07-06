
"""
VAA Classifier — Herramienta individual de clasificacion semantica de endpoints.
Extraida de app/core/m1_grammar.py (M1GrammarModel.classify_endpoint_type).

Uso:
  # Clasificar un endpoint manualmente
  python tools/vaa_classifier.py --url "https://api.ejemplo.com/v1/user/login" --method POST

  # Clasificar una lista de endpoints desde vaa_parser (JSON)
  python tools/vaa_parser.py --source https://api.ejemplo.com/openapi.json --json | python tools/vaa_classifier.py --stdin

  # Salida en JSON (para encadenar con otros scripts o con el MCP)
  python tools/vaa_classifier.py --stdin --json < endpoints.json
"""

import re
import json
import sys
import argparse
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse


_AUTH_KEYWORDS    = frozenset({"login", "logout", "signin", "signup", "register",
                                "token", "oauth", "authorize", "auth", "refresh",
                                "password", "forgot"})
_ADMIN_KEYWORDS   = frozenset({"admin", "dashboard", "manage", "manager",
                                "management", "backoffice", "settings", "config", "panel"})
_SEARCH_KEYWORDS  = frozenset({"search", "query", "find", "filter", "lookup", "suggest"})
_WEBHOOK_KEYWORDS = frozenset({"webhook", "callback", "notify", "hook", "event", "events"})
_FILE_KEYWORDS    = frozenset({"upload", "download", "export", "import", "attachment",
                                "file", "media", "asset", "image", "report"})
_HEALTH_KEYWORDS  = frozenset({"health", "ping", "status", "metrics", "diagnostic",
                                "info", "version", "readiness", "liveness", "debug"})
_GRAPHQL_KEYWORDS = frozenset({"graphql", "graph", "gql"})
_SEARCH_PARAMS    = frozenset({"q", "search", "query", "keyword", "filter", "find"})


_ENDPOINT_TYPE_MAP = [
    ("auth",    _AUTH_KEYWORDS),
    ("admin",   _ADMIN_KEYWORDS),
    ("graphql", _GRAPHQL_KEYWORDS),
    ("health",  _HEALTH_KEYWORDS),
    ("webhook", _WEBHOOK_KEYWORDS),
    ("file",    _FILE_KEYWORDS),
    ("search",  _SEARCH_KEYWORDS),
]


_TYPE_RISK = {
    "auth":      {"risk": "High",   "owasp": "API2 - Broken Authentication",
                  "hint": "Probar fuerza bruta, fijacion de sesion, JWT debil."},
    "admin":     {"risk": "Critical","owasp": "API5 - Broken Function Level Auth",
                  "hint": "Verificar si el endpoint es accesible sin privilegios de admin."},
    "graphql":   {"risk": "High",   "owasp": "API4 - Unrestricted Resource Consumption",
                  "hint": "Probar introspection, queries recursivos (DoS), batching."},
    "file":      {"risk": "High",   "owasp": "API8 - Security Misconfiguration",
                  "hint": "Probar path traversal, subida de archivos maliciosos."},
    "webhook":   {"risk": "Medium", "owasp": "API7 - SSRF",
                  "hint": "Probar SSRF apuntando a servicios internos (169.254.169.254)."},
    "search":    {"risk": "Medium", "owasp": "API1 - BOLA / SQLi",
                  "hint": "Probar SQLi ciego, BOLA via manipulacion de filtros."},
    "data-read": {"risk": "Medium", "owasp": "API1 - BOLA/IDOR",
                  "hint": "Iterar IDs. Verificar acceso entre usuarios (cross-user)."},
    "data-write":{"risk": "Medium", "owasp": "API3 - Mass Assignment",
                  "hint": "Enviar campos extra (role, isAdmin). Verificar persistencia."},
    "health":    {"risk": "Low",    "owasp": "API9 - Improper Inventory Management",
                  "hint": "Verificar si expone informacion de infraestructura sin auth."},
    "generic":   {"risk": "Low",    "owasp": "N/A",
                  "hint": "Realizar reconocimiento manual."},
}


def classify_endpoint(url: str, method: str = "GET", params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Clasifica el tipo semantico de un endpoint.
    Logica extraida directamente de M1GrammarModel.classify_endpoint_type().
    """
    parsed = urlparse(url)
    path = parsed.path.lower() if parsed.path else ""
    params = params or {}

    parts = set(p for p in path.strip("/").split("/") if p)


    for label, keywords in _ENDPOINT_TYPE_MAP:
        if parts & keywords:
            risk_info = _TYPE_RISK.get(label, {})
            return {"type": label, **risk_info}


    if any(p.lower() in _SEARCH_PARAMS for p in params):
        return {"type": "search", **_TYPE_RISK["search"]}


    segments = [p for p in path.strip("/").split("/") if p]
    for seg in segments:
        if seg.isdigit():
            return {"type": "data-read", **_TYPE_RISK["data-read"]}
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}', seg, re.IGNORECASE):
            return {"type": "data-read", **_TYPE_RISK["data-read"]}


    id_params = {"id", "user_id", "userId", "account_id", "accountId", "uuid", "guid"}
    if any(k in id_params for k in params):
        return {"type": "data-read", **_TYPE_RISK["data-read"]}


    if params and method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        return {"type": "data-write", **_TYPE_RISK["data-write"]}

    return {"type": "generic", **_TYPE_RISK["generic"]}


def classify_list(endpoints: List[Dict]) -> List[Dict]:
    """Clasifica una lista de endpoints (output de vaa_parser --json)."""
    results = []
    for ep in endpoints:
        url    = ep.get("url", "")
        method = ep.get("method", "GET")
        params = ep.get("params", {})

        flat_params = {}
        if isinstance(params, dict):
            for group in params.values():
                if isinstance(group, list):
                    for p in group:
                        flat_params[str(p)] = None

        classification = classify_endpoint(url, method, flat_params)
        results.append({
            "method": method,
            "url": url,
            **classification
        })
    return results


def main():
    parser = argparse.ArgumentParser(
        description="VAA Classifier: Clasificador semantico de endpoints de API"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--url", help="URL del endpoint a clasificar")
    group.add_argument("--stdin", action="store_true",
                       help="Leer lista JSON de endpoints desde stdin (salida de vaa_parser --json)")
    parser.add_argument("--method", default="GET", help="Metodo HTTP (solo con --url)")
    parser.add_argument("--json", action="store_true", dest="json_out",
                        help="Devolver resultado en formato JSON")
    args = parser.parse_args()

    if args.stdin:
        try:
            data = json.load(sys.stdin)
            results = classify_list(data)
        except (json.JSONDecodeError, Exception) as e:
            print(f"[ERROR] No se pudo leer JSON desde stdin: {e}")
            sys.exit(1)

        if args.json_out:
            print(json.dumps(results, indent=2))
        else:

            by_type: Dict[str, List] = {}
            for r in results:
                t = r["type"]
                by_type.setdefault(t, []).append(r)

            print(f"\n[*] Clasificacion de {len(results)} endpoints:\n")
            for ep_type, eps in sorted(by_type.items(), key=lambda x: x[1][0].get("risk","Low")):
                risk = eps[0].get("risk", "?")
                owasp = eps[0].get("owasp", "")
                hint  = eps[0].get("hint", "")
                print(f"  [{risk}] {ep_type.upper()} ({owasp})")
                print(f"   -> {hint}")
                for ep in eps:
                    print(f"      {ep['method']:<7} {ep['url']}")
                print()
    else:
        result = classify_endpoint(args.url, args.method)
        if args.json_out:
            print(json.dumps({"url": args.url, "method": args.method, **result}, indent=2))
        else:
            print(f"\n[*] Clasificacion de: {args.method} {args.url}")
            print(f"    Tipo    : {result['type'].upper()}")
            print(f"    Riesgo  : {result.get('risk', 'N/A')}")
            print(f"    OWASP   : {result.get('owasp', 'N/A')}")
            print(f"    Consejo : {result.get('hint', '')}\n")


if __name__ == "__main__":
    main()
