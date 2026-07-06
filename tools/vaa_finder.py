
import asyncio
import httpx
import argparse
import sys
from typing import List, Dict


DOC_PATHS = [

    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/swagger-ui.html", "/swagger-ui/", "/swagger/",
    "/docs", "/redoc",

    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
    "/v1/swagger.yaml", "/v2/swagger.yaml", "/v3/swagger.yaml",
    "/v1/api-docs",   "/v2/api-docs",   "/v3/api-docs",
    "/v1/docs",       "/v2/docs",       "/v3/docs",

    "/api/swagger.json", "/api/openapi.json",
    "/api/docs", "/api/swagger",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/api/v1/openapi.json", "/api/v2/openapi.json",

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

async def find_docs(target_url: str, timeout: float = 5.0):
    """Escanea una URL base en busca de documentacion expuesta."""
    base = target_url.rstrip("/")
    found = []

    print(f"[*] Escaneando {base} en busca de definiciones de API...")

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        tasks = []
        for path in DOC_PATHS:
            tasks.append(check_path(client, base, path))
        
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                found.append(r)
    
    return found

async def check_path(client, base, path):
    url = f"{base}{path}"
    try:
        resp = await client.get(url, follow_redirects=True)
        if resp.status_code == 200 and len(resp.text) > 50:
            content_lower = resp.text[:1000].lower()
            if any(sig.lower() in content_lower for sig in DOC_SIGNATURES):
                return url
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="VAA Finder: Herramienta de descubrimiento de APIs")
    parser.add_argument("--url", required=True, help="URL base del target (ej: https://api.ejemplo.com)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout por peticion")
    args = parser.parse_args()

    try:
        found_urls = asyncio.run(find_docs(args.url, args.timeout))
        
        if found_urls:
            print(f"\n[!] Se han encontrado {len(found_urls)} posibles definiciones/docs:")
            for url in found_urls:
                print(f" [+] {url}")
        else:
            print("\n[-] No se han encontrado definiciones publicas en los paths comunes.")
            
    except KeyboardInterrupt:
        print("\n[!] Escaneo cancelado por el usuario.")
    except Exception as e:
        print(f"\n[ERROR] {e}")

if __name__ == "__main__":
    main()
