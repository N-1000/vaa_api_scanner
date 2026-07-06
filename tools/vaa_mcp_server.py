
"""
VAA Discovery MCP Server
========================
Servidor MCP que expone las 3 herramientas de reconocimiento de VAA como tools
invocables por Claude Desktop u otro cliente MCP compatible.

Herramientas expuestas:
  - discover_api_docs    : Encuentra archivos OpenAPI/Swagger expuestos en una URL.
  - parse_api_spec       : Extrae la lista de endpoints de una especificacion.
  - classify_endpoints   : Clasifica endpoints por tipo semantico y riesgo OWASP.

Configurar en Claude Desktop (claude_desktop_config.json):
  {
    "mcpServers": {
      "vaa-discovery": {
        "command": "python",
        "args": ["C:/ruta/al/proyecto/tools/vaa_mcp_server.py"]
      }
    }
  }
"""

import asyncio
import json
import re
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

import httpx
import yaml
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent


sys.path.insert(0, ".")
from tools.vaa_finder import DOC_PATHS, DOC_SIGNATURES, check_path
from tools.vaa_classifier import classify_endpoint, classify_list, _TYPE_RISK


app = Server("vaa-discovery")


@app.list_tools()
async def list_tools() -> List[Tool]:
    return [
        Tool(
            name="discover_api_docs",
            description=(
                "Escanea una URL base en busca de definiciones de API publicamente "
                "accesibles: OpenAPI (swagger.json, openapi.yaml), endpoints de debug "
                "(actuator, metrics, .env), y documentacion de GraphQL. "
                "Retorna una lista de URLs donde se encontro contenido relevante."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "URL base del objetivo (ej: https://api.ejemplo.com)"
                    },
                    "timeout": {
                        "type": "number",
                        "description": "Timeout en segundos por peticion (default: 5)",
                        "default": 5.0
                    }
                },
                "required": ["target_url"]
            }
        ),
        Tool(
            name="parse_api_spec",
            description=(
                "Descarga y parsea una especificacion OpenAPI/Swagger (JSON o YAML) "
                "desde una URL o archivo local. Extrae todos los endpoints con su metodo "
                "HTTP, URL completa, y parametros conocidos (query, path, body). "
                "Util para entender la superficie de ataque de una API antes de auditarla."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "description": "URL o ruta local de la especificacion OpenAPI/Swagger"
                    }
                },
                "required": ["source"]
            }
        ),
        Tool(
            name="classify_endpoints",
            description=(
                "Clasifica una lista de endpoints de API por su tipo semantico y riesgo OWASP. "
                "Categorias: auth (API2), admin (API5), data-read/IDOR (API1), "
                "data-write/Mass Assignment (API3), file (API8), webhook/SSRF (API7), "
                "search (SQLi), graphql, health. "
                "Acepta la salida directa de parse_api_spec o un endpoint individual."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "endpoints": {
                        "type": "array",
                        "description": "Lista de endpoints (salida de parse_api_spec)",
                        "items": {
                            "type": "object",
                            "properties": {
                                "url":    {"type": "string"},
                                "method": {"type": "string"},
                                "params": {"type": "object"}
                            }
                        }
                    },
                    "single_url": {
                        "type": "string",
                        "description": "URL individual a clasificar (alternativa a 'endpoints')"
                    },
                    "single_method": {
                        "type": "string",
                        "description": "Metodo HTTP para single_url (default: GET)",
                        "default": "GET"
                    }
                }
            }
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]):
    

    if name == "discover_api_docs":
        target_url = arguments["target_url"].rstrip("/")
        timeout    = float(arguments.get("timeout", 5.0))
        found      = []

        async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
            tasks = [check_path(client, target_url, path) for path in DOC_PATHS]
            results = await asyncio.gather(*tasks)
            found = [r for r in results if r]

        if found:
            output = {
                "status": "found",
                "count": len(found),
                "urls": found,
                "next_step": f"Usa parse_api_spec con alguna de estas URLs para extraer los endpoints."
            }
        else:
            output = {
                "status": "not_found",
                "message": "No se encontraron definiciones publicas en los paths comunes.",
                "suggestion": "Prueba con subdominios (api., docs.) o rutas personalizadas."
            }

        return [TextContent(type="text", text=json.dumps(output, indent=2, ensure_ascii=False))]


    elif name == "parse_api_spec":
        source = arguments["source"]

        try:
            spec = {}
            base_url = ""
            
            if source.startswith("http"):
                async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                    resp = await client.get(source)
                    resp.raise_for_status()
                    content = resp.text
                    parsed = urlparse(source)
                    base_url = f"{parsed.scheme}://{parsed.netloc}"
            else:
                with open(source, 'r', encoding='utf-8') as f:
                    content = f.read()

            try:
                spec = json.loads(content)
            except json.JSONDecodeError:
                spec = yaml.safe_load(content)

            if not spec:
                return [TextContent(type="text", text=json.dumps({"error": "No se pudo parsear la especificacion."}))]


            if "servers" in spec and spec["servers"]:
                server_url = spec["servers"][0].get("url", "/")
                if server_url.startswith("http"):
                    base_url = server_url
                elif base_url:
                    base_url = urljoin(base_url, server_url)


            endpoints = []
            for path, methods in spec.get("paths", {}).items():
                for method, details in methods.items():
                    if method.lower() not in ["get","post","put","delete","patch"]:
                        continue
                    full_url = urljoin(base_url, path) if base_url else path
                    params   = {"query": [], "path": [], "body": []}
                    for p in details.get("parameters", []):
                        p_in = p.get("in", "query")
                        if p_in in params:
                            params[p_in].append(p.get("name"))
                    if "requestBody" in details:
                        content_types = details["requestBody"].get("content", {})
                        if "application/json" in content_types:
                            body_schema = content_types["application/json"].get("schema", {})
                            if "properties" in body_schema:
                                params["body"] = list(body_schema["properties"].keys())
                    endpoints.append({
                        "method": method.upper(),
                        "url": full_url,
                        "summary": details.get("summary", ""),
                        "params": params
                    })

            output = {
                "status": "ok",
                "source": source,
                "base_url": base_url,
                "endpoint_count": len(endpoints),
                "endpoints": endpoints,
                "next_step": "Usa classify_endpoints con esta lista para obtener el analisis de riesgo OWASP."
            }
        except Exception as e:
            output = {"error": str(e)}

        return [TextContent(type="text", text=json.dumps(output, indent=2, ensure_ascii=False))]


    elif name == "classify_endpoints":
        if "single_url" in arguments and arguments["single_url"]:
            url    = arguments["single_url"]
            method = arguments.get("single_method", "GET")
            result = classify_endpoint(url, method)
            output = {"url": url, "method": method, **result}
        else:
            endpoints = arguments.get("endpoints", [])
            classified = classify_list(endpoints)
            

            by_risk = {"Critical": [], "High": [], "Medium": [], "Low": []}
            for ep in classified:
                risk = ep.get("risk", "Low")
                by_risk.setdefault(risk, []).append(ep)
            
            output = {
                "total": len(classified),
                "summary": {risk: len(eps) for risk, eps in by_risk.items() if eps},
                "endpoints": classified
            }

        return [TextContent(type="text", text=json.dumps(output, indent=2, ensure_ascii=False))]

    else:
        return [TextContent(type="text", text=json.dumps({"error": f"Tool desconocida: {name}"}))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
