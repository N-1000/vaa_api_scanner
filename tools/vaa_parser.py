
import asyncio
import json
import yaml
import httpx
import argparse
import sys
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

class StandaloneOpenAPIParser:
    def __init__(self):
        self.spec = {}
        self.base_url = ""

    async def load_spec(self, source: str):
        try:
            if source.startswith("http"):
                async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                    resp = await client.get(source)
                    resp.raise_for_status()
                    content = resp.text
                    parsed = urlparse(source)
                    self.base_url = f"{parsed.scheme}://{parsed.netloc}"
            else:
                with open(source, 'r', encoding='utf-8') as f:
                    content = f.read()

            try:
                self.spec = json.loads(content)
            except json.JSONDecodeError:
                self.spec = yaml.safe_load(content)
            
            if "servers" in self.spec and self.spec["servers"]:
                server_url = self.spec["servers"][0].get("url", "/")
                if not server_url.startswith("http") and self.base_url:
                     self.base_url = urljoin(self.base_url, server_url)
                elif server_url.startswith("http"):
                     self.base_url = server_url
            
            return True
        except Exception as e:
            print(f"[ERROR] No se pudo cargar la especificacion: {e}")
            return False

    def parse_endpoints(self) -> List[Dict[str, Any]]:
        targets = []
        paths = self.spec.get("paths", {})
        if not paths: return []

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                    continue
                
                full_url = urljoin(self.base_url, path) if self.base_url else path
                
                target = {
                    "method": method.upper(),
                    "url": full_url,
                    "summary": details.get("summary", ""),
                    "params": self._extract_params(details)
                }
                targets.append(target)
        return targets

    def _extract_params(self, details: Dict):
        params = {"query": [], "path": [], "body": []}

        for p in details.get("parameters", []):
            p_in = p.get("in", "query")
            if p_in in params:
                params[p_in].append(p.get("name"))
        

        if "requestBody" in details:
            content = details["requestBody"].get("content", {})
            if "application/json" in content:
                schema = content["application/json"].get("schema", {})
                if "properties" in schema:
                    params["body"] = list(schema["properties"].keys())
        return params

async def main():
    parser = argparse.ArgumentParser(description="VAA Parser: Extractor de endpoints de OpenAPI")
    parser.add_argument("--source", required=True, help="URL o archivo local de la especificación (JSON/YAML)")
    parser.add_argument("--json", action="store_true", help="Salida en formato JSON")
    args = parser.parse_args()

    parser_obj = StandaloneOpenAPIParser()
    if await parser_obj.load_spec(args.source):
        endpoints = parser_obj.parse_endpoints()
        if args.json:
            print(json.dumps(endpoints, indent=2))
        else:
            print(f"[*] Se han extraido {len(endpoints)} endpoints:\n")
            for ep in endpoints:
                print(f" {ep['method']:<7} {ep['url']}")
                if any(ep['params'].values()):
                    print(f"   - Params: {ep['params']}")
    else:
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
