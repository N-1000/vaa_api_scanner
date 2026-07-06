
import json
import yaml  # pyre-ignore[21]
import httpx  # pyre-ignore[21]
from app.config.settings import settings  # pyre-ignore[21]
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
from app.utils.logger import logger  # pyre-ignore[21]

class OpenAPIParser:
    """
    Parsea especificaciones OpenAPI (Swagger) v4.0.0 y v4.0.0.
    Extrae endpoints, metodos y esquemas de parametros para alimentar al escaner.
    """

    def __init__(self):
        self.spec = {}
        self.base_url = ""

    async def load_spec(self, source: str, headers: Optional[Dict[str, str]] = None, verify: Optional[bool] = None) -> bool:
        """
        Carga la especificacion desde una URL o archivo local.
        Acepta headers opcionales para autenticacion (e.g., Authorization: Bearer ...).
        """
        verify_ssl = verify if verify is not None else settings.VERIFY_SSL

        try:
            content = ""
            if source.startswith("http"):
                logger.info(f"[OpenAPI] Descargando especificacion desde: {source}")
                async with httpx.AsyncClient(verify=verify_ssl, timeout=10.0) as client:
                    resp = await client.get(source, headers=headers or {})
                    resp.raise_for_status()
                    content = resp.text

                    parsed = urlparse(source)
                    self.base_url = f"{parsed.scheme}://{parsed.netloc}"
            else:
                logger.info(f"[OpenAPI] Leyendo archivo local: {source}")
                with open(source, 'r', encoding='utf-8') as f:
                    content = f.read()


            try:
                self.spec = json.loads(content)
            except json.JSONDecodeError:

                try:
                    self.spec = yaml.safe_load(content)
                except yaml.YAMLError:
                    logger.debug("[OpenAPI] No se pudo parsear el archivo (ni JSON ni YAML valido).")
                    return False
            

            version = self.spec.get("openapi", self.spec.get("swagger", "Unknown"))
            logger.info(f"[OpenAPI] Especificacion cargada exitosamente. Version: {version}")
            

            if "servers" in self.spec and self.spec["servers"]:
                server_url = self.spec["servers"][0].get("url", "/")  # pyre-ignore[16]
                if not server_url.startswith("http") and self.base_url:
                     self.base_url = urljoin(self.base_url, server_url)
                elif server_url.startswith("http"):
                     self.base_url = server_url
            
            logger.info(f"[OpenAPI] Base URL detectada: {self.base_url}")
            return True

        except Exception as e:


            logger.debug(f"[OpenAPI] Error cargando especificacion (ignorando si es auto-discovery): {e}")
            return False

    def parse_endpoints(self) -> List[Dict[str, Any]]:
        """
        Extrae todos los endpoints y sus definiciones.
        Retorna una lista de diccionarios con metadata para el scanner.
        """
        targets = []
        paths = self.spec.get("paths", {})
        
        for path, methods in paths.items():  # pyre-ignore[16]
            for method, details in methods.items():  # pyre-ignore[16]
                if method.lower() not in ["get", "post", "put", "delete", "patch", "options", "head"]:
                    continue
                

                full_url = urljoin(self.base_url, path) if self.base_url else path
                

                params = self._extract_parameters(details.get("parameters", []), path)  # pyre-ignore[6]
                

                for p_info in params.get("path", []):
                    p_name = p_info["name"]
                    p_type = p_info.get("schema", {}).get("type", "string")
                    p_fmt  = p_info.get("schema", {}).get("format", "")
                    placeholder = "{" + p_name + "}"
                    if placeholder in full_url:
                        if p_type in ("integer", "number"):
                            val = "101"
                        elif p_fmt == "uuid" or "uuid" in p_name.lower():
                            # UUID format explícito o nombre contiene 'uuid'
                            val = "123e4567-e89b-12d3-a456-426614174001"
                        elif p_type == "string" and any(
                            kw in p_name.lower() for kw in ("id", "key", "guid", "ref")
                        ):
                            # Param tipo string con nombre de identificador → asumir UUID
                            # (el seed se puede sobrescribir con IDs cosechados en BOLA harvest)
                            val = "123e4567-e89b-12d3-a456-426614174001"
                        else:
                            val = "1"
                        full_url = full_url.replace(placeholder, val)


                body_schema = self._extract_body(details, params)
                

                auth = details.get("security", self.spec.get("security", []))
                
                target = {
                    "url": full_url,
                    "method": method.upper(),
                    "path": path,
                    "summary": details.get("summary", ""),
                    "params": params,
                    "body_schema": body_schema,
                    "auth_required": bool(auth)
                }
                targets.append(target)
                
        logger.info(f"[OpenAPI] Se extrajeron {len(targets)} endpoints unicos.")
        return targets

    def _resolve_ref(self, ref: str) -> Dict[str, Any]:
        """Resuelve una referencia $ref local."""
        if not ref.startswith("#/"):
            return {}
        parts = ref[2:].split("/")
        curr = self.spec
        try:
            for p in parts:
                curr = curr[p]
            return curr
        except KeyError:
            return {}

    def _extract_parameters(self, params_list: List[Dict], path: str) -> Dict[str, Any]:
        """Procesa parametros de query y path. Retorna diccionario estructurado para fuzzer."""
        extracted = {"query": [], "path": [], "header": [], "cookie": []}
        for param in params_list:
            if "$ref" in param:
                param = self._resolve_ref(param["$ref"])
                if not param:
                    continue
                    
            p_name = param.get("name")
            p_in = param.get("in", "query")
            if not p_name: continue

            extracted[p_in].append({
                "name": p_name,
                "in": p_in,
                "schema": param.get("schema", {})
            })
                
        return extracted

    def _extract_body(self, details: Dict, extracted_params: Dict[str, Any]) -> Any:
        """Extrae esquema del cuerpo de la peticion (JSON) y aplana las propiedades en extracted_params."""
        schema = None
        

        if "requestBody" in details:
            content = details["requestBody"].get("content", {})

            if "application/json" in content:
                schema = content["application/json"].get("schema", {})
            else:
                for ct, conf in content.items():
                    if "schema" in conf:
                        schema = conf["schema"]
                        break

        else:
            for param in details.get("parameters", []):
                if param.get("in") == "body":
                    schema = param.get("schema", {})
                    break

        if not schema:
            return None


        if "$ref" in schema:
            schema = self._resolve_ref(schema["$ref"])


        if "body" not in extracted_params:
            extracted_params["body"] = []
            
        properties = schema.get("properties", {})
        for prop_name, prop_details in properties.items():
            if "$ref" in prop_details:
                prop_details = self._resolve_ref(prop_details["$ref"])
            
            extracted_params["body"].append({
                "name": prop_name,
                "in": "body",
                "schema": prop_details
            })

        return schema
