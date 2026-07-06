
import os
import httpx  # pyre-ignore[21]
from typing import List, Dict, Any, Optional, Tuple

from app.config.settings import settings  # pyre-ignore[21]
from app.utils.logger import logger  # pyre-ignore[21]
from app.core.modules.openapi_parser import OpenAPIParser  # pyre-ignore[21]
from app.core.modules.postman_parser import PostmanParser  # pyre-ignore[21]
from app.utils.ingestor import TrafficIngestor  # pyre-ignore[21]

class M74P1Navigator:
    """
    M74P1: Structural API Navigator.
    Reemplaza la navegacion visual (crawler) por ingesta de planos y deteccion inteligente.
    """

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        self.options = options or {}
        self.postman_parser = PostmanParser()
        self.openapi_parser = OpenAPIParser()


    async def navigate_input(self, input_path_or_url: str, verify: Optional[bool] = None) -> List[Dict[str, Any]]:
        """
        Punto de entrada principal. Detecta el formato y extrae endpoints.
        """

        format_type = await self._sniff_format(input_path_or_url, verify=verify)
        logger.info(f"[M74P1] Formato detectado: {format_type.upper()}")

        endpoints = []


        if format_type == "postman":
            env_file = self.options.get("env_file")
            endpoints = self.postman_parser.parse(input_path_or_url, env_file)
            
        elif format_type == "openapi":
            if await self.openapi_parser.load_spec(input_path_or_url):
                endpoints = self.openapi_parser.parse_endpoints()
                
        elif format_type == "har":


             api_only = self.options.get("api_only", settings.IMPORT_API_ONLY)
             endpoints = TrafficIngestor.load_traffic(input_path_or_url, api_only=api_only)
             
        elif format_type == "url":

             is_api, reason = await self._classify_target_type(input_path_or_url, verify=verify)
             if not is_api:
                 logger.warning(f"[ABORT] El objetivo parece ser una Interfaz Web ({reason}).")
                 logger.warning("[SUGGESTION] Recomendacion: Use 'LokiTrace Web Scanner' para aplicaciones con GUI.")
                 return []
             

             if await self._probe_openapi_autodiscovery(input_path_or_url, verify=verify):
                  endpoints = self.openapi_parser.parse_endpoints()
             else:

                  endpoints = [{"url": input_path_or_url, "method": "GET", "source": "input"}]


        else:
            logger.error(
                f"[M74P1] Formato no reconocido o archivo no encontrado: '{input_path_or_url}'. "
                f"Formatos soportados: Postman, OpenAPI/Swagger, HAR, URL directa."
            )

        logger.info(f"[M74P1] Se cargaron {len(endpoints)} endpoints estructurales.")


        if endpoints:
            logger.info("[M74P1] ╔══ SUPERFICIE DE ATAQUE DESCUBIERTA ══════════════════════")
            for i, ep in enumerate(endpoints, 1):
                method = ep.get("method", "GET").upper()
                url    = ep.get("url", "")
                src    = ep.get("source", "")
                auth   = " 🔒" if ep.get("requires_auth") else ""
                logger.info(f"[M74P1] ║ [{i:02d}] {method:<7} {url}{auth}  ({src})")
            logger.info("[M74P1] ╚════════════════════════════════════════════════════════")

        return endpoints

    @staticmethod
    def _has_key(text: str, key: str) -> bool:
        """
        Comprueba si una clave JSON existe en el texto, tolerando ambos estilos:
          - Compacto:    "openapi":
          - Prettified:  "openapi" :   (espacio antes del colon — estilo Jackson/spring-doc)
        """
        return f'"{key}":' in text or f'"{key}" :' in text

    async def _sniff_format(self, source: str, verify: Optional[bool] = None) -> str:
        """Determina si la entrada es Postman, OpenAPI, HAR o URL."""
        verify_ssl = verify if verify is not None else settings.VERIFY_SSL

        if source.startswith("http"):
            try:
                async with httpx.AsyncClient(verify=verify_ssl, timeout=5.0) as client:
                    head_resp = await client.head(source)
                    ct = head_resp.headers.get("content-type", "").lower()

                    is_spec_content_type = (
                        "" in ct or "yaml" in ct or
                        source.endswith(".") or source.endswith(".yaml")
                    )

                    if is_spec_content_type:
                        r = await client.get(source)
                        content = r.text[:1000]
                        if self._has_key(content, "_postman_id"): return "postman"
                        if self._has_key(content, "openapi") or self._has_key(content, "swagger"): return "openapi"
                        if 'openapi:' in content or 'swagger:' in content: return "openapi"
            except Exception:
                pass
            return "url"

        if not os.path.exists(source):
            return "unknown"


        try:
            with open(source, 'r', encoding='utf-8', errors='ignore') as f:
                header = f.read(8192)

                if self._has_key(header, "_postman_id"): return "postman"
                if self._has_key(header, "openapi") or self._has_key(header, "swagger"): return "openapi"
                if 'openapi:' in header or 'swagger:' in header: return "openapi"
                if self._has_key(header, "log") and self._has_key(header, "entries"): return "har"


                remainder = f.read()
                full = header + remainder
                if self._has_key(full, "openapi") or self._has_key(full, "swagger"): return "openapi"
                if 'openapi:' in full or 'swagger:' in full: return "openapi"
                if self._has_key(full, "log") and self._has_key(full, "entries"): return "har"
        except: pass

        return "unknown"

    async def _classify_target_type(self, url: str, verify: Optional[bool] = None) -> Tuple[bool, str]:
        """
        Distingue entre API Endpoint y Web Interface.
        Returns: (is_api, reason)
        [FIX Bug 3] Inyecta el token de self.options en HEAD y GET para que
        targets protegidos no devuelvan 401 → HTML del login → falso-negativo.
        """
        verify_ssl = verify if verify is not None else settings.VERIFY_SSL

        auth_headers = {}
        token = self.options.get("token") or self.options.get("auth_token")
        if token:
            auth_headers["Authorization"] = f"Bearer {token}"

        try:
            async with httpx.AsyncClient(verify=verify_ssl, follow_redirects=True, timeout=8.0) as client:
                resp = await client.head(url, headers=auth_headers)
                ct = resp.headers.get("content-type", "").lower()


                if "application/" in ct or "xml" in ct:
                    return True, f"Content-Type: {ct}"


                needs_body_check = (
                    "text/html" in ct or
                    not ct or
                    "octet-stream" in ct
                )

                if needs_body_check:
                    resp_get = await client.get(url, headers=auth_headers)
                    body_start = resp_get.text[:1000].lower()
                    get_ct = resp_get.headers.get("content-type", "").lower()


                    if "application/" in get_ct or "xml" in get_ct:
                        return True, f"GET Content-Type: {get_ct}"


                    if "<!doctype html" in body_start or "<html" in body_start:

                        if "swagger-ui" in body_start or "redoc" in body_start:
                            return True, "Swagger UI detected"
                        return False, "HTML Document detected"


                    if body_start.strip().startswith(("{" , "[")):
                        return True, "JSON body detected (malformed Content-Type)"

            return True, "Unknown/Generic (Default to API)"

        except Exception as e:
            logger.debug(f"Error classifying target: {e}")
            return True, "Connection Error (Assume API)"

    async def _probe_openapi_autodiscovery(self, base_url: str, verify: Optional[bool] = None) -> bool:
        """Intenta descubrir openapi. en rutas comunes.
        [FIX Bug 2] Pasa el token de self.options a load_spec para que el
        request de discovery lleve Authorization header y no reciba 401.
        """
        verify_ssl = verify if verify is not None else settings.VERIFY_SSL
        common_paths = [
            "/openapi.json", "/swagger.json", "/api/v1/openapi.json",
            "/openapi.yaml", "/swagger.yaml", "/api/v1/openapi.yaml",
            "/docs"
        ]
        base = base_url.rstrip("/")


        auth_headers: Dict[str, str] = {}
        token = self.options.get("token") or self.options.get("auth_token")
        if token:
            auth_headers["Authorization"] = f"Bearer {token}"


        for path in common_paths:
            probe_url = f"{base}{path}"
            temp_parser = OpenAPIParser()
            if await temp_parser.load_spec(probe_url, headers=auth_headers, verify=verify_ssl):
                self.openapi_parser = temp_parser
                logger.info(f"[M74P1] Auto-Discovery exitoso: OpenAPI encontrado en {probe_url}")
                return True

        return False
