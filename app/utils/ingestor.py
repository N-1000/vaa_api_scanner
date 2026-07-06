
import base64
import json
import defusedxml.ElementTree as ET
from typing import List, Dict, Any, Optional
import os
import re
from app.config.settings import settings
from urllib.parse import urlparse, parse_qs, urljoin
from app.utils.logger import logger  # pyre-ignore[21]

class TrafficIngestor:
    """
    Clase estatica para cargar archivos de trafico.
    Detecta automaticamente el formato por extension.
    """
    
    @staticmethod
    def load_traffic(filepath: str, api_only: bool = None) -> List[Dict[str, Any]]:
        """
        Carga trafico desde archivo. Retorna lista de diccionarios normalizada.
        """
        if api_only is None:
            api_only = getattr(settings, "IMPORT_API_ONLY", False)

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Archivo no encontrado: {filepath}")

        _, ext = os.path.splitext(filepath)
        ext = ext.lower()

        if ext == ".json":
            return TrafficIngestor._parse_json(filepath, api_only)
        elif ext == ".xml":
            return TrafficIngestor._parse_burp_xml(filepath, api_only)
        elif ext == ".har":
            return TrafficIngestor._parse_har(filepath, api_only)
        else:
            raise ValueError(f"Formato no soportado: {ext}")

    @staticmethod
    def _parse_json(filepath: str, api_only: bool = False) -> List[Dict[str, Any]]:
        with open(filepath, 'r') as f:
            data = json.load(f)
            
            traffic = []
            if isinstance(data, list):
                traffic = data
            else:
                traffic = [data]
                
            if api_only:
                filtered = []
                for item in traffic:
                    path = item.get("path", "").lower()
                    if any(kw in path for kw in settings.API_PATH_KEYWORDS):
                        filtered.append(item)
                return filtered
            return traffic

    @staticmethod
    def _parse_burp_xml(filepath: str, api_only: bool = False) -> List[Dict[str, Any]]:
        """
        Parsea exportaciones XML de Burp Suite (Save Items → base64=true).
        Extrae URL, método, headers, params Y response body decodificado.
        El response body es clave para que M6 coseche UUIDs de otros usuarios.
        """
        traffic_list = []
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            for item in root.findall('item'):
                url_elem = item.find('url')
                if url_elem is None:
                    continue

                full_url = url_elem.text or ""
                if not full_url:
                    continue

                parsed    = urlparse(full_url)
                path      = parsed.path
                method_el = item.find('method')
                method    = (method_el.text or "GET").upper() if method_el is not None else "GET"


                params: Dict[str, str] = {}
                for k, v in parse_qs(parsed.query).items():
                    params[k] = v[0]

                params_elem = item.find('parameters')
                if params_elem is not None:
                    for param in params_elem.findall('parameter'):
                        name  = param.find('name')
                        value = param.find('value')
                        if name is not None and value is not None and name.text:
                            params[name.text] = value.text or ""


                headers: Dict[str, str] = {}
                req_elem = item.find('request')
                if req_elem is not None:
                    is_b64 = (req_elem.get('base64', 'false').lower() == 'true')
                    raw_req = req_elem.text or ""
                    try:
                        req_text = base64.b64decode(raw_req).decode('utf-8', errors='ignore') if is_b64 else raw_req
                        for line in req_text.splitlines()[1:]:
                            if ':' in line:
                                hname, _, hval = line.partition(':')
                                hname = hname.strip()
                                if hname.lower() not in ('host', 'content-length', 'connection'):
                                    headers[hname] = hval.strip()
                            elif not line.strip():
                                break
                    except Exception:
                        pass


                response_text = ""
                resp_elem = item.find('response')
                if resp_elem is not None:
                    is_b64 = (resp_elem.get('base64', 'false').lower() == 'true')
                    raw_resp = resp_elem.text or ""
                    try:
                        decoded = base64.b64decode(raw_resp).decode('utf-8', errors='ignore') if is_b64 else raw_resp

                        if '\r\n\r\n' in decoded:
                            response_text = decoded.split('\r\n\r\n', 1)[1]
                        elif '\n\n' in decoded:
                            response_text = decoded.split('\n\n', 1)[1]
                        else:
                            response_text = decoded
                    except Exception:
                        pass


                is_api = not api_only
                if api_only and any(kw in path.lower() for kw in settings.API_PATH_KEYWORDS):
                    is_api = True

                if is_api:
                    traffic_list.append({
                        "url":           full_url,
                        "path":          path,
                        "method":        method,
                        "params":        params,
                        "headers":       headers,
                        "response_text": response_text,
                    })

        except Exception as e:
            logger.error(f"[Ingestor] Error parseando Burp XML: {e}")

        logger.info(f"[Ingestor] Burp XML: {len(traffic_list)} items cargados.")
        return traffic_list

    @staticmethod
    def load_burp_responses(filepath: str) -> List[Dict[str, str]]:
        """
        Carga SOLO los response bodies de un XML de Burp Suite.
        Retorna lista de {url, response_text} para que M6._harvest_ids_from_burp
        pueda extraer UUIDs e IDs de otros usuarios sin necesidad de parsear
        el tráfico completo.
        Uso: m6._harvest_ids_from_burp(TrafficIngestor.load_burp_responses(path))
        """
        items = TrafficIngestor._parse_burp_xml(filepath, api_only=False)
import base64
import json
import defusedxml.ElementTree as ET
from typing import List, Dict, Any, Optional
import os
import re
from app.config.settings import settings
from urllib.parse import urlparse, parse_qs, urljoin
from app.utils.logger import logger  # pyre-ignore[21]

class TrafficIngestor:
    """
    Clase estatica para cargar archivos de trafico.
    Detecta automaticamente el formato por extension.
    """
    
    @staticmethod
    def load_traffic(filepath: str, api_only: bool = None) -> List[Dict[str, Any]]:
        """
        Carga trafico desde archivo. Retorna lista de diccionarios normalizada.
        """
        if api_only is None:
            api_only = getattr(settings, "IMPORT_API_ONLY", False)

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Archivo no encontrado: {filepath}")

        _, ext = os.path.splitext(filepath)
        ext = ext.lower()

        if ext == ".json":
            return TrafficIngestor._parse_json(filepath, api_only)
        elif ext == ".xml":
            return TrafficIngestor._parse_burp_xml(filepath, api_only)
        elif ext == ".har":
            return TrafficIngestor._parse_har(filepath, api_only)
        else:
            raise ValueError(f"Formato no soportado: {ext}")

    @staticmethod
    def _parse_json(filepath: str, api_only: bool = False) -> List[Dict[str, Any]]:
        with open(filepath, 'r') as f:
            data = json.load(f)
            
            traffic = []
            if isinstance(data, list):
                traffic = data
            else:
                traffic = [data]
                
            if api_only:
                filtered = []
                for item in traffic:
                    path = item.get("path", "").lower()
                    if any(kw in path for kw in settings.API_PATH_KEYWORDS):
                        filtered.append(item)
                return filtered
            return traffic

    @staticmethod
    def _parse_burp_xml(filepath: str, api_only: bool = False) -> List[Dict[str, Any]]:
        """
        Parsea exportaciones XML de Burp Suite (Save Items → base64=true).
        Extrae URL, método, headers, params Y response body decodificado.
        El response body es clave para que M6 coseche UUIDs de otros usuarios.
        """
        traffic_list = []
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            for item in root.findall('item'):
                url_elem = item.find('url')
                if url_elem is None:
                    continue

                full_url = url_elem.text or ""
                if not full_url:
                    continue

                parsed    = urlparse(full_url)
                path      = parsed.path
                method_el = item.find('method')
                method    = (method_el.text or "GET").upper() if method_el is not None else "GET"


                params: Dict[str, str] = {}
                for k, v in parse_qs(parsed.query).items():
                    params[k] = v[0]

                params_elem = item.find('parameters')
                if params_elem is not None:
                    for param in params_elem.findall('parameter'):
                        name  = param.find('name')
                        value = param.find('value')
                        if name is not None and value is not None and name.text:
                            params[name.text] = value.text or ""


                headers: Dict[str, str] = {}
                req_elem = item.find('request')
                if req_elem is not None:
                    is_b64 = (req_elem.get('base64', 'false').lower() == 'true')
                    raw_req = req_elem.text or ""
                    try:
                        req_text = base64.b64decode(raw_req).decode('utf-8', errors='ignore') if is_b64 else raw_req
                        for line in req_text.splitlines()[1:]:
                            if ':' in line:
                                hname, _, hval = line.partition(':')
                                hname = hname.strip()
                                if hname.lower() not in ('host', 'content-length', 'connection'):
                                    headers[hname] = hval.strip()
                            elif not line.strip():
                                break
                    except Exception:
                        pass


                response_text = ""
                resp_elem = item.find('response')
                if resp_elem is not None:
                    is_b64 = (resp_elem.get('base64', 'false').lower() == 'true')
                    raw_resp = resp_elem.text or ""
                    try:
                        decoded = base64.b64decode(raw_resp).decode('utf-8', errors='ignore') if is_b64 else raw_resp

                        if '\r\n\r\n' in decoded:
                            response_text = decoded.split('\r\n\r\n', 1)[1]
                        elif '\n\n' in decoded:
                            response_text = decoded.split('\n\n', 1)[1]
                        else:
                            response_text = decoded
                    except Exception:
                        pass


                is_api = not api_only
                if api_only and any(kw in path.lower() for kw in settings.API_PATH_KEYWORDS):
                    is_api = True

                if is_api:
                    traffic_list.append({
                        "url":           full_url,
                        "path":          path,
                        "method":        method,
                        "params":        params,
                        "headers":       headers,
                        "response_text": response_text,
                    })

        except Exception as e:
            logger.error(f"[Ingestor] Error parseando Burp XML: {e}")

        logger.info(f"[Ingestor] Burp XML: {len(traffic_list)} items cargados.")
        return traffic_list

    @staticmethod
    def load_burp_responses(filepath: str) -> List[Dict[str, str]]:
        """
        Carga SOLO los response bodies de un XML de Burp Suite.
        Retorna lista de {url, response_text} para que M6._harvest_ids_from_burp
        pueda extraer UUIDs e IDs de otros usuarios sin necesidad de parsear
        el tráfico completo.
        Uso: m6._harvest_ids_from_burp(TrafficIngestor.load_burp_responses(path))
        """
        items = TrafficIngestor._parse_burp_xml(filepath, api_only=False)
        return [
            {"url": it.get("url", ""), "response_text": it.get("response_text", "")}
            for it in items
            if it.get("response_text")
        ]

    @staticmethod
    def load_traffic_from_dict(data: Optional[Dict], api_only: bool = False) -> List[Dict[str, Any]]:
        """
        Acepta un dict HAR ya cargado en memoria (evita re-leer el disco).
        """
        if not data:
            return []

        if 'log' in data and 'entries' in data.get('log', {}):
            return TrafficIngestor._process_har_dict(data, api_only)

        if isinstance(data, list):
            return data
        return []

    @staticmethod
    def _parse_har(filepath: str, api_only: bool = False) -> List[Dict[str, Any]]:
        """
        Parsea formato HTTP Archive (HAR).
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
            return TrafficIngestor._process_har_dict(data, api_only)
        except Exception as e:
            logger.error(f"Error parseando archivo HAR {filepath}: {e}")
            return []

    @staticmethod
    def _process_har_dict(data: Dict, api_only: bool = False) -> List[Dict[str, Any]]:
        traffic_list = []
        try:
            entries = data.get('log', {}).get('entries', [])
            for entry in entries:
                req = entry.get('request', {})
                url = req.get('url', '')
                
                if not url:
                    continue
                    
                parsed = urlparse(url)
                path = parsed.path
                params = {}
                
                for qs in req.get('queryString', []):
                    params[qs['name']] = qs['value']
                
                headers = {}
                ignored_headers = ["content-length", "host", "connection", "accept-encoding", "user-agent"]
                for h in req.get('headers', []):
                    if h['name'].lower() not in ignored_headers:
                        headers[h['name']] = h['value']
                
                post_data = req.get('postData', {})
                mime = post_data.get('mimeType', '').lower()
                
                if 'application/x-www-form-urlencoded' in mime:
                    for pd in post_data.get('params', []):
                         params[pd['name']] = pd['value']
                elif 'application/json' in mime and post_data.get('text'):
                    try:
                        # Extraer campos de nivel superior del body JSON como params
                        j_body = json.loads(post_data.get('text'))
                        if isinstance(j_body, dict):
                            for k, v in j_body.items():
                                if not isinstance(v, (dict, list)):
                                    params[k] = str(v)
                    except Exception:
                        pass
                
                if not params and parsed.query:
                    qs_parsed = parse_qs(parsed.query)
                    for k, v in qs_parsed.items():
                        params[k] = v[0]

                is_api = not api_only
                if api_only:
                    if any(kw in path.lower() for kw in settings.API_PATH_KEYWORDS):
                        is_api = True

                    resp_mime = entry.get('response', {}).get('content', {}).get('mimeType', '').lower()
                    if any(mt in resp_mime for mt in settings.API_MIME_TYPES):
                        is_api = True

                    if any(path.lower().endswith(ext) for ext in settings.IGNORED_EXTENSIONS):
                        is_api = False

                if is_api:
                    traffic_list.append({
                        "url": url,
                        "path": path,
                        "params": params,
                        "method": req.get('method', 'GET'),
                        "headers": headers
                    })
                    
        except Exception as e:
            logger.error(f"Error procesando data HAR: {e}")
            
        return traffic_list
