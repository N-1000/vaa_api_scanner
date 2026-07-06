
import json
import re
from typing import List, Dict, Any, Optional

class PostmanParser:
    """
    Parser para Colecciones de Postman (v4.0.0 / v4.0.0).
    Soporta extraccion recursiva de requests y resolucion de variables de entorno.
    """

    def __init__(self):
        self.variables = {}

    def parse(self, collection_path: str, environment_path: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Parsea una coleccion de Postman y retorna una lista de endpoints planos.
        :param collection_path: Ruta al archivo .json de la coleccion.
        :param environment_path: Ruta al archivo .json del entorno (opcional).
        """
        endpoints = []
        

        if environment_path:
            self.variables = self._load_environment(environment_path)
            

        try:
            with open(collection_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error cargando coleccion Postman: {e}")
            return []


        if 'variable' in data:
            for v in data['variable']:
                if v.get('key') and v.get('value'):

                    if v['key'] not in self.variables:
                        self.variables[v['key']] = v['value']


        if 'item' in data:
            self._extract_items(data['item'], endpoints)
            
        return endpoints

    def _load_environment(self, env_path: str) -> Dict[str, str]:
        """Carga variables desde un archivo de entorno de Postman."""
        vars_map = {}
        try:
            with open(env_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if 'values' in data:
                    for item in data['values']:
                        if item.get('enabled', True):
                            vars_map[item['key']] = item['value']
        except Exception as e:
            print(f"Error cargando entorno Postman: {e}")
        return vars_map

    def _extract_items(self, items: List[Dict], storage: List[Dict]):
        """Navega recursivamente folders e items."""
        for item in items:

            if 'item' in item:
                self._extract_items(item['item'], storage)
            

            elif 'request' in item:
                endpoint = self._parse_request(item)
                if endpoint:
                    storage.append(endpoint)

    def _parse_request(self, item: Dict) -> Optional[Dict]:
        """Procesa un item de request individual."""
        try:
            req = item['request']
            name = item.get('name', 'Unknown')
            method = req.get('method', 'GET')
            

            url_raw = ""
            if isinstance(req.get('url'), str):
                url_raw = req['url']
            elif isinstance(req.get('url'), dict):
                url_raw = req['url'].get('raw', '')
            

            final_url = self._resolve_vars(url_raw)
            

            headers = {}
            if 'header' in req:
                for h in req['header']:
                    if not h.get('disabled'):
                        headers[h['key']] = self._resolve_vars(h['value'])
            

            auth = {}
            if 'auth' in req:
                auth_type = req['auth'].get('type')
                if auth_type == 'bearer':
                    token = req['auth'].get('bearer', [{}])[0].get('value', '')
                    auth = {'type': 'bearer', 'token': self._resolve_vars(token)}
                elif auth_type == 'apikey':

                     pass


            body = {}
            if 'body' in req and req['body'].get('mode') == 'raw':
                raw_body = req['body'].get('raw', '')
                try:

                    if raw_body and '{' in raw_body:
                        json_str = self._resolve_vars(raw_body)
                        body = json.loads(json_str)
                except:
                    pass

            return {
                "name": name,
                "url": final_url,
                "method": method,
                "headers": headers,
                "body": body,
                "auth": auth,
                "source": "postman"
            }

        except Exception as e:

            return None

    def _resolve_vars(self, text: str) -> str:
        """Reemplaza {{variables}} con sus valores."""
        if not text or not isinstance(text, str):
            return text
            
        def replace(match):
            key = match.group(1)
            return str(self.variables.get(key, f"{{{{{key}}}}}"))
            
        return re.sub(r'\{\{([a-zA-Z0-9_.-]+)\}\}', replace, text)
