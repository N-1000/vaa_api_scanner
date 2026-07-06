
from typing import Dict, Any, List, Union, Optional
import re
import json
import os
from app.config.settings import settings  # pyre-ignore[21]
from app.utils.logger import logger  # pyre-ignore[21]


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
_ID_PARAMS        = frozenset({"id", "user_id", "userId", "account_id", "accountId",
                                "uuid", "guid"})
_GRAPHQL_PARAMS   = frozenset({"query", "mutation"})


_ENDPOINT_TYPE_MAP = [
    ("auth",    _AUTH_KEYWORDS),
    ("admin",   _ADMIN_KEYWORDS),
    ("graphql", _GRAPHQL_KEYWORDS),
    ("health",  _HEALTH_KEYWORDS),
    ("webhook", _WEBHOOK_KEYWORDS),
    ("file",    _FILE_KEYWORDS),
    ("search",  _SEARCH_KEYWORDS),
]


_TYPE_DISPATCH: list = [
    (bool,  "bool"),
    (int,   "int"),
    (float, "float"),
    (dict,  "object"),
    (str,   "string"),
]
_NUMERIC_TYPES: frozenset = frozenset({"int", "float"})

class MarkovPredictor:
    """
    [Roadmap v4.0.0] Predictive Endpoint Discovery using Markov Chains.
    Aprende secuencias de rutas y predice posibles carpetas/archivos ocultos.
    """
    def __init__(self):

        self.transitions: Dict[str, Dict[str, int]] = {}

        self.roots = set()

    def learn_path(self, path: str):
        """Descompone una ruta y aprende las transiciones entre segmentos."""
        parts = [p for p in path.strip("/").split("/") if p]
        if not parts: return
        
        self.roots.add(parts[0])
        
        for i in range(len(parts) - 1):
            current = parts[i]
            next_part = parts[i+1]
            if current not in self.transitions:
                self.transitions[current] = {}
            self.transitions[current][next_part] = self.transitions[current].get(next_part, 0) + 1

    def predict_next(self, seed_part: str, limit: int = 3) -> List[str]:
        """Dada una parte de una ruta, predice las siguientes mas probables."""
        if seed_part not in self.transitions:
            return []

        sorted_next = sorted(self.transitions[seed_part].items(), key=lambda x: x[1], reverse=True)
        return [p[0] for p in sorted_next[:limit]]  # pyre-ignore

    def generate_probes(self, observed_paths: List[str]) -> List[str]:
        """
        [v4.0.0] Advanced Proactive Discovery.
        """
        probes = set()
        common_api_suffixes = ["admin", "debug", "v1", "v2", "v3", "config", "setup", "metrics", "health", "pvt", "internal", "export", "export-users", "admin/debug/export-users"]
        
        for path in observed_paths:
            parts = [p for p in path.strip("/").split("/") if p]
            if not parts: continue
            

            path_probes_count: int = 0
            MAX_PROBES_PER_PATH: int = 40
            

            last_part = parts[-1]
            predictions = self.predict_next(last_part, limit=5)
            for pred in predictions:
                probes.add("/".join(parts + [pred]))
                path_probes_count = path_probes_count + 1  # pyre-ignore
            

            version_indices = [i for i, p in enumerate(parts) if re.match(r"(v\d+|api|beta|dev|stg)", p.lower())]
            for i in version_indices:
                if path_probes_count > MAX_PROBES_PER_PATH: break
                for v in ["v1", "v2", "v3", "api"]:
                    new_parts = list(parts)
                    new_parts[i] = v
                    base_probe = "/".join(new_parts)
                    probes.add(base_probe)
                    path_probes_count = path_probes_count + 1  # pyre-ignore
                    

                    for s in ["admin", "debug", "health"]:
                        probes.add(f"{base_probe}/{s}")
                        path_probes_count = path_probes_count + 1  # pyre-ignore
                    

            for i, part in enumerate(parts):
                if path_probes_count > MAX_PROBES_PER_PATH: break
                if part.isdigit():
                    num = int(part)
                    for n in [0, 1, num + 1]:
                        new_parts = list(parts)
                        new_parts[i] = str(n)
                        probes.add("/".join(new_parts))
                        path_probes_count = path_probes_count + 1  # pyre-ignore
                elif re.match(r"^[0-9a-f]{8}-", part, re.IGNORECASE):
                    prefix = "/".join(parts[:i])  # pyre-ignore
                    probes.add(f"{prefix}/track")
                    path_probes_count = path_probes_count + 1  # pyre-ignore


            if len(parts) > 1:
                prefix = "/".join(parts[:-1])  # pyre-ignore
                for s in ["admin", "debug"]:
                    probes.add(f"{prefix}/{s}")
                    path_probes_count = path_probes_count + 1  # pyre-ignore

        return [p for p in probes if p and p not in observed_paths]

class M1GrammarModel:
    """
    Modelo de Gramatica que construye un mapa cognitivo del objetivo.
    Almacena que parametros espera cada endpoint y sus restricciones (Entero, Email, UUID).
    """


    MAX_CONTEXT_SIZE = 10000 

    def __init__(self):
        self.grammar_context: Dict[str, Any] = {}
        self.markov = MarkovPredictor()
        self._cache: Dict[str, Any] = {}

    def learn_exploit(self, endpoint: str, payload: str, vuln_type: str):
        """
        Memoria Estrategica: Almacena un exploit exitoso para uso futuro.
        """
        if "known_exploits" not in self.grammar_context:
            self.grammar_context["known_exploits"] = {}
        
        if endpoint not in self.grammar_context["known_exploits"]:
             self.grammar_context["known_exploits"][endpoint] = []

        exploit_entry = {"type": vuln_type, "payload": payload}
        if exploit_entry not in self.grammar_context["known_exploits"][endpoint]:
            self.grammar_context["known_exploits"][endpoint].append(exploit_entry)
            logger.info(f"[M1] Nuevo exploit aprendido para {endpoint}: {payload}")

    def load_context(self, filepath: str):
        """Carga un contexto previamente aprendido desde un archivo JSON."""
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    self.grammar_context = json.load(f)
                logger.info(f"[M1] Contexto cargado desde {filepath}")
            except Exception as e:
                logger.error(f"Error cargando contexto M1: {e}")

    def save_context(self, filepath: str):
        """Guarda el mapa gramatical aprendido en disco."""
        try:
            def json_default(obj):
                if isinstance(obj, set): return list(obj)
                return str(obj)

            with open(filepath, 'w') as f:
                json.dump(self.grammar_context, f, indent=4, default=json_default)
            logger.info(f"[M1] Contexto guardado en {filepath}")
        except Exception as e:
            logger.error(f"Error guardando contexto M1: {e}")

    def merge_context(self, saved_context: Dict[str, Any]):
        """
        [v4.0.0 Memoria Persistente] Une gramática guardada con la actual.
        La gramática actual tiene preferencia si hay conflicto, pero se combinan 
        los parámetros conocidos.
        """
        for key, val in saved_context.items():
            if key == "known_exploits": continue
            if key not in self.grammar_context:
                self.grammar_context[key] = val
            else:

                saved_params = val.get("seen_params", {})
                current_params = self.grammar_context[key].get("seen_params", {})
                
                for param, data in saved_params.items():
                    if param not in current_params:
                        current_params[param] = data
                
                self.grammar_context[key]["seen_params"] = current_params

    def learn_from_traffic(self, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analiza trafico HTTP pasivo para aprender la estructura de la aplicacion.
        """
        if not isinstance(traffic_data, dict):
            return self.grammar_context
            
        path = traffic_data.get("path")
        params = traffic_data.get("params", {})

        if not isinstance(path, str) or not path:
            return self.grammar_context
            

        self.markov.learn_path(path)

        if not isinstance(params, dict):
            return self.grammar_context


        is_graph = ("graphql" in path.lower() or
                    bool(params.keys() & _GRAPHQL_PARAMS))


        if len(self.grammar_context) > self.MAX_CONTEXT_SIZE:
             return self.grammar_context


        dedup_key = path
        if params:
            sorted_keys = sorted(params.keys())
            param_sig = ",".join(sorted_keys)
            dedup_key = f"{path}[{param_sig}]"

        if dedup_key not in self.grammar_context:
             self.grammar_context[dedup_key] = {
                 "path": path,
                 "seen_params": {},
                 "methods": set(),
                 "is_graph": is_graph
             }
        else:

            if "methods" not in self.grammar_context[dedup_key]:
                self.grammar_context[dedup_key]["methods"] = set()
            if is_graph:
                self.grammar_context[dedup_key]["is_graph"] = True

        for param_name, param_value in params.items():

            if not isinstance(param_name, str) or len(param_name) > 256:
                continue
            

            self._update_param_context(dedup_key, param_name, param_value)
            

        req_method = traffic_data.get("method", "GET").upper()
        if req_method:
             self.grammar_context[dedup_key]["methods"].add(req_method)

        return self.grammar_context
    
    def learn_from_url(self, url: str):
        """
        Metodo auxiliar para aprender solo de una URL (sin parametros POST).
        Util para el output del Crawler M7.
        """


        pass

    def classify_endpoint_type(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        """
        [v4.0.0] Clasifica el tipo semantico de un endpoint para que M2 priorice payloads:

        Etiquetas posibles:
            auth          - Endpoints de autenticacion (/login, /token, /signup)
            admin         - Panel administrativo (/admin, /dashboard, /manage)
            data-write    - Escritura de datos (POST/PUT/PATCH con body)
            data-read     - Lectura de datos con ID de objeto (IDOR candidato)
            search        - Endpoints de busqueda con q= / search= / query=
            graphql       - Endpoint GraphQL
            webhook       - Webhook externo (/webhook, /callback, /notify)
            file          - Descarga/subida de archivos (/upload, /download, /export)
            health        - Endpoints de salud/debug (/health, /metrics, /ping)
            generic       - Sin clasificacion especifica

        Args:
            path:   Ruta del endpoint (ej: /api/v1/users/123)
            params: Diccionario de parametros conocidos (opcional, de M1 grammar_context)

        Returns:
            String con la etiqueta del tipo.
        """
        path_lower = path.lower() if path else ""
        params     = params or {}

        parts = set(p for p in path_lower.strip("/").split("/") if p)


        for label, keywords in _ENDPOINT_TYPE_MAP:
            if parts & keywords:
                return label


        if any(p.lower() in _SEARCH_PARAMS for p in params):
            return "search"


        segments = [p for p in path_lower.strip("/").split("/") if p]
        for seg in segments:
            if seg.isdigit():
                return "data-read"
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}', seg, re.IGNORECASE):
                return "data-read"


        id_params = {"id", "user_id", "userId", "account_id", "accountId", "uuid", "guid"}
        if any(k in id_params for k in params):
            return "data-read"


        if params:
            return "data-write"

        return "generic"

    def _update_param_context(self, path: str, param_name: str, param_value: Any):
        """
        Actualiza la inferencia de tipos para un parametro especifico.
        """

        cache_key = f"{path}|{param_name}"
        if self._cache.get(cache_key) == param_value:
            return
        self._cache[cache_key] = param_value

        param_context = self.grammar_context[path]["seen_params"].setdefault(param_name, {})
        param_context.setdefault("inconsistencies", [])
        
        inferred_type = self._infer_type(param_value)
        

        if "type" in param_context and param_context["type"] != inferred_type:
             if inferred_type not in param_context["inconsistencies"]:
                 if len(param_context["inconsistencies"]) < 10:
                     param_context["inconsistencies"].append(inferred_type)
             return
        
        param_context["type"] = inferred_type


        if inferred_type in _NUMERIC_TYPES:
            self._update_numeric_constraints(param_context, param_value)
        elif inferred_type == "string":
            self._update_string_constraints(param_context, param_value)
            param_context["subtype"] = self._infer_subtype(param_value)

    def _infer_type(self, value: Any) -> str:
        """Infiere el tipo de dato primitivo de un valor."""

        for python_type, label in _TYPE_DISPATCH:
            if isinstance(value, python_type):
                return label
        if isinstance(value, list):
            return f"list_of_{self._infer_type(value[0])}" if value else "list"
        return "unknown"

    def _infer_subtype(self, value: str) -> str:
        """
        Iniferencias semanticas avanzadas (Email, UUID, Fecha).
        """

        if re.match(r"[^@]+@[^@]+\.[^@]+", value):
            return "email"

        if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", value, re.IGNORECASE):
            return "uuid"

        if re.match(r"^\d{4}-\d{2}-\d{2}$", value):
            return "date"

        if value.isalnum():
            return "alphanumeric"
        return "text"

    def _update_numeric_constraints(self, context: Dict[str, Any], value: Union[int, float]):
        """
        Actualiza min/max para valores numericos.
        """
        if "range" not in context:
            context["range"] = [value, value]
        else:
            current_min, current_max = context["range"]
            context["range"] = [min(current_min, value), max(current_max, value)]
        
        if "constraints" not in context:
            context["constraints"] = []
        

        constraints = []
        if context["range"][0] >= 0:
            constraints.append("non_negative")
        context["constraints"] = constraints

    def _update_string_constraints(self, context: Dict[str, Any], value: str):
        """
        Actualiza longitud maxima para strings.
        """
        current_len = len(value)
        if "max_length" not in context:
            context["max_length"] = current_len
        else:
            context["max_length"] = max(context["max_length"], current_len)

class TechFingerprinter:
    """
    [Roadmap v4.0.0] Modulo de Deteccion de Tecnologias.
    Analiza headers y cookies para determinar el stack tecnologico.
    Carga patrones desde models/tech_signatures.json
    """
    
    PATTERNS: Dict[str, Any] = {}

    @staticmethod
    def _load_patterns():
        if TechFingerprinter.PATTERNS: return
        
        try:
            json_path = os.path.join(settings.MODELS_DIR, "tech_signatures.json")
            if os.path.exists(json_path):
                with open(json_path, 'r') as f:
                    TechFingerprinter.PATTERNS = json.load(f)
            else:
                print(f"[-] Warn: {json_path} no encontrado.")
        except Exception as e:
            print(f"[-] Error cargando tech_signatures: {e}")

    @staticmethod
    def identify(headers: Dict[str, str], cookies: Optional[Dict[str, str]] = None) -> List[str]:
        TechFingerprinter._load_patterns()
        
        detected_techs = set()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        

        for tech, patterns in TechFingerprinter.PATTERNS.items():
            if "headers" in patterns:
                for h_name, h_regex in patterns["headers"].items():
                    h_str = str(h_name)
                    h_val = headers_lower.get(h_str)
                    if h_val is not None:
                        if re.search(str(h_regex), h_val):
                            detected_techs.add(tech)
        

        if cookies is not None:
            cookie_names = list(cookies.keys())  # pyre-ignore
        else:
            set_cookie = headers_lower.get("set-cookie", "")
            cookie_names = [x.split("=")[0].strip() for x in set_cookie.split(";")]

        for tech, patterns in TechFingerprinter.PATTERNS.items():
            if "cookies" in patterns:
                for c_regex in patterns["cookies"]:
                    for c_name in cookie_names:
                        if re.search(c_regex, c_name, re.IGNORECASE):
                            detected_techs.add(tech)


        server = headers_lower.get("server", "")
        if "nginx" in server: detected_techs.add("nginx")
        elif "apache" in server: detected_techs.add("apache")
        elif "cloudflare" in server: detected_techs.add("cloudflare")

        return list(detected_techs)
