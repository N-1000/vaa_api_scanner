
"""
Modulo M12: Vesta (Velocity & Stability).
Optimizador heuristico para escaneos de gran escala.

Algoritmos:
1. Cluster-based Deduplication: Agrupa endpoints por firma estructural (M1).
2. Priority Scoring: Pesos por keywords y profundidad de ruta.
3. Adaptive Payload Scaling: Ajusta la intensidad del fuzzing.
"""

from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from app.utils.logger import logger  # pyre-ignore[21]
from app.utils.similarity import SimHash  # pyre-ignore[21]

class M12Vesta:
    """
    Controlador de optimizacion de velocidad.
    Actua como un filtro inteligente entre el Recon y el Fuzzing.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):


        if config is None:
            config = {}
        self.config = config
        self.deduplication_level = config.get("deduplication_level", 1)
        self.max_per_cluster = config.get("max_per_cluster", 3)
        

        self.high_priority_keywords = [
            "auth", "login", "admin", "payment", "pvt", "secret", "config", 
            "root", "internal", "vault", "checkout", "user", "order", "ai", "graphql"
        ]
        

        self.low_priority_keywords = [
            "static", "assets", "img", "css", "js", "docs", "manual", "help", "v1/public"
        ]

    def optimize_scan_manifest(self, endpoints: List[Dict[str, Any]], grammar_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Toma una lista bruta de endpoints y devuelve una version optimizada y priorizada.
        """
        if not endpoints:
            return []

        logger.info(f"[M12] Iniciando optimizacion sobre {len(endpoints)} endpoints iniciales...")


        optimized_list = self._deduplicate(endpoints, grammar_context)
        

        for ep in optimized_list:
            ep["priority_score"] = self._calculate_priority(ep)
            

        optimized_list.sort(key=lambda x: x["priority_score"], reverse=True)

        logger.info(f"[M12] Optimizacion completada. Manifest reducido a {len(optimized_list)} targets.")
        return optimized_list

    def _deduplicate(self, endpoints: List[Dict[str, Any]], grammar_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Agrupa endpoints que comparten la misma estructura gramatical.
        """


        if not endpoints:
            return []
        

        is_local = any(x in str(endpoints[0].get("url", "")) for x in ["localhost", "127.0.0.1", "::1"])
        if self.deduplication_level == 0 or is_local:
            return endpoints

        clusters: Dict[str, List[Dict]] = {}
        
        for ep in endpoints:
            path = ep.get("path", urlparse(ep["url"]).path)


            cluster_key = self._get_structural_signature(path, ep.get("method", "GET"), grammar_context)
            
            if cluster_key not in clusters:
                clusters[cluster_key] = []
            

            if len(clusters[cluster_key]) < self.max_per_cluster:
                clusters[cluster_key].append(ep)


        result = []
        for key in clusters:
            result.extend(clusters[key])
            
        return result

    def get_fuzzy_cluster_key(self, response_text: str) -> str:
        """
        Genera una firma difusa utilizando SimHash para agrupar respuestas similares.
        """
        if not response_text:
            return "empty"
        h = SimHash.get_hash(response_text)

        return f"simhash:{h & 0xFFFF000000000000}"

    def _get_structural_signature(self, path: str, method: str, grammar_context: Dict[str, Any]) -> str:
        """
        Genera una firma unica basada en la forma de la ruta y los parametros vistos.
        [DEUDA TECNICA] Esta logica de normalizacion de path ({ID}, {UUID}) esta duplicada
        en M6 (get_structural_signature) y M74P1 (_sniff_format).
        Candidato para extraer a app/utils/path_utils.py como funcion compartida.
        Si se anade soporte a NanoIDs u otros formatos, actualizar los 3 sitios.
        """

        from app.utils.helpers import normalize_path_structure  # pyre-ignore[21]
        sig = normalize_path_structure(path)
        

        param_sig = ""


        for key in grammar_context:
            if key.startswith(path) and "[" in key:
                param_sig = key[key.find("["):]  # pyre-ignore[16]
                break
                
        return f"{method}:{sig}{param_sig}"

    def _calculate_priority(self, ep: Dict[str, Any]) -> float:
        """
        Heuristica de puntuacion:
        - Base: 1.0
        - Keywords de riesgo: +2.0 cada una.
        - Keywords de baja prioridad: -1.0.
        - Profundidad: -0.1 por cada nivel de subdirectorio (los niveles profundos suelen ser mas especificos).
        """
        score: float = 10.0
        url_low = ep["url"].lower()
        
        for kw in self.high_priority_keywords:
            if kw in url_low:
                score += 5.0  # pyre-ignore[16,58]
                
        for kw in self.low_priority_keywords:
            if kw in url_low:
                score -= 4.0  # pyre-ignore[16,58]


        depth = url_low.count("/")
        score -= (depth * 0.5)  # pyre-ignore[16,58]


        if ep.get("params") or ep.get("body_schema"):
            score += 3.0

        return score

    def get_shannon_adjustment(self, entropy: float) -> int:
        """
        Decide cuantos payloads mas enviar segun la entropia.
        Retorna un multiplicador o limite de ejecucion.
        """
        if entropy < 0.2: return 0
        if entropy < 0.5: return 5
        return 20
