"""
UUID Oracle: Statistical analysis of harvested UUIDs to find predictable segments and generate fuzzing masks.
"""

import re
import math
from typing import List, Dict, Any

class UUIDOracle:
    """
    Analiza una lista de UUIDs cosechados (harvested) para encontrar entropía baja
    y predecir/fuzzear nuevos identificadores validos.
    """
    
    def __init__(self, uuids: List[str]):
        self.raw_uuids = [u.strip().lower() for u in uuids if u.strip()]
        self.uuids = self._normalize_and_filter(self.raw_uuids)
        self.total = len(self.uuids)
        
    def _normalize_and_filter(self, uuids: List[str]) -> List[str]:
        """Asegura que todos tengan el formato correcto de 36 caracteres."""
        valid = []
        pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
        for u in uuids:
            if pattern.match(u):
                valid.append(u)
        return valid

    def analyze(self) -> Dict[str, Any]:
        """
        Ejecuta el analisis estadistico y retorna un reporte completo.
        """
        if self.total == 0:
            return {
                "status": "error",
                "message": "No hay UUIDs validos para analizar.",
                "total_analyzed": 0
            }
            
        version = self._detect_version()
        entropy_map = self._calculate_entropy()
        mask = self._generate_mask(entropy_map)
        
        return {
            "status": "success",
            "total_analyzed": self.total,
            "version_detected": version,
            "mask": mask,
            "entropy_analysis": entropy_map,
            "is_predictable": version in ["v1", "v7", "sequential_like"] or "?" not in mask,
            "candidates": self._generate_candidates(mask, limit=5)
        }

    def _detect_version(self) -> str:
        """
        Identifica la version predominante de los UUIDs.
        En el formato 8-4-4-4-12, la version esta en el indice 14.
        """
        versions = {}
        for u in self.uuids:
            v_char = u[14]
            versions[v_char] = versions.get(v_char, 0) + 1
            
        # Obtener la version mas comun
        if not versions:
            return "unknown"
            
        most_common = max(versions.items(), key=lambda x: x[1])[0]
        
        if most_common == '1':
            return "v1" # Time-based
        elif most_common == '4':
            return "v4" # Random
        elif most_common == '7':
            return "v7" # Unix epoch time
        else:
            # Check if it looks sequential (very low entropy in first segments)
            return "sequential_like" if self._looks_sequential() else f"v{most_common}"

    def _looks_sequential(self) -> bool:
        """Si los primeros caracteres son siempre los mismos o cambian muy poco."""
        if self.total < 2:
            return False
            
        prefixes = [u[:8] for u in self.uuids]
        unique_prefixes = len(set(prefixes))
        return unique_prefixes < self.total and unique_prefixes <= 3

    def _calculate_entropy(self) -> List[Dict[str, Any]]:
        """
        Calcula la entropia por posicion en el UUID.
        0 entropia = el caracter es igual en todos los UUIDs.
        """
        if self.total == 0:
            return []
            
        analysis = []
        for i in range(36):
            if i in [8, 13, 18, 23]: # Guiones
                analysis.append({"pos": i, "char": "-", "entropy": 0.0, "distinct": 1})
                continue
                
            chars_at_pos = [u[i] for u in self.uuids]
            counts = {}
            for c in chars_at_pos:
                counts[c] = counts.get(c, 0) + 1
                
            entropy = 0.0
            for count in counts.values():
                p = count / self.total
                entropy -= p * math.log2(p)
                
            analysis.append({
                "pos": i,
                "entropy": round(entropy, 2),
                "distinct": len(counts),
                "most_common": max(counts.items(), key=lambda x: x[1])[0] if counts else "?"
            })
            
        return analysis

    def _generate_mask(self, entropy_map: List[Dict[str, Any]]) -> str:
        """
        Genera una mascara donde '?' representa caracteres aleatorios
        y valores hexadecimales representan partes predecibles.
        """
        mask = ""
        for stat in entropy_map:
            if stat.get("char") == "-":
                mask += "-"
            elif stat["distinct"] == 1:
                # Si todos tienen el mismo caracter en esta posicion, es fijo
                mask += stat["most_common"]
            else:
                # Si cambia, lo marcamos para fuzzing
                mask += "?"
        return mask

    def _generate_candidates(self, mask: str, limit: int = 5) -> List[str]:
        """
        Genera ejemplos de UUIDs que encajan en la mascara.
        Si la mascara tiene pocas incognitas, genera permutaciones.
        Si tiene muchas, genera aleatorios validos para la mascara.
        """
        candidates = []
        unknowns_count = mask.count("?")
        
        if unknowns_count == 0:
            return [mask] if self.total > 0 else []
            
        # Si hay demasiadas incognitas y no es v1/v7, es dificil predecir exacto
        import random
        hex_chars = "0123456789abcdef"
        
        for _ in range(limit):
            candidate = ""
            for char in mask:
                if char == "?":
                    candidate += random.choice(hex_chars)
                else:
                    candidate += char
            candidates.append(candidate)
            
        return candidates

if __name__ == "__main__":
    # Test
    test_uuids = [
        "123e4567-e89b-12d3-a456-426614174000",
        "123e4567-e89b-12d3-a456-426614174001",
        "123e4567-e89b-12d3-a456-426614174002"
    ]
    oracle = UUIDOracle(test_uuids)
    print(oracle.analyze())
