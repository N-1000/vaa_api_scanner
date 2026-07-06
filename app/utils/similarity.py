
"""
VAA Utility: Similarity Algorithms.
Optimized for high-speed response comparison.
"""

import re
import hashlib

class SimHash:
    """
    Algoritmo de Hashing de Similitud (LSH ligero).
    Permite detectar si dos respuestas son casi identicas ignorando pequenos cambios (timestamps, IDs).
    """

    @staticmethod
    def get_hash(text: str, hash_bits: int = 64) -> int:
        """Calcula el SimHash de un texto."""
        if not text:
            return 0


        tokens = re.findall(r'\w+', text.lower())
        if not tokens:
            return 0


        v = [0] * hash_bits
        for token in tokens:

            t_hash = int(hashlib.md5(token.encode('utf-8')).hexdigest(), 16)
            for i in range(hash_bits):
                bit = (t_hash >> i) & 1
                if bit:
                    v[i] += 1
                else:
                    v[i] -= 1


        fingerprint = 0
        for i in range(hash_bits):
            if v[i] > 0:
                fingerprint |= (1 << i)

        return fingerprint

    @staticmethod
    def calculate_similarity(hash1: int, hash2: int, hash_bits: int = 64) -> float:
        """Calcula el porcentaje de similitud basado en la Distancia de Hamming."""
        x = hash1 ^ hash2
        hamming_distance = bin(x).count('1')
        return 1.0 - (hamming_distance / hash_bits)


