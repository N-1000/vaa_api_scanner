"""
VAA — Algoritmo de Similitud de Respuestas HTTP (1912 Jaccard).

Umbrales calibrados (NO modificar sin actualizar test_algorithms.py):
  - similarity < 0.75  → Candidato a SQLi  (differential_jaccard)
  - similarity < 0.70  → Señal fuerte de BOLA / datos de otro usuario
"""
import re

def calculate_similarity(text_a: str, text_b: str) -> float:
    tokens_a = set(re.split(r'\W+', text_a.lower()))
    tokens_b = set(re.split(r'\W+', text_b.lower()))
    union = tokens_a | tokens_b
    if not union:
        return 1.0
    return len(tokens_a & tokens_b) / len(union)

def normalize_dynamic_fields(text: str) -> str:


    text = re.sub(
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'UUID', text
    )

    text = re.sub(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?',
        'TIMESTAMP', text
    )

    text = re.sub(r'\b1[0-9]{9,12}\b', 'EPOCH', text)


    dynamic_keys = (
        "updated_at|created_at|last_seen|last_modified|request_id|"
        "session|session_id|token|access_token|refresh_token|nonce|etag"
    )
    text = re.sub(
        r'("(?:' + dynamic_keys + r')")\s*:\s*"[^"]*"',
        r'\1:"REDACTED"',
        text,
    )
    return text


SQLI_THRESHOLD = 0.75
BOLA_THRESHOLD = 0.70
