"""
VAA — Algoritmo de Entropía de Shannon (1948) — The Oracle.


Umbral de agotamiento: H < 0.05 (ver EXHAUSTION_THRESHOLD).
Ventana deslizante: últimas N respuestas (SLIDING_WINDOW).
"""
import math
from typing import Dict, List, Tuple


EXHAUSTION_THRESHOLD = 0.05
SLIDING_WINDOW       = 10
MIN_SAMPLES_REMOTE   = 20
MIN_SAMPLES_LOCAL    = 50


def calculate_entropy(data: List[str]) -> float:
   
    if len(data) < 5:
        return 1.0  

    frequency: Dict[str, int] = {}
    for item in data:
        frequency[item] = frequency.get(item, 0) + 1

    entropy = 0.0
    total = len(data)
    for count in frequency.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def build_response_signature(status_code: int, content_length: int) -> str:

    if content_length < 100:
        bucket = "xs"
    elif content_length < 500:
        bucket = "sm"
    elif content_length < 2000:
        bucket = "md"
    else:
        bucket = "lg"
    return f"{status_code}_{bucket}"


class ShannonOracle:

    def __init__(self) -> None:
        self._state:     Dict[str, List[str]] = {}
        self._exhausted: Dict[str, bool]      = {}
        self._counts:    Dict[str, int]        = {}  

    def make_key(self, url: str, vuln_type: str, param: str) -> str:
        return f"{url}|{vuln_type}|{param}"

    def is_exhausted(self, key: str) -> bool:
        return self._exhausted.get(key, False)

    def reset(self, key: str) -> None:
        self._exhausted[key] = False
        self._counts[key]    = 0

    def record(self, key: str, status_code: int, content_length: int, is_local: bool = False) -> Tuple[bool, bool]:
       
        sig = build_response_signature(status_code, content_length)

        if key not in self._state:
            self._state[key] = []
            self._counts[key] = 0
        window = self._state[key]
        prev_sig = window[-1] if window else None

        window.append(sig)
        if len(window) > SLIDING_WINDOW:
            window.pop(0)
        self._counts[key] += 1

        state_changed = (prev_sig is not None) and (sig != prev_sig)

        recent_statuses = [int(s.split("_")[0]) for s in window]
        auth_only = all(s in (401, 403) for s in recent_statuses)
        if auth_only:
            return state_changed, False

        min_samples = MIN_SAMPLES_LOCAL if is_local else MIN_SAMPLES_REMOTE
        newly_exhausted = False
        if self._counts[key] >= min_samples and len(window) >= min(SLIDING_WINDOW, 5):
            h = calculate_entropy(window)
            if h < EXHAUSTION_THRESHOLD and not self._exhausted.get(key, False):
                self._exhausted[key] = True
                newly_exhausted = True

        return state_changed, newly_exhausted

    def detect_bypass(self, key: str) -> bool:
        window = self._state.get(key, [])
        if len(window) < 2:
            return False
        prev_status = int(window[-2].split("_")[0])
        last_status = int(window[-1].split("_")[0])
        return prev_status in (401, 403) and last_status == 200
