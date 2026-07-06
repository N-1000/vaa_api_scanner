"""
VAA Engine — Modelos de datos compartidos.

Contrato tipado para hallazgos y endpoints que viajan entre fases.
Elimina los dicts genéricos que causaban KeyError en runtime.
"""
from typing import Any, Dict, Optional
from typing_extensions import TypedDict, Required


class VulnerabilityFinding(TypedDict, total=False):
    """
    Contrato mínimo para un hallazgo de vulnerabilidad.
    Campos marcados como Required deben existir siempre.
    El resto son opcionales según la fase que los genera.
    """

    url:               Required[str]
    norm_url:          Required[str]
    type:              Required[str]
    method:            Required[str]
    payload:           Required[str]
    risk:              Required[str]
    confidence:        Required[float]
    verified:          Required[bool]
    validation_method: Required[str]


    status_code:        int
    response_text:      str
    params:             Dict[str, Any]
    is_json:            bool
    report_policy:      str
    evidence_data:      str
    similarity_score:   float
    ai_razonamiento:    str
    ai_remediacion:     str
    ai_tipo_confirmado: str
    ai_nota:            str
    _degraded:          bool


class EndpointTarget(TypedDict, total=False):
    """
    Contrato tipado para un endpoint del manifiesto de ataque.
    Producido por M74P1 Navigator y consumido por el Fuzzer y fases lógicas.
    """
    url:         Required[str]
    method:      Required[str]
    path:        str
    params:      Dict[str, Any]
    body_schema: Optional[Dict]
    headers:     Dict[str, str]
    source:      str
