"""
VAA — Fase 5.6: BOLA Harvest Attack (OWASP API1 — Encadenamiento).

Estrategia:
  Usa IDs/GUIDs cosechados durante el fuzzing (_harvest) e intenta accederlos
  con el token del ATACANTE en endpoints de lectura que tengan path params.

  Diferencia clave vs M6:
    - M6 busca objetos del ATACANTE accesibles por la VÍCTIMA (cross-session IDOR).
    - Este módulo busca objetos de OTRO USUARIO accesibles SIN autorización real.

  Confirmación:
    - Jaccard similarity < BOLA_THRESHOLD entre baseline atacante y respuesta harvest.
    - Umbral: 0.70 (ver similarity.py).
"""
import re
from typing import Any, Dict, List

from app.utils.logger import logger  # pyre-ignore[21]
from app.core.engine.algorithms.similarity import (
        normalize_dynamic_fields,
    BOLA_THRESHOLD,
)
from app.core.engine.models import VulnerabilityFinding, EndpointTarget
from app.core.m_uuid_oracle import UUIDOracle


# Detecta tanto {placeholder} como /uuid-xxxx y /123 (IDs ya resueltos)
_PARAM_PATTERN = re.compile(r'\{[^}]+\}')
_UUID_IN_URL   = re.compile(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$)', re.IGNORECASE)
_INT_IN_URL    = re.compile(r'/(\d+)(?=/|$)')


def _extract_all_ids(harvest: Dict[str, List[str]]) -> List[str]:
    """UUIDs primero — son el caso mayoritario en APIs modernas."""
    return (
        harvest.get("uuids", [])[:30]
        + harvest.get("vehicle_ids", [])[:5]
        + harvest.get("order_ids", [])[:5]
        + harvest.get("numeric_ids", [])[:5]
    )


def _detect_url_id_type(url: str):
    """
    Detecta si la URL ya tiene un ID resuelto (UUID o numérico).
    Retorna (id_str, is_numeric, replace_pattern).
    Si no tiene ID resuelto, retorna (None, None, None).
    """
    # Primero intenta UUID
    m = _UUID_IN_URL.search(url)
    if m:
        return m.group(1), False, _UUID_IN_URL

    # Luego intenta entero
    m = _INT_IN_URL.search(url)
    if m:
        return m.group(1), True, _INT_IN_URL

    return None, None, None


async def run(
    endpoints: List[EndpointTarget],
    network_manager: Any,
    options: Dict[str, Any],
    harvest: Dict[str, List[str]],
    m3_calculate_similarity,
    record_finding,
) -> int:
    """
    Ejecuta BOLA Harvest Attack usando IDs cosechados del fuzzing.

    Args:
        endpoints:               Manifiesto de endpoints.
        network_manager:         NetworkManager del orquestador.
        options:                 options{} del scan.
        harvest:                 Dict con listas de IDs cosechados (_harvest).
        m3_calculate_similarity: Función  de M3 (Jaccard).
        record_finding:          Coroutine para registrar hallazgos.

    Returns:
        Número de BOLA confirmados.
    """
    logger.info("\n=== [v4.0.0] FASE 5.6: BOLA HARVEST ATTACK (API1 — ENCADENAMIENTO) ===")

    auth_token = options.get("auth_token", "")
    headers = {"Authorization": auth_token if " " in auth_token else f"Bearer {auth_token}"} if auth_token else {}

    read_eps = [
        ep for ep in endpoints
        if ep.get("method", "GET").upper() == "GET"
    ]
    logger.info(f"[BOLA-Harvest] {len(read_eps)} endpoints GET candidatos")

    confirmed = 0

    for ep in read_eps[:20]:
        base_url = ep.get("url") or ep.get("path", "")
        if not base_url:
            continue

        # Detectar el ID real que ya está en la URL (resuelto por el parser)
        attacker_id_str, is_numeric, replace_pattern = _detect_url_id_type(base_url)

        if attacker_id_str is None:
            # Si la URL aún tiene placeholder {param}, intentar con ambos pools
            if not _PARAM_PATTERN.search(base_url):
                continue
            # URL no resuelta — no podemos hacer baseline semántico, saltar
            logger.debug(f"[BOLA-Harvest] URL con placeholder sin resolver: {base_url}")
            continue

        # Seleccionar IDs del mismo tipo para probar
        if is_numeric:
            valid_ids = [i for i in harvest.get("numeric_ids", []) if str(i) != attacker_id_str]
        else:
            valid_ids = [i for i in harvest.get("uuids", []) if str(i).lower() != attacker_id_str.lower()]
            
            # Integración de UUIDOracle para predecir/fuzzear UUIDs si la piscina es chica
            if len(valid_ids) < 10 and harvest.get("uuids"):
                oracle = UUIDOracle(harvest.get("uuids", []))
                analysis = oracle.analyze()
                if analysis.get("is_predictable") and analysis.get("candidates"):
                    logger.info(f"[BOLA-Harvest] UUIDOracle predijo {len(analysis['candidates'])} UUIDs adicionales basados en la máscara {analysis.get('mask')}")
                    valid_ids.extend([c for c in analysis["candidates"] if c.lower() != attacker_id_str.lower()])

        if not valid_ids:
            logger.debug(f"[BOLA-Harvest] Sin IDs cosechados del tipo correcto para {base_url}")
            continue

        # Obtener baseline del atacante (su propia URL)
        attacker_baseline_norm: str = ""
        try:
            bl_resp = await network_manager.send_request_raw(
                base_url, headers=headers, timeout=8.0
            )
            if bl_resp and bl_resp.status_code == 200:
                try:
                    bl_text = bl_resp.text
                except Exception:
                    bl_text = bl_resp.content.decode("latin-1", errors="ignore") if hasattr(bl_resp, "content") else ""
                attacker_baseline_norm = normalize_dynamic_fields(bl_text)
        except Exception as err:
            logger.debug(f"[BOLA-Harvest] Error en baseline: {err}")

        logger.info(f"[BOLA-Harvest] Probando {len(valid_ids[:30])} IDs en {base_url}")

        for harvested_id in valid_ids[:30]:
            # Reemplazar el ID del atacante por el ID cosechado
            tested_url = replace_pattern.sub(
                lambda m: m.group(0).replace(attacker_id_str, str(harvested_id)),
                base_url,
                count=1
            )
            if tested_url == base_url:
                continue

            try:
                resp = await network_manager.send_request_raw(
                    tested_url, headers=headers, timeout=8.0
                )
            except Exception as exc:
                logger.debug(f"[BOLA-Harvest] Error: {exc}")
                continue

            if resp is None:
                continue

            try:
                r_text = resp.text
            except Exception:
                r_text = resp.content.decode("latin-1", errors="ignore") if hasattr(resp, "content") else ""

            if not (resp.status_code == 200 and len(r_text) > 50):
                continue

            if attacker_baseline_norm:
                norm_resp = normalize_dynamic_fields(r_text)
                sim = m3_calculate_similarity(attacker_baseline_norm, norm_resp)
                has_data = sim < BOLA_THRESHOLD
            else:
                has_data = any(
                    k in r_text for k in ['"email"', '"id"', '"vehicleId"', '"name"', '"secret"']
                )

            if has_data:
                logger.warning(
                    f"[BOLA-Harvest] 🚨 BOLA CONFIRMADO: {tested_url} "
                    f"devuelve datos con ID cosechado '{harvested_id}'"
                )
                finding: VulnerabilityFinding = {  # type: ignore[assignment]
                    "url":               tested_url,
                    "norm_url":          base_url,
                    "type":              "BOLA (Broken Object Level Authorization)",
                    "method":            "GET",
                    "payload":           str(harvested_id),
                    "risk":              "Critical",
                    "confidence":        1.0,
                    "verified":          True,
                    "validation_method": "bola_harvest_chaining",
                    "response_text":     r_text[:500],
                    "evidence_data": (
                        f"ID cosechado '{harvested_id}' accede a datos de otro usuario"
                    ),
                    "params": {"id": str(harvested_id)},
                    "is_json": False,
                    "report_policy": "local",
                }
                await record_finding(finding)
                confirmed += 1
                break

    logger.info(f"[BOLA-Harvest] {confirmed} BOLA(s) confirmado(s) por encadenamiento")
    return confirmed
