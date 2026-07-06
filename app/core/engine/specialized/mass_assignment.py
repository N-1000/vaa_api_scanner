"""
VAA — Fase 5.5: Mass Assignment Activo (OWASP API3).

Estrategia:
  Para cada endpoint POST/PUT/PATCH del manifiesto, inyectar campos extra
  (role, isAdmin, balance, etc.) y verificar si:
    1. El campo aparece en la respuesta inmediata (reflection) → trivial
    2. El campo persiste en un GET posterior → confirmed write

  Utiliza asyncio.gather con semáforo para paralelismo controlado.
"""
import asyncio
import json
from typing import Any, Dict, List, Optional

from app.utils.logger import logger  # pyre-ignore[21]
from app.core.engine.models import VulnerabilityFinding, EndpointTarget


EXTRA_FIELDS: List[Dict[str, Any]] = [
    {"isAdmin": True}, {"role": "admin"}, {"status": "delivered"},
    {"balance": 999999}, {"credit": 999999}, {"admin": True},
    {"conversion_params": "| id"}, {"is_verified": True},
    {"quantity": -1}, {"available_credit": 999},
]


async def run(
    endpoints: List[EndpointTarget],
    network_manager: Any,
    options: Dict[str, Any],
    sem: asyncio.Semaphore,
    record_finding,
) -> int:
    """
    Ejecuta Mass Assignment activo contra todos los endpoints POST/PUT/PATCH.

    Args:
        endpoints:       Lista de endpoints del manifiesto.
        network_manager: NetworkManager del orquestador.
        options:         options{} del scan (auth_token, etc.).
        sem:             Semáforo global de concurrencia.
        record_finding:  Coroutine del orquestador para registrar hallazgos.

    Returns:
        Número de hallazgos confirmados.
    """
    logger.info("\n=== [v4.0.0] FASE 5.5: MASS ASSIGNMENT ACTIVO (API3) ===")

    auth_token = options.get("auth_token", "")
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}

    post_put_eps = [
        ep for ep in endpoints
        if ep.get("method", "GET").upper() in ("POST", "PUT", "PATCH")
    ]
    logger.info(f"[MA] {len(post_put_eps)} endpoints POST/PUT/PATCH a probar")

    found = 0

    async def _test_field(ep: EndpointTarget, url: str, method: str, extra_field: Dict) -> Optional[Dict]:
        field_name  = list(extra_field.keys())[0]
        field_value = list(extra_field.values())[0]
        body = {**ep.get("body_schema", {}).get("example", {}), **extra_field}  # type: ignore[arg-type]

        resp = None


        schema_extra = ep.get("body_schema", {})
        schema_example = schema_extra.get("example", {}) if isinstance(schema_extra, dict) else {}
        body_from_schema = {**schema_example, **extra_field}

        _candidate_bodies = [extra_field]
        if body_from_schema != extra_field:
            _candidate_bodies.append(body_from_schema)
        _candidate_bodies += [
            {"name": "test", **extra_field},
        ]

        auth_token_b = options.get("auth_token_b") or options.get("auth_b_token", "")

        _base_headers = {**headers, "Content-Type": "application/json"}
        _token_headers_list = [_base_headers]
        if auth_token_b:
            _token_headers_list.append({
                "Authorization": f"Bearer {auth_token_b}",
                "Content-Type": "application/json"
            })

        try:
            async with sem:
                for _hdrs in _token_headers_list:
                    for body in _candidate_bodies:
                        resp = await network_manager.send_request_raw(
                            url, method=method, headers=_hdrs, payload=body, json_body=True
                        )
                        if resp and resp.status_code not in (400, 422, 401, 403):
                            break
                    if resp and resp.status_code not in (400, 422, 401, 403):
                        break
                if not resp:
                    return None
        except Exception as exc:
            logger.debug(f"[MA] Error en {method} {url}: {exc}")
            return None

        if not resp or resp.status_code in (400, 401, 403, 404, 405, 422, 500):
            return None

        resp_text = resp.text
        logger.debug(f"[MA-Debug] {method} {url} field={field_name}={field_value!r} status={resp.status_code} body={resp_text[:120]}")


        field_val_str   = str(field_value).lower()
        field_val_json  = json.dumps(field_value).lower()


        val_in_response = (
            field_val_str in resp_text.lower()
            or field_val_json in resp_text.lower()
        )
        reflected = (
            val_in_response
            and (
                field_name in resp_text
                or "applied_fields" in resp_text
            )
        )


        persisted = False
        if resp.status_code in (200, 201):
            try:
                parsed = json.loads(resp_text)
                resource_id = (
                    parsed.get("id") or parsed.get("_id")
                    or parsed.get("vehicleId") or parsed.get("orderId")
                )
                if resource_id:
                    get_url = f"{url.rstrip('/')}/{resource_id}"
                    get_resp = await network_manager.send_request_raw(
                        get_url, headers=headers, timeout=8.0
                    )
                    if get_resp and get_resp.status_code == 200:
                        persisted = (
                            field_name in get_resp.text
                            and str(field_value) in get_resp.text
                        )
            except Exception:
                pass

        if not (reflected or persisted):
            return None

        mechanism = "persistence_via_get" if persisted else "reflection_in_response"
        finding: VulnerabilityFinding = {  # type: ignore[assignment]
            "url":               url,
            "norm_url":          url,
            "type":              "MASS_ASSIGNMENT",
            "method":            method,
            "payload":           json.dumps(extra_field),
            "risk":              "High",
            "confidence":        1.0 if persisted else 0.85,
            "verified":          True,
            "validation_method": mechanism,
            "response_text":     resp_text[:500],
            "evidence_data": (
                f"Campo '{field_name}' aceptado con valor '{field_value}' — "
                f"{'persistio en GET posterior' if persisted else 'reflejado en respuesta inmediata'}"
            ),
        }
        return finding

    for ep in post_put_eps:
        url = ep.get("url", "")
        if not url:
            continue
        method = ep.get("method", "POST").upper()

        tasks = [_test_field(ep, url, method, f) for f in EXTRA_FIELDS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, dict):
                logger.warning(
                    f"[MA]  MASS ASSIGNMENT confirmado en {method} {url}"
                )
                await record_finding(res)
                found += 1
                break

    logger.info(f"[MA] {found} hallazgo(s) Mass Assignment confirmado(s).")
    return found
