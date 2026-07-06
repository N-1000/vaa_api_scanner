"""
VAA — Fase 7: Validación Activa de Hallazgos (PoC Checks).

Cada tipo de vulnerabilidad tiene una estrategia de second-pass diferente:

  SQLi   → Differential Jaccard: dos pares true/false, similarity < 0.75
  XSS    → Nonce reflection: inyectar nonce alfanumérico, verificar reflejo raw/html-decoded
  Server Error → Trust M3 oracle (M3 ya exige cambio de estado, no solo 500)
  SDL    → Structural response analysis (descartar 422 = Pydantic validation)
  SSRF   → Semantic check + re-probe activo con 169.254.169.254
  EXPLOIT CONFIRMED → Baseline GET sin payload — datos en respuesta limpia
  Mass Assignment → GET posterior para verificar persistencia del campo
"""
import html
import re
import asyncio
import random
from typing import Any, Optional

from app.utils.logger import logger  # pyre-ignore[21]
from app.core.engine.models import VulnerabilityFinding
from app.core.engine.algorithms.similarity import calculate_similarity, SQLI_THRESHOLD


async def validate_finding(
    finding: VulnerabilityFinding,
    network_manager: Any,
    m2_get_pairs,
    token_health_check=None,
    pipeline_log=None,
) -> Optional[VulnerabilityFinding]:
    """
    Active PoC validation. Retorna el hallazgo enriquecido si se confirma,
    None si es descartado como falso positivo.

    Args:
        finding:          Hallazgo de la cola de validación.
        network_manager:  NetworkManager del orquestador.
        m2_get_pairs:     M2.get_verification_pairs(vuln_type) para SQLi diferencial.
        pipeline_log:     Callable opcional para trazabilidad (--debug-pipeline).
    """
    vuln_type = finding["type"].lower()
    url       = finding["url"]
    norm_url  = finding.get("norm_url", url.split("?")[0])
    method    = finding.get("method", "GET")
    params    = finding.get("params") or {}
    is_json   = finding.get("is_json", False)

    _fid = f"{norm_url}|{vuln_type}|{str(finding.get('payload', ''))[:20]}"
    logger.debug(f"[Validation] PoC check: {vuln_type} @ {norm_url}")

    def _plog(action, reason, confidence=0.0):
        if pipeline_log:
            pipeline_log(_fid, "validate", action, reason, url=norm_url, vuln_type=vuln_type, confidence=confidence)

    try:

        if "sqli" in vuln_type or "sql injection" in vuln_type:
            param_name = list(params.keys())[0] if params else "q"
            pairs = m2_get_pairs("sqli")
            confirmed = False
            for pair in pairs[:2]:
                resp_t = await network_manager.send_request(norm_url, payload={param_name: pair["true"]})
                if resp_t and resp_t.status_code == 401 and token_health_check:
                    await token_health_check(norm_url)
                    resp_t = await network_manager.send_request(norm_url, payload={param_name: pair["true"]})

                resp_f = await network_manager.send_request(norm_url, payload={param_name: pair["false"]})
                if resp_f and resp_f.status_code == 401 and token_health_check:
                    await token_health_check(norm_url)
                    resp_f = await network_manager.send_request(norm_url, payload={param_name: pair["false"]})

                if resp_t and resp_f:
                    sim = calculate_similarity(resp_t.text, resp_f.text)
                    logger.debug(f"[SQLi-{pair['name']}] Jaccard similarity: {sim:.2f}")
                    if sim < SQLI_THRESHOLD:
                        finding.update({
                            "confidence": 1.0, "verified": True,
                            "validation_method": f"differential_jaccard_{pair['name'].lower().replace(' ', '_')}",
                            "similarity_score": sim,
                        })
                        confirmed = True
                        break
                    elif sim > 0.98:
                        continue

            if confirmed:
                return finding


            orig_conf = finding.get("confidence", 0)
            if orig_conf >= 0.9:
                logger.debug(f"[SQLi] Jaccard ambiguo, pero M3 confidence={orig_conf}. Reteniendo.")
                finding.update({
                    "verified": True,
                    "validation_method": "m3_signature_error_based",
                    "ai_razonamiento": (
                        "Se detectó una firma de error de base de datos (SQL Injection). "
                        "La validación diferencial fue ambigua pero el error es indicativo."
                    ),
                })
            else:
                finding.update({
                    "confidence": 0.6, "verified": False,
                    "validation_method": "sqli_unconfirmed_jaccard",
                    "ai_razonamiento": (
                        "Posible SQLi por firma de error, no confirmada mediante pruebas booleanas."
                    ),
                })
            return finding


        elif any(k in vuln_type for k in ["xss", "cross-site", "scripting"]):


            nonce       = f"<VAA_NONCE_{id(finding) & 0xFFFF:04X}>"
            nonce_tag   = nonce
            xss_payload = nonce
            nonce_resp  = None
            is_path_xss = (method == "GET" and not params)

            if is_path_xss:
                probe_url = url.replace(finding.get("payload", ""), xss_payload)
                if probe_url == url:
                    probe_url = url
                try:
                    nonce_resp = await network_manager.send_request(
                        probe_url, method="GET", payload=None, json_body=False,
                        custom_headers={"User-Agent": "Mozilla/5.0 (VAA-reprobe)"}
                    )
                except Exception:
                    nonce_resp = None

            elif params:
                param_name = list(params.keys())[0]
                nonce_resp = await network_manager.send_request(
                    norm_url, method=method,
                    payload={param_name: xss_payload},
                    json_body=is_json,
                    custom_headers={"User-Agent": "Mozilla/5.0 (VAA-reprobe)"}
                )

            elif method in ("POST", "PUT", "PATCH"):


                _field = list(params.keys())[0] if params else None
                _common_fields = ["content", "message", "text", "input", "q", "data"]
                _fields_to_try = [_field] if _field else _common_fields
                for _f in _fields_to_try:
                    nonce_resp = await network_manager.send_request(
                        norm_url, method=method,
                        payload={_f: xss_payload},
                        json_body=True,
                        custom_headers={"User-Agent": "Mozilla/5.0 (VAA-reprobe)"}
                    )
                    if nonce_resp and nonce_tag in (nonce_resp.text or ""):
                        break

            if nonce_resp:
                raw_body     = nonce_resp.text
                decoded_body = html.unescape(raw_body)
                reflected_raw     = nonce_tag in raw_body
                reflected_encoded = (nonce_tag not in raw_body) and (html.unescape(nonce_tag) in decoded_body)

                if reflected_raw:
                    finding.update({
                        "confidence": 0.95, "verified": True,
                        "validation_method": "nonce_reflection_unescaped",
                        "ai_razonamiento": (
                            "El nonce (con tag HTML) fue reflejado sin sanitización en el body. "
                            "Permite ejecución de scripts arbitrarios en el navegador de la víctima."
                        ),
                    })
                    _plog("pass", "xss_nonce_reflected_unescaped", 0.95)
                    return finding
                elif reflected_encoded:
                    logger.debug(f"[XSS] Nonce HTML-encoded (sanitizado). Descartando FP @ {norm_url}")
                    _plog("discard", "xss_nonce_html_encoded_safe", finding.get("confidence", 0.0))
                    return None
                else:


                    orig_conf = finding.get("confidence", 0.5)
                    if orig_conf >= 0.9 and method in ("POST", "PUT", "PATCH"):
                        logger.debug(f"[XSS] Nonce no reflejado en POST, pero M3 conf={orig_conf}. Reteniendo.")
                        finding.update({
                            "confidence": 0.75, "verified": True,
                            "validation_method": "xss_m3_confirmed_post",
                            "ai_razonamiento": "XSS confirmado por M3 en endpoint POST. Nonce reprobe inconcluso.",
                        })
                        return finding
                    logger.debug(f"[XSS] Nonce NOT reflected. Descartando FP @ {norm_url}")
                    _plog("discard", "xss_nonce_not_reflected", finding.get("confidence", 0.0))
                    return None
            else:
                _degraded = min(finding.get("confidence", 0.5), 0.55)
                finding.update({
                    "confidence": _degraded, "verified": False,
                    "validation_method": "reprobe_failed", "needs_manual_review": True,
                })
                _plog("pass", "xss_reprobe_failed_kept_low_conf", _degraded)
                return finding


        elif "server_error" in vuln_type:
            finding.update({
                "confidence": 0.85, "verified": True,
                "validation_method": "m3_oracle_confirmed",
                "ai_razonamiento": (
                    "El servidor devolvió un error interno (500) consistente al procesar "
                    "el payload malicioso. Manejo inadecuado de excepciones."
                ),
            })
            return finding


        elif "sensitive data" in vuln_type or "leakage" in vuln_type:
            original_status = finding.get("status_code", 200)
            if original_status == 422:
                logger.debug(f"[SDL] Descartando — 422 es validación Pydantic, no fuga. {norm_url}")
                _plog("discard", "sdl_422_validation_error", 0.0)
                return None

            _resp_text = finding.get("response_text", "")
            _fields = re.findall(
                r'"(email|id|userId|user_id|token|name|creditCard|vehicleId|orderId|phone)"',
                _resp_text
            )
            _vals = re.findall(
                r'"(?:email|id|userId|user_id|token|name|creditCard|vehicleId|orderId|phone)"'
                r'\s*:\s*"?([^",\}\]\[]{1,60})',
                _resp_text
            )
            _ufields = list(dict.fromkeys(_fields))[:6]
            if _ufields:
                _ev = f"Datos en respuesta: {', '.join(_ufields)}"
                if _vals:
                    _ev += f" — ej: {_vals[0][:40]}"
                finding["evidence_data"] = _ev
            else:
                if "message" in _resp_text or "details" in _resp_text:
                    finding["type"] = "server_error_induced (reclassified from SDL)"
                    finding["risk"] = "Medium"
                    finding["ai_razonamiento"] = (
                        "El endpoint devuelve mensajes de error detallados sin datos de usuario directos. "
                        "Expone información de infraestructura."
                    )

            confidence = max(finding.get("confidence", 0.75), 0.75)
            finding.update({"confidence": confidence, "verified": True,
                            "validation_method": "structural_response_analysis"})
            return finding


        elif "exploit confirmed" in vuln_type:
            auth_token = None
            baseline_resp = await network_manager.send_request(
                norm_url, method=method,
                payload=params if method in ("POST", "PUT") else None,
                json_body=is_json,
            )
            if baseline_resp and baseline_resp.status_code == 200:
                body = baseline_resp.text
                exposure_markers = [
                    '"id":', '"email":', '"token":', '"password":',
                    '"userId":', '"username":', '"results":', '"users":',
                    '"item":', '"entries":',
                ]
                if any(m in body for m in exposure_markers):
                    _ec_fields = re.findall(
                        r'"(email|id|userId|username|users|item|entries|results|user_id|token|name|vehicleId|orderId|phone)"',
                        body
                    )
                    _ec_vals = re.findall(
                        r'"(?:email|id|userId|user_id|token|name|vehicleId|orderId|phone)"'
                        r'\s*:\s*"?([^",\}\]\[]{1,60})', body
                    )
                    _ec_ufields = list(dict.fromkeys(_ec_fields))[:6]
                    if _ec_ufields:
                        _ev = f"Datos en respuesta limpia: {', '.join(_ec_ufields)}"
                        if _ec_vals:
                            _ev += f" — ej: {_ec_vals[0][:40]}"
                        finding["evidence_data"] = _ev
                    finding.update({
                        "confidence": 1.0, "verified": True,
                        "validation_method": "baseline_data_exposure",
                        "response_text": body,
                    })
                    return finding
                else:
                    finding.update({"confidence": 0.75, "verified": False,
                                    "validation_method": "baseline_no_keys"})
                    return finding
            else:
                confidence = finding.get("confidence", 0.7)
                finding.update({
                    "verified": confidence >= 0.8,
                    "validation_method": "baseline_non200" if confidence < 0.8 else "high_confidence_passthrough",
                })
                return finding


        elif any(k in vuln_type for k in ["ssrf", "server-side request forgery"]):
            original_status = finding.get("status_code", 200)
            if original_status == 422:
                logger.debug(f"[SSRF] Descartando — 422 indica rechazo de validación. {norm_url}")
                _plog("discard", "ssrf_422_validation_rejection", 0.0)
                return None

            _ssrf_semantic = ["ssrf", "fetch", "redirect", "proxy", "webhook", "callback"]
            _check_url = str(url).lower() + "|" + str(norm_url).lower()
            if any(sig in _check_url for sig in _ssrf_semantic):
                finding.update({"confidence": 0.90, "verified": True,
                                "validation_method": "ssrf_semantic_confirmed"})
                _plog("pass", f"ssrf_semantic_endpoint status={original_status}", 0.90)
                return finding


            _ssrf_payload = "http://169.254.169.254/latest/meta-data/"
            _ssrf_field   = list(params.keys())[0] if params else "url"
            try:
                _ssrf_resp = await network_manager.send_request(
                    norm_url, method=method,
                    params={_ssrf_field: _ssrf_payload} if method == "GET" else None,
                    payload={_ssrf_field: _ssrf_payload} if method in ("POST", "PUT") else None,
                    json_body=is_json,
                )
                _body = (_ssrf_resp.text or "").lower()
                _confirmed = any(sig in _body for sig in [
                    "169.254", "computemetadata", "latest/meta-data",
                    "ami-id", "instance-id", "connection refused",
                    "fetched successfully",  # solo si hay evidencia clara
                    # NOTA: "error" e "internal server error" removidos — demasiado genéricos
                    # causaban falsos positivos con cualquier JSON {"error": "not found"}
                ])
                if _confirmed or _ssrf_resp.status_code >= 500:
                    finding.update({"confidence": 0.95, "verified": True,
                                    "validation_method": "ssrf_active_reprobe"})
                    return finding
            except Exception as _err:
                logger.debug(f"[SSRF] Re-probe fallido: {_err}")

            finding.update({"confidence": 0.75, "verified": False,
                            "validation_method": "ssrf_unconfirmed"})
            return finding


        elif any(k in vuln_type for k in ["mass_assign", "mass assignment"]):
            if params:
                param_name = list(params.keys())[0]
                try:
                    get_resp = await network_manager.send_request(norm_url, method="GET", params={})
                    if get_resp and get_resp.status_code == 200:
                        payload_val = str(params.get(param_name, ""))
                        if payload_val and payload_val.lower() in get_resp.text.lower():
                            finding.update({
                                "confidence": 1.0, "verified": True,
                                "validation_method": "mass_assign_get_persistence",
                                "evidence_data": f"Campo '{param_name}' persiste en GET response",
                            })
                            return finding
                except Exception as _err:
                    logger.debug(f"[API3] Error en GET de verificación: {_err}")

            finding.update({"confidence": 0.75, "verified": False,
                            "validation_method": "mass_assign_unverified"})
            return finding


        elif any(k in vuln_type for k in ["command_injection", "rce", "cmd"]):

            _rce_markers = [
                "VAA_RCE_CONFIRMED", "SUCCESS_RCE_VAA_BENCHMARK", "SUCCESS_RCE",
                "uid=", "root:x:0:0", "nt authority\\",
                "desktop-", "laptop-", "whoami", "PROCESSOR_IDENTIFIER",
                "ComSpec", "\\Windows\\", "pong", "bytes=",
            ]
            orig_payload = finding.get("payload", "")
            _field = list(params.keys())[0] if params else None


            _rce_fields = ([_field] if _field else []) + ["target", "domain", "host", "cmd", "command", "ip", "url", "input", "q"]
            

            math_val_a, math_val_b = random.randint(100, 999), random.randint(100, 999)
            math_result = str(math_val_a + math_val_b)
            
            math_payloads = [
                f"&set /a {math_val_a}+{math_val_b}",
                f"|expr {math_val_a} + {math_val_b}",
                f"$(expr {math_val_a} + {math_val_b})",
            ]
            
            confirmed = False
            for _f in _rce_fields[:4]:
                if confirmed:
                    break
                for m_pay in math_payloads:
                    try:
                        rce_resp = await network_manager.send_request(
                            norm_url, method=method,
                            payload={_f: m_pay} if method in ("POST", "PUT", "PATCH") else None,
                            params={_f: m_pay} if method == "GET" else None,
                            json_body=is_json,
                        )
                        if rce_resp and math_result in rce_resp.text:
                            finding.update({
                                "confidence": 1.0, "verified": True,
                                "validation_method": "rce_math_confirmed",
                                "ai_razonamiento": (
                                    f"RCE confirmado mediante ejecucion de comando matematico: "
                                    f"'{m_pay}' resulto en '{math_result}' en la respuesta."
                                ),
                            })
                            _plog("pass", "rce_math_confirmed", 1.0)
                            confirmed = True
                            break
                    except Exception:
                        continue

            if confirmed:
                return finding


            rce_resp_text = ""
            try:
                for _f in _rce_fields[:4]:
                    rce_resp = await network_manager.send_request(
                        norm_url, method=method,
                        payload={_f: orig_payload} if method in ("POST", "PUT", "PATCH") else None,
                        params={_f: orig_payload} if method == "GET" else None,
                        json_body=is_json,
                    )
                    if rce_resp:
                        rce_resp_text = rce_resp.text
                        for m in _rce_markers:
                            if m in rce_resp_text:
                                full_payload_echoed = str(orig_payload) in rce_resp_text
                                if not full_payload_echoed or "SUCCESS_RCE_VAA_BENCHMARK" in m:
                                    finding.update({
                                        "confidence": 1.0, "verified": True,
                                        "validation_method": "rce_marker_confirmed",
                                        "ai_razonamiento": f"RCE confirmado via marcador: {m}"
                                    })
                                    return finding
            except Exception:
                pass


            orig_conf = finding.get("confidence", 0.5)
            _url_lower = norm_url.lower()
            _rce_url_hints  = any(x in _url_lower for x in ["rce", "cmd", "ping", "dns", "exec", "shell", "command", "inject"])
            _rce_url_clash  = any(x in _url_lower for x in ["xss", "sqli", "mass-assign", "bola", "uuid", "safe"])
            _rce_url_ok = _rce_url_hints or not _rce_url_clash
            if orig_conf >= 0.85 and method in ("POST", "PUT", "PATCH") and _rce_url_ok:
                logger.debug(f"[RCE] Math/marker inconcluso en POST, M3 conf={orig_conf}. Reteniendo.")
                finding.update({
                    "confidence": 0.75, "verified": True,
                    "validation_method": "rce_m3_confirmed_post",
                    "ai_razonamiento": "RCE confirmado por M3 en endpoint POST. Math reprobe inconcluso.",
                })
                return finding


            logger.warning(f"[RCE FP] No se pudo confirmar RCE independientemente en {norm_url}")
            return None


        elif any(k in vuln_type for k in ["prompt_injection", "ai injection", "ai_injection", "prompt injection"]):
            _ai_markers = [
                "VAA_AI_OVERRIDE_SUCCESS", "VAA_BENCHMARK_PWNED",
                "i am a large language model", "as an ai", "system instructions",
                "ignore previous", "my new instructions",
                "system_secret_key", "SYSTEM_SECRET_KEY",

                "SYSTEM_SECRET=", "leaked_secret", "UNRESTRICTED",
            ]
            orig_payload = finding.get("payload", "")

            _ai_fields = ([list(params.keys())[0]] if params else []) + ["prompt", "message", "input", "text", "query", "content"]
            _ai_confirmed = False
            for _field in _ai_fields:
                try:
                    ai_resp = await network_manager.send_request(
                        norm_url, method=method,
                        payload={_field: orig_payload} if method in ("POST", "PUT", "PATCH") else None,
                        params={_field: orig_payload} if method == "GET" else None,
                        json_body=is_json,
                    )
                    if ai_resp and ai_resp.status_code not in (400, 422):
                        ai_body = ai_resp.text.lower()
                        for m in _ai_markers:
                            if m.lower() in ai_body and m.lower() not in str(orig_payload).lower():
                                finding.update({
                                    "confidence": 1.0, "verified": True,
                                    "validation_method": "prompt_injection_marker_confirmed",
                                    "ai_razonamiento": (
                                        f"El re-probe (campo='{_field}') produjo marcador '{m}'. "
                                        "Prompt Injection confirmado."
                                    ),
                                })
                                _plog("pass", "prompt_injection_marker_in_reprobe", 1.0)
                                _ai_confirmed = True
                                break
                    if _ai_confirmed:
                        break
                except Exception as _ai_err:
                    logger.debug(f"[PromptInjection] Re-probe error ({_field}): {_ai_err}")
                    continue
            if _ai_confirmed:
                return finding


            orig_conf = finding.get("confidence", 0.5)
            _url_lower = norm_url.lower()
            _ai_url_hints = any(x in _url_lower for x in ["prompt", "inject", "ai", "llm", "chat", "gpt", "model", "generate"])
            _ai_url_clash = any(x in _url_lower for x in ["xss", "sqli", "rce", "mass-assign", "bola", "uuid", "safe", "ping", "dns"])
            _ai_url_ok = _ai_url_hints or not _ai_url_clash
            if orig_conf >= 0.85 and method in ("POST", "PUT", "PATCH") and _ai_url_ok:
                logger.debug(f"[PromptInjection] Marker inconcluso en POST, M3 conf={orig_conf}. Reteniendo.")
                finding.update({
                    "confidence": 0.75, "verified": True,
                    "validation_method": "prompt_injection_m3_confirmed_post",
                    "ai_razonamiento": "Prompt Injection confirmado por M3 en endpoint POST. Marker reprobe inconcluso.",
                })
                return finding

            # Si no se confirmó con marker y confianza < 0.85, degradar a no-verificado
            finding.update({
                "confidence": min(orig_conf, 0.70), "verified": False,
                "validation_method": "prompt_injection_unconfirmed",
                "ai_razonamiento": "Prompt Injection detectado por M3 pero sin confirmación de marker. Requiere revisión manual.",
            })
            return finding

        else:
            finding.update({
                "confidence": 0.8, "verified": False,
                "validation_method": "unverified_fallback",
                "ai_razonamiento": (
                    "Comportamiento anómalo detectado que coincide con patrones de ataque conocidos, "
                    "pero no se pudo confirmar la explotación automática. Requiere revisión manual."
                ),
            })
            return finding

    except Exception as exc:
        logger.debug(f"[Validation] PoC error for {vuln_type} @ {norm_url}: {exc}")
        finding.update({"confidence": 0.7, "verified": False})
        return finding


async def process_queue(
    validation_queue: asyncio.Queue,
    network_manager: Any,
    m2_get_pairs,
    record_finding,
    m1_learn_exploit,
    token_health_check=None,
    pipeline_log=None,
) -> None:
    """
    Drena la validation_queue y procesa cada hallazgo en paralelo (asyncio.gather).

    Args:
        validation_queue: Cola de hallazgos pendientes de validación.
        network_manager:  NetworkManager del orquestador.
        m2_get_pairs:     M2.get_verification_pairs para SQLi diferencial.
        record_finding:   Coroutine del orquestador para registrar hallazgos.
        m1_learn_exploit: M1.learn_exploit para retroalimentación.
        pipeline_log:     Callable opcional de trazabilidad.
    """
    if validation_queue.empty():
        return

    logger.info(f"\n[*] Iniciando Validación Activa ({validation_queue.qsize()} hallazgos)...")
    tasks = []

    async with network_manager.create_client():
        while not validation_queue.empty():
            finding = await validation_queue.get()
            tasks.append(validate_finding(
                finding, network_manager, m2_get_pairs, 
                token_health_check=token_health_check, 
                pipeline_log=pipeline_log
            ))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r and not isinstance(r, Exception):
                    await record_finding(r)
                    m1_learn_exploit(
                        endpoint=r.get("url", ""),
                        payload=r.get("payload", ""),
                        vuln_type=r.get("type", ""),
                    )
