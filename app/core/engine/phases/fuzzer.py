"""
Fase 3: Fuzzing masivo asincrono (Attack Worker Pool).
"""
import asyncio
import re
import time
from typing import Any, Dict, List, Optional

from app.utils.logger import logger  # pyre-ignore[21]
from app.core.engine.algorithms.shannon import ShannonOracle
from app.core.engine.models import VulnerabilityFinding, EndpointTarget


DEFAULT_VULN_TYPES = ["mass_assignment", "sqli", "xss", "ssrf", "rce", "bola", "idor"]


_HIDDEN_MA_FIELDS = ["is_admin", "role", "admin", "permissions", "privileges", "root", "internal"]


AUTH_BLOCK_THRESHOLD = 1000


M9_MAX_PARAMS = 15


EP_FUZZ_TIMEOUT = 60


async def run(
    endpoints: List[EndpointTarget],
    network_manager: Any,
    options: Dict[str, Any],
    sem: asyncio.Semaphore,
    oracle: ShannonOracle,
    m1_grammar_context: Dict,
    m1_classify,
    m2_generate_suite,
    m2_prioritize,
    m3_predict_risk,
    m9_discover_params,
    harvest_from_response,
    record_finding,
    validation_queue: asyncio.Queue,
    queue_dedup: set,
    target: str,
    detected_stack: List[str],
    abort_scan_ref: List[bool],
    stats: Dict[str, int],
    token_health_check,
    pipeline_log=None,
) -> None:
    """Ejecuta el ciclo de fuzzing masivo sobre todos los endpoints."""
    logger.info(f"\n=== FASE 3: FUZZING API contra {len(endpoints)} Endpoints ===")

    is_local = any(x in target for x in ["localhost", "127.0.0.1", "::1"])
    limit    = options.get("concurrency", 5)
    is_tor   = options.get("use_tor", False)


    vuln_types = list(DEFAULT_VULN_TYPES)
    
    if options.get("scan_ai"):  
        if "prompt_injection" not in vuln_types: vuln_types.append("prompt_injection")
        if "ai_injection" not in vuln_types: vuln_types.append("ai_injection")
        
    if not options.get("scan_rce", True):
        vuln_types = [t for t in vuln_types if t != "rce"]
    
    logger.info(f"[*] Tipos de vulnerabilidades activos: {vuln_types}")


    _waf_profile = next(
        (s for s in detected_stack if s in ("cloudflare", "nginx", "apache", "akamai")),
        "auto"
    )
    if _waf_profile != "auto":
        logger.info(f"[WAF Profile] Usando perfil de evasión: {_waf_profile}")


    attack_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
    auth_blocked: Dict[str, int] = {}

    token_health_checked = False

    async def _worker():
        nonlocal token_health_checked
        while True:
            item = await attack_queue.get()
            if item is None:
                break

            client, url, method, payload, v_type, v_score, q_dict, b_dict, j_body, c_hdrs = item


            if "{" in url and "}" in url:
                logger.debug(f"[Worker] URL con placeholder sin resolver: {url}")
                attack_queue.task_done()
                continue

            base_url = url.split("?")[0]
            if auth_blocked.get(base_url, 0) >= AUTH_BLOCK_THRESHOLD:
                attack_queue.task_done()
                continue

            async with sem:
                try:
                    status = await _scan_single(
                        url, method, payload, v_type, v_score,
                        q_dict, b_dict, j_body, c_hdrs,
                    )
                    if status in (401, 403):

                        auth_hdr = c_hdrs.get("Authorization", "") if c_hdrs else ""
                        is_alt_token = options.get("auth_b_token") and options.get("auth_b_token") in auth_hdr
                        
                        if not is_alt_token:
                            auth_blocked[base_url] = auth_blocked.get(base_url, 0) + 1
                            if auth_blocked[base_url] == AUTH_BLOCK_THRESHOLD:
                                logger.warning(f"[Auth-Block] {base_url} bloqueado (multiples 401/403).")
                    else:
                        if base_url in auth_blocked:
                            auth_blocked[base_url] = 0
                except Exception as exc:
                    logger.debug(f"[Worker] Error en {url}: {exc}")
                finally:
                    attack_queue.task_done()


    async def _scan_single(
        url, method, payload, v_type, v_score,
        query_params, body_payload, json_body, custom_headers
    ) -> Optional[int]:

        if abort_scan_ref[0]:
            return None


        _active_param = (
            list(query_params.keys())[0] if query_params else
            list(body_payload.keys())[0] if body_payload else "_no_param"
        )
        shannon_key = oracle.make_key(url, v_type, _active_param)


        if oracle.is_exhausted(shannon_key):
            import random as _rnd


            skip_prob = 0.8 if is_local else 0.9
            if _rnd.random() < skip_prob:
                return None

        t0 = time.time()
        headers = custom_headers.copy() if custom_headers else {}

        resp = await network_manager.send_request(
            url, method=method, payload=body_payload, json_body=json_body,
            custom_headers=headers, query_params=query_params
        )
        if not resp:
            return None


        stats["total_requests"] += 1
        total = stats["total_requests"]

        if resp.status_code == 429:
            stats["429_count"] += 1
            rate_429 = stats["429_count"] / total
            if total > 20 and rate_429 > 0.2:
                if not abort_scan_ref[0]:
                    abort_scan_ref[0] = True
                    logger.critical(f"🚨 CIRCUIT BREAKER! 429 Rate: {rate_429:.1%}. Abortando.")
                return resp.status_code

        if resp.status_code == 401:
            stats["401_count"] = stats.get("401_count", 0) + 1
            rate_401 = stats["401_count"] / total
            nonlocal token_health_checked
            if total > 10 and rate_401 > 0.3 and not token_health_checked:
                token_health_checked = True
                logger.warning(f"⚠️ [Token Health] Alta tasa 401 ({rate_401:.1%}). Verificando token...")
                try:
                    valid = await token_health_check(url)
                    if not valid:
                        logger.critical("🚨 [Token Health] TOKEN EXPIRADO.")
                    else:
                        token_health_checked = False
                        stats["401_count"] = 0
                except Exception:
                    pass


        if resp.status_code == 200 and resp.text:
            harvest_from_response(resp.text, url)


        t1 = time.time()
        state_changed, newly_exhausted = oracle.record(
            shannon_key, resp.status_code, len(resp.content), is_local
        )
        if state_changed:
            oracle.reset(shannon_key)
            if newly_exhausted:
                logger.warning(f"[Oracle] Shannon agotado para {shannon_key}")
                
        if oracle.detect_bypass(shannon_key):
            logger.warning(f"[Shannon] BYPASS DETECTADO (401/403 -> 200) para {shannon_key}!")
            finding = {
                "url": url, "norm_url": url.split("?")[0],
                "type": "Broken Access Control (Bypass)", "payload": payload,
                "risk": "High", "confidence": 0.85,
                "report_policy": "strict",
                "method": method,
                "params": query_params or body_payload or {},
                "is_json": json_body,
                "status_code": resp.status_code,
                "response_text": resp.text[:500],
                "verified": False,
                "validation_method": "shannon_oracle_bypass"
            }
            if pipeline_log:
                pipeline_log(shannon_key, "shannon", "detect_bypass", "Auth bypass detected via state change", url=url, vuln_type="bac_bypass", confidence=0.85)
            await validation_queue.put(finding)


        if resp.status_code == 422 and isinstance(payload, str) and payload in (getattr(resp, 'text', '') or ''):
            return resp.status_code


        recent = [int(s.split("_")[0]) for s in oracle._state.get(shannon_key, [])]
        if recent and all(s in (401, 403) for s in recent):
            return resp.status_code


        try:
            r_text = resp.text
        except Exception:
            r_text = resp.content.decode("latin-1", errors="ignore") if hasattr(resp, "content") else ""


        decoded_payload = payload
        if isinstance(payload, str):
            if "%" in payload:
                import urllib.parse
                decoded_payload = urllib.parse.unquote(payload)
            if "\\u" in payload:
                try:
                    decoded_payload = payload.encode().decode('unicode_escape')
                except Exception:
                    pass
        is_refl = 1.0 if (isinstance(payload, str) and (payload in r_text or decoded_payload in r_text)) else 0.0


        result_vector = {
            "endpoint": url,
            "status_code": resp.status_code,
            "response_text": r_text,
            "response_time_ms": (t1 - t0) * 1000,
            "is_reflected": is_refl,
            "decoded_payload": decoded_payload,
            "type": v_type,
            "context_violation_score": v_score,
            "headers": dict(resp.headers),
            "params": query_params or body_payload or {},
        }
        risk, confidence, label = m3_predict_risk(result_vector, is_tor=is_tor)

        norm_url = url.split("?")[0]
        last_seg = norm_url.rstrip("/").rsplit("/", 1)[-1]
        if re.search(r'[<>\'"\\%{(]', last_seg):
            norm_url = norm_url.rstrip("/").rsplit("/", 1)[0]

        is_local_target = is_local
        report_policy   = "local" if is_local_target else "strict"


        if risk in ("High", "Medium"):
            _queue_key = f"{norm_url}|{label}"

            if _queue_key in queue_dedup:
                return resp.status_code
            queue_dedup.add(_queue_key)

            logger.warning(f"{risk} Risk ({label}) detectado en {url}!")
            finding: VulnerabilityFinding = {  # type: ignore[assignment]
                "url": url, "norm_url": norm_url,
                "type": label, "payload": payload,
                "risk": risk, "confidence": confidence,
                "report_policy": report_policy,
                "method": method,
                "params": query_params or body_payload or {},
                "is_json": json_body,
                "status_code": resp.status_code,
                "response_text": resp.text[:500],
                "verified": False,
                "validation_method": "",
            }
            await validation_queue.put(finding)

        return resp.status_code


    async def _enqueue(client, url, method, payload, v_type, v_score,
                   ep_headers, q_params=None, b_payload=None, j=False, h=None, force_token=None):
        base_hdrs = ep_headers.copy()
        

        token = force_token or options.get("auth_token") or options.get("token")
        if token and "Authorization" not in base_hdrs:
            base_hdrs["Authorization"] = token if " " in token else f"Bearer {token}"

        if not h and (v_type in ("sqli", "rce", "cmdi") or "analytics" in url):
            h = {"User-Agent": payload, "X-Forwarded-For": payload}
        if h:
            base_hdrs.update(h)

        await attack_queue.put((client, url, method, payload, v_type, v_score,
                            q_params, b_payload, j, base_hdrs))


    workers = [asyncio.create_task(_worker()) for _ in range(limit)]
    logger.info(f"[*] Worker Pool iniciado ({limit} workers)...")
    client = None

    for ep in endpoints:
        if abort_scan_ref[0]:
            break

        url         = ep["url"]
        method      = ep["method"]
        logger.info(f"[Fuzzer] Analizando {method} {url}...")

        ep_params   = ep.get("params", {})
        body_schema = ep.get("body_schema")
        ep_headers  = ep.get("headers", {})


        discovered = []
        has_known = bool(ep_params.get("query") or ep_params.get("path") or body_schema)
        _m9_eligible = method == "GET" and not has_known and not abort_scan_ref[0]
        if options.get("discover_params", True) and _m9_eligible:
            logger.info(f"[M9] Parameter Discovery en {url}...")
            discovered = await m9_discover_params(
                network_manager, url, method,
                token_health_check=token_health_check
            )
            if discovered:

                if len(discovered) > M9_MAX_PARAMS:
                    logger.info(f"[M9] Limitando de {len(discovered)} a {M9_MAX_PARAMS} params (usa --deep-scan para m\u00e1s).")
                    discovered = discovered[:M9_MAX_PARAMS]
                logger.info(f"[M9] \u2705 {len(discovered)} param(s) oculto(s): {discovered}")
                for dp in discovered:
                    p_in = "query" if method == "GET" else "body"
                    ep_params.setdefault(p_in, []).append({"name": dp, "in": p_in, "source": "m9_discovery"})
                ep["params"] = ep_params


                resource_kw = {"limit", "count", "size", "page_size", "per_page", "max", "take"}
                resource_params = [p for p in discovered if p.lower() in resource_kw]
                if resource_params:
                    await _probe_resource_consumption(
                        url, method, resource_params[0],
                        network_manager, options, target, record_finding
                    )


        ep_path     = url.replace(target, "") or url
        ep_known_p  = {p["name"]: "" for p in ep_params.get("query", [])}
        endpoint_type = m1_classify(ep_path, ep_known_p)


        tokens_to_try = [options.get("auth_token")]
        if options.get("auth_b_token"): tokens_to_try.append(options.get("auth_b_token"))
        active_tokens = list(set(filter(None, tokens_to_try))) or [None]

        for v_type in vuln_types:

            if oracle.is_exhausted(oracle.make_key(url, v_type, "_no_param")):
                logger.debug(f"[Fuzzer] {v_type} exhausto en {url}. Saltando.")
                continue

            suite = await asyncio.to_thread(m2_generate_suite, m1_grammar_context, url, v_type, _waf_profile)
            suite = m2_prioritize(suite, endpoint_type)


            _is_auth = any(seg in url for seg in ["/auth", "/token", "/login"])
            limit_val = 8 if _is_auth else 15
            suite = suite[:limit_val]

            for payload, v_score in suite:

                if oracle.is_exhausted(oracle.make_key(url, v_type, "_no_param")):
                    break

                for t in active_tokens:

                    for p_info in ep_params.get("query", []):
                        await _enqueue(client, url, method, payload, v_type, v_score, ep_headers, q_params={p_info["name"]: payload}, force_token=t)


                    for p_info in ep_params.get("path", []):
                        placeholder = "{" + p_info["name"] + "}"
                        if placeholder in url:
                            await _enqueue(client, url.replace(placeholder, str(payload)), method, payload, v_type, v_score, ep_headers, force_token=t)


                    if method in ("POST", "PUT", "PATCH"):
                        json_hdrs = ep_headers.copy()
                        json_hdrs["Content-Type"] = "application/json"
                        if body_schema and "properties" in body_schema:
                            for field in body_schema["properties"].keys():
                                await _enqueue(client, url, method, payload, v_type, v_score, json_hdrs, b_payload={field: payload}, j=True, force_token=t)
                        if v_score > 0.8:
                            for field in _HIDDEN_MA_FIELDS:
                                await _enqueue(client, url, method, payload, v_type, v_score, json_hdrs, b_payload={field: payload}, j=True, force_token=t)


                    if method in ("POST", "PUT", "PATCH"):
                        json_hdrs = ep_headers.copy()
                        json_hdrs["Content-Type"] = "application/json"
                        for p_info in ep_params.get("body", []):
                            await _enqueue(client, url, method, payload, v_type, v_score, json_hdrs, b_payload={p_info["name"]: payload}, j=True, force_token=t)


                    if v_score > 0.9:
                        for hdr in ("User-Agent", "Referer", "X-Forwarded-For"):
                            await _enqueue(client, url, method, payload, v_type, v_score, ep_headers, h={hdr: payload}, force_token=t)


    try:
        await asyncio.wait_for(attack_queue.join(), timeout=300.0)
    except asyncio.TimeoutError:
        logger.warning("[Fuzzer] attack_queue.join() timeout (300s). Continuando con hallazgos actuales.")

        while not attack_queue.empty():
            try:
                attack_queue.get_nowait()
                attack_queue.task_done()
            except Exception:
                break

    for _ in range(limit):
        await attack_queue.put(None)
    await asyncio.gather(*workers, return_exceptions=True)


async def _probe_resource_consumption(
    url: str, method: str, param_name: str,
    network_manager: Any, options: Dict, target: str, record_finding
) -> None:
    """
    Prueba valores extremos en par\u00e1metros de paginaci\u00f3n para detectar API4.
    Umbral Adaptativo: tiempo extremo / tiempo baseline \u2265 5.0x O > 5000ms.
    """
    import time as _time
    auth_token = options.get("auth_token", "")
    auth_hdrs  = {"Authorization": auth_token if " " in auth_token else f"Bearer {auth_token}"} if auth_token else {}

    try:
        t0 = _time.monotonic()
        baseline = await network_manager.send_request_raw(
            url, payload={param_name: "10"}, headers=auth_hdrs, timeout=15.0
        )
        baseline_ms = (_time.monotonic() - t0) * 1000

        if not (baseline and baseline.status_code == 200):
            return


        ratio_threshold = 5.0
        time_threshold  = 5000

        for extreme_val in ("99999", "999999"):
            t1 = _time.monotonic()
            extreme = await network_manager.send_request_raw(
                url, payload={param_name: extreme_val}, headers=auth_hdrs, timeout=15.0
            )
            extreme_ms = (_time.monotonic() - t1) * 1000

            if not (extreme and extreme.status_code == 200):
                continue

            ratio = extreme_ms / max(baseline_ms, 1)
            if ratio >= ratio_threshold or extreme_ms > time_threshold:
                logger.warning(
                    f"[API4] Resource Consumption: {url} ?{param_name}={extreme_val} "
                    f"({extreme_ms:.0f}ms vs {baseline_ms:.0f}ms, {ratio:.1f}x)"
                )
                await record_finding({
                    "url": url, "norm_url": url,
                    "type": "Resource_Consumption (API4)",
                    "method": method,
                    "payload": f"?{param_name}={extreme_val}",
                    "risk": "Medium",
                    "confidence": min(0.7 + (ratio / 50), 1.0),
                    "verified": True,
                    "validation_method": "response_time_ratio",
                    "response_text": f"baseline={baseline_ms:.0f}ms, extreme={extreme_ms:.0f}ms",
                    "ai_razonamiento": (
                        f"El parámetro `{param_name}` acepta valores sin límite: "
                        f"`{extreme_val}` incrementó el tiempo {ratio:.1f}x "
                        f"({extreme_ms:.0f}ms vs {baseline_ms:.0f}ms)."
                    ),
                    "ai_remediacion": (
                        f"Imponer un límite máximo en `{param_name}` (ej: max=100). "
                        "Implementar rate limiting por token/IP."
                    ),
                })
                break
    except Exception as err:
        logger.debug(f"[API4] Error en resource probe: {err}")
