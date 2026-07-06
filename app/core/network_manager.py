"""
Network Manager: Manejo de sesiones HTTP, proxies y evasion TLS.
"""

import asyncio
import httpx  # pyre-ignore[21]
import random
import time
from typing import Dict, Any, Optional, List
from curl_cffi.requests import AsyncSession  # pyre-ignore[21]
from app.config.settings import settings  # pyre-ignore[21]
from app.utils.logger import logger  # pyre-ignore[21]
from app.core.m5_ghost_v2 import M5GhostProtocol # pyre-ignore[21]

class AdaptiveBackoff:
    """
    Circuit Breaker para deteccion de WAF/Rate Limiting.
    """
    def __init__(self):
        self.block_count = 0
        self.last_block_time: Optional[float] = None
        self.current_delay_ms = 0
        self.window_start = time.time()
        self.window_duration = 30
        self.threshold = 5
        
    def on_block(self, status_code: int) -> Optional[Dict[str, Any]]:
        """
        Called when 403/429 is detected.
        Returns action dict if circuit breaker triggers.
        """
        current_time = time.time()
        

        if current_time - self.window_start > self.window_duration:
            self.block_count = 0
            self.window_start = current_time
        
        self.block_count += 1
        self.last_block_time = current_time
        
        if self.block_count > self.threshold:

            self.current_delay_ms = min(self.current_delay_ms * 2 if self.current_delay_ms > 0 else 1000, 30000)
            
            logger.warning(f" [Circuit Breaker] Triggered! Blocks: {self.block_count}, Delay: {self.current_delay_ms}ms")
            
            return {
                "action": "rotate_identity",
                "delay_ms": self.current_delay_ms,
                "clear_cookies": True
            }
        
        return None
    
    def cooldown(self):
        """Decremento gradual tras respuesta saludable."""
        if self.block_count > 0:
            self.block_count -= 1
        if self.current_delay_ms > 0:
            self.current_delay_ms = max(0, self.current_delay_ms // 2)

    def reset(self):
        """Reset total — solo llamar en reconexion limpia o inicio de sesion."""
        self.block_count = 0
        self.current_delay_ms = 0


class NetworkManager:
    def __init__(self, target: str, options: Dict[str, Any]):
        self.target = target
        self.options = options
        self.proxy = self._setup_proxy()
        self.session_pool: List[AsyncSession] = []
        self.max_pool_size = 5
        self.browser_pool = self._get_browser_pool()
        self.base_headers = self._parse_custom_headers()
        self.auth_refresh_fn = self.options.get("auth_refresh_fn")
        
        self.m5 = M5GhostProtocol(self.options)
        self.circuit_breaker = AdaptiveBackoff()
        self.auth_401_count = 0
        self.detected_waf = "Unknown"
        self.waf_fingerprinted = False
        self._pool_ref_count: int = 0

        self.waf_state: str = "clean"
        self.waf_block_streak: int = 0
        self._last_blocked_url: str = ""
        self._WAF_TRIGGER_THRESHOLD: int = 3

        _local_indicators = ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
        _target_is_local = any(ind in self.target for ind in _local_indicators)
        self.verify_ssl = settings.VERIFY_SSL if not _target_is_local else False

    def _parse_custom_headers(self) -> Dict[str, str]:
        """Parsea headers desde string 'Header:Value' y aplica OPSEC."""
        headers = {}
        

        raw_headers_str = self.options.get("custom_headers")
        if raw_headers_str:
            try:
                for pair in raw_headers_str.split(";"):
                    if ":" in pair:
                        k, v = pair.split(":", 1)
                        headers[k.strip()] = v.strip()
            except Exception as e:
                logger.error(f"Error parseando custom_headers string: {e}")

        auth_token = self.options.get("auth_token")
        if auth_token:
            headers["Authorization"] = auth_token if " " in auth_token else f"Bearer {auth_token}"

        if self.options.get("use_ghost") or self.options.get("anonymous"):
             risky_headers = ["X-Bug-Bounty", "X-Research-Contact", "From", "User-Email"]
             for h in risky_headers:
                 if h in headers: del headers[h]
        elif self.options.get("bug_bounty_mode"):
             if "X-Bug-Bounty" not in headers:
                  headers["X-Bug-Bounty"] = getattr(settings, "APP_NAME", "VAA-Scanner")
             if "X-Research-Contact" not in headers:
                  headers["X-Research-Contact"] = getattr(settings, "H1_EMAIL", "anonymous@example.com")
                  
        return headers

    def _is_waf_block(self, resp: Any) -> bool:
        """
        Distingue un 403 de WAF de un 403 de autenticacion/permisos.
        WAF blocks tienen firmas especificas en headers; auth 403s no.
        """
        if not resp or getattr(resp, 'status_code', None) != 403:
            return False
        headers_lower = {k.lower(): v.lower() for k, v in (resp.headers or {}).items()}
        waf_signatures = [
            "cf-ray", "cf-cache-status",
            "x-sucuri-id", "x-sucuri-cache",
            "x-iinfo",
            "x-cdn", "x-amz-cf-id",
            "x-akamai-session-id",
            "server: cloudflare", "server: awselb",
        ]
        body_lower = (getattr(resp, 'text', '') or '').lower()[:500]
        body_signatures = [
            "cloudflare", "ray id", "access denied", "request blocked",
            "sucuri", "incapsula", "mod_security", "firewall",
        ]
        for sig in waf_signatures:
            if ": " in sig:
                h, v = sig.split(": ", 1)
                if headers_lower.get(h, "") == v:
                    return True
            elif sig in headers_lower:
                return True
        return any(sig in body_lower for sig in body_signatures)


    def _setup_proxy(self) -> Optional[str]:
        if self.options.get("use_tor"):
            socks_port = getattr(settings, "TOR_SOCKS_PORT", 9050)
            return f"socks5://127.0.0.1:{socks_port}"
        return self.options.get("proxy")

    def _get_browser_pool(self):
        return [
            {"impersonate": "chrome120", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
            {"impersonate": "safari17_2_ios", "ua": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"},
            {"impersonate": "edge101", "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36 Edge/101.0.1210.53"}
        ]

    def create_client(self):
        """Context manager compatible con el orquestador."""
        return self

    async def __aenter__(self):
        self._pool_ref_count += 1
        if self._pool_ref_count == 1:

            for _ in range(self.max_pool_size):
                browser = random.choice(self.browser_pool)
                session = AsyncSession(
                    impersonate=browser["impersonate"],
                    proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None,
                    verify=self.verify_ssl,
                    timeout=settings.DEFAULT_TIMEOUT
                )

                final_headers = {**self.base_headers, "User-Agent": browser["ua"]}
                session.headers.update(final_headers)
                self.session_pool.append(session)
            logger.debug(f"[Network] Pool inicializado con {len(self.session_pool)} sesiones JA3.")
        else:
            logger.debug(f"[Network] Pool reutilizado (ref_count={self._pool_ref_count}, sesiones={len(self.session_pool)}).")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._pool_ref_count = max(0, self._pool_ref_count - 1)
        if self._pool_ref_count == 0:

            for session in self.session_pool:
                try:
                    await session.close()
                except Exception as e:
                    logger.debug(f"[Network] Error cerrando sesion del pool: {e}")
            self.session_pool.clear()
            logger.debug("[Network] Pool cerrado y limpiado (ref_count=0).")
        else:
            logger.debug(f"[Network] Pool NO cerrado aún (ref_count={self._pool_ref_count}).")
    async def send_request(
        self,
        url: str,
        method: str = "GET",
        payload: Optional[Dict[str, Any]] = None,
        json_body: bool = False,
        custom_headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, Any]] = None,
        use_pool: bool = True,
        stealth: bool = True
    ) -> Optional[Any]:
        """Envia una peticion usando el pool (reuso) o raw (limpia). Evasion WAF adaptativa integrada."""
        if not use_pool or not self.session_pool:
            merged_hdrs = self.base_headers.copy()
            if custom_headers:
                merged_hdrs.update(custom_headers)
            return await self.send_request_raw(
                url, method=method, payload=payload or query_params,
                json_body=json_body, headers=merged_hdrs
            )

        session = random.choice(self.session_pool)

        base_delay = self.options.get("delay", 0.0)
        if stealth and base_delay > 0:
            await asyncio.sleep(base_delay)

        current_headers = self.base_headers.copy()

        ghost_active = self.options.get("use_ghost") or self.waf_state in ("triggered", "verified")
        if stealth and ghost_active:
            current_headers = self.m5.get_stealth_headers(current_headers)
            await asyncio.sleep(random.uniform(0.1, 0.5))

        if custom_headers:
            current_headers.update(custom_headers)

        for attempt in range(2):
            try:
                q_params = query_params if query_params is not None else (payload if method == "GET" else None)
                req_kwargs = {}
                if q_params:
                    req_kwargs["params"] = {k: str(v) for k, v in q_params.items()}

                if method in ("POST", "PUT", "PATCH"):
                    if json_body and payload is not None: req_kwargs["json"] = payload
                    elif not json_body and payload is not None: req_kwargs["data"] = payload

                resp = await session.request(method, url, headers=current_headers, **req_kwargs)

                if resp is not None:
                    if resp.status_code == 429:
                        action = self.circuit_breaker.on_block(resp.status_code)
                        if action and action.get("delay_ms", 0) > 0:
                            await asyncio.sleep(action["delay_ms"] / 1000)
                            continue

                    elif self._is_waf_block(resp):
                        self.waf_block_streak += 1
                        self._last_blocked_url = url

                        if self.waf_state == "clean" and self.waf_block_streak >= self._WAF_TRIGGER_THRESHOLD:
                            self.waf_state = "triggered"
                            self.m5.activate()
                            logger.warning(
                                f"[WAF Adaptive] Estado: CLEAN → TRIGGERED "
                                f"(streak={self.waf_block_streak}, profile={self.m5.active_profile})"
                            )

                        elif self.waf_state == "triggered" and self.waf_block_streak >= self._WAF_TRIGGER_THRESHOLD + 3:
                            new_profile = self.m5.get_next_profile()
                            logger.warning(f"[WAF Adaptive] Evasion fallida. Rotando perfil → {new_profile}")
                            self.waf_block_streak = self._WAF_TRIGGER_THRESHOLD

                    elif resp.status_code < 400:
                        self.circuit_breaker.cooldown()

                        if self.waf_state == "triggered" and url == self._last_blocked_url:
                            self.waf_state = "verified"
                            logger.info(
                                f"[WAF Adaptive] Estado: TRIGGERED → VERIFIED ✅ "
                                f"Evasion exitosa con perfil '{self.m5.active_profile}' en {url}"
                            )
                        else:
                            if self.waf_block_streak > 0:
                                self.waf_block_streak -= 1

                return resp

            except Exception as e:
                err_msg = str(e).lower()
                is_session_dead = "closed" in err_msg or "connection" in err_msg or "timeout" in err_msg

                if is_session_dead and attempt == 0:
                    logger.debug(f"[Network] Sesión rota detectada ({type(e).__name__}). Regenerando pool...")
                    try:
                        idx = self.session_pool.index(session)
                        browser = random.choice(self.browser_pool)
                        new_session = AsyncSession(
                            impersonate=browser["impersonate"],
                            proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None,
                            verify=self.verify_ssl,
                            timeout=settings.DEFAULT_TIMEOUT
                        )
                        new_session.headers.update({**self.base_headers, "User-Agent": browser["ua"]})
                        await session.close()
                        self.session_pool[idx] = new_session
                        session = new_session
                        continue
                    except Exception as re_err:
                        logger.error(f"[Network] Error crítico regenerando sesión: {re_err}")

                logger.warning(f"[Network] Fallo irreversible en {method} {url}: {e}")
                return None

        return None

    async def send_request_raw(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        payload: Optional[Dict[str, Any]] = None,
        json_body: bool = False,
        timeout: float = 10.0,
        query_params: Optional[Dict[str, Any]] = None
    ) -> Optional[Any]:
        """Peticion raw sin reuso de TLS."""
        base_delay = self.options.get("delay", 0.0)
        is_local = any(x in url for x in ["localhost", "127.0.0.1", "::1"])
        

        if is_local and base_delay == 0.0:
            base_delay = 0.15

        if base_delay > 0:
            await asyncio.sleep(base_delay)

        import httpx
        try:
            resp = None
            transport_proxy = self.proxy if self.proxy else None


            async with httpx.AsyncClient(timeout=timeout, verify=self.verify_ssl, proxy=transport_proxy) as client:
                for attempt in range(2):
                    q_params = query_params if query_params is not None else (payload if method == "GET" else None)
                    logger.debug(f"[Network] {method} {url} | query={q_params} | body={payload if method != 'GET' else None} | json={json_body}")

                    req_kwargs = {}
                    if q_params: req_kwargs["params"] = q_params
                    if method in ("POST", "PUT", "PATCH"):
                        if json_body and payload is not None: req_kwargs["json"] = payload
                        elif not json_body and payload is not None: req_kwargs["data"] = payload

                    resp = await client.request(method, url, headers=headers, **req_kwargs)


                    if resp is not None and getattr(resp, 'status_code', None) in (429, 403):
                        if getattr(resp, 'status_code', None) == 403:
                            break
                        
                        if getattr(resp, 'status_code', None) == 429:
                            action = self.circuit_breaker.on_block(resp.status_code)
                            if action and action.get("delay_ms", 0) > 0:
                                delay_s = action["delay_ms"] / 1000
                                logger.warning(f" [CB Raw] Rate limited. Backoff: {delay_s:.1f}s. Reintentando...")
                                await asyncio.sleep(delay_s)
                                continue
                    

                    if resp is not None and resp.status_code < 400:
                        self.circuit_breaker.cooldown()
                        
                    break
                
            if resp is not None and getattr(resp, 'status_code', None) == 429:
                return None
                
            return resp
        except Exception as e:
            logger.debug(f"[Network Raw] Exception {method} {url}: {e}")
            return None


    async def check_token_health(self, test_url: str = "") -> bool:
        """Verifica si el token sigue siendo valido y lo renueva si es necesario."""
        if not self.target:
            return True


        urls_to_probe = []
        if test_url and test_url.startswith("http"):

            urls_to_probe.append(test_url)
        else:
            for path in ["/api/me", "/api/health", "/health", "/api/status", "/api/v1/me"]:
                urls_to_probe.append(f"{self.target.rstrip('/')}{path}")

        for probe_url in urls_to_probe:
            try:
                resp = await self.send_request(probe_url, method="GET")
                if resp is None:
                    continue

                if resp.status_code in (200, 403):
                    logger.info(f" [Token Health] Token valido (verificado en {probe_url})")
                    return True

                elif resp.status_code == 401:
                    logger.critical(f" [Token Health] Token EXPIRADO (401 en {probe_url})")
                    if self.auth_refresh_fn:
                        logger.info(" [Token Health] Ejecutando auto-refresh...")
                        new_token = self.auth_refresh_fn()
                        if new_token:
                            new_token = new_token.strip()
                            self.options["auth_token"] = new_token
                            self.base_headers["Authorization"] = f"Bearer {new_token}"

                            for s in self.session_pool:
                                try:
                                    s.headers["Authorization"] = f"Bearer {new_token}"
                                except Exception:
                                    pass
                            logger.info(f"\U0001f511 [Token] Renovado: {new_token[:30]}...")
                            self.auth_401_count = 0
                            return True
                        else:
                            logger.error(" [Token Health] Refresh fallido — no se obtuvo token nuevo")
                    return False

            except Exception as e:
                logger.debug(f"[Token Health] Error probando {probe_url}: {e}")
                continue


        logger.warning("[Token Health] No se pudo verificar. Asumiendo token valido.")
        return True
