import asyncio
from typing import List
from app.utils.logger import logger  # pyre-ignore[21]


class M9ParameterDiscovery:
    """
    Descubre parametros ocultos en endpoints API.
    [v4.0.0] Conectado a engine.phase_fuzzing_attack.
    Delega todo HTTP a NetworkManager.send_request() — hereda JA3 fingerprinting,
    Circuit Breaker, session pooling y proxy sin codigo adicional.
    """


    CONTENT_DELTA_THRESHOLD = 20


    _PROBE_CONCURRENCY = 5

    def __init__(self):
        self.common_params = [
            "id", "user_id", "admin", "debug", "test", "q", "search",
            "query", "file", "path", "url", "callback", "redirect",
            "target", "ip", "host", "hostname", "domain",
            "cmd", "exec", "command", "token", "auth", "key", "password",
            "username", "email", "role", "type", "category", "view",
            "page", "limit", "offset", "sort", "order", "filter",
            "lang", "locale", "version", "api", "apikey", "secret",
            "access_token", "session", "session_id", "data", "payload"
        ]


        self.probe_values = ["true", "1", "debug", "vz99"]

    async def discover_params(
        self,
        network_manager,
        endpoint: str,
        method: str = "GET",
        token_health_check=None
    ) -> List[str]:
        """
        Intenta descubrir parametros ocultos enviando peticiones con parametros comunes.
        Retorna lista de parametros que causaron un cambio de status code o tamano.

        [v4.0.0] Usa NetworkManager.send_request() directamente en lugar de
        gestionar su propio httpx.AsyncClient. Esto elimina la incompatibilidad de
        interfaz con curl_cffi.AsyncSession y hereda todo el stack de red del engine.
        [v4.0.0] Ejecuta todos los probes en paralelo (Semaphore=_PROBE_CONCURRENCY).
        """

        async with network_manager.create_client() as base_client:
            base_resp = await network_manager.send_request(endpoint, method=method)
        
        if base_resp and base_resp.status_code == 401 and token_health_check:
            logger.warning(f"[M9] Token expirado en baseline de {endpoint}. Intentando refresh...")
            if await token_health_check(endpoint):
                async with network_manager.create_client() as base_client:
                    base_resp = await network_manager.send_request(endpoint, method=method)

        if base_resp is None:
            logger.debug(f"[M9] Baseline fallido para {endpoint} — abortando discovery.")
            return []

        try:
            base_len = len(base_resp.content)  # pyre-ignore[16]
            base_code = base_resp.status_code  # pyre-ignore[16]
        except Exception:
            return []

        semaphore = asyncio.Semaphore(self._PROBE_CONCURRENCY)
        _endpoint_blocked = [False]

        _status_change_count: dict = {}

        async def _probe_param(param: str):
            """Prueba un unico param contra todos probe_values. Retorna param si hay hit."""
            async with semaphore:
                none_streak = 0
                for test_val in self.probe_values:

                    if _endpoint_blocked[0]:
                        return None

                    try:
                        resp = await network_manager.send_request(
                            endpoint, 
                            method=method, 
                            payload={param: test_val},
                            json_body=(method in ["POST", "PUT", "PATCH"])
                        )
                        if resp is None:

                            none_streak += 1
                            if none_streak >= 2:
                                logger.debug(f"[M9] Endpoint rate-limited detectado — abortando discovery en {endpoint}")
                                _endpoint_blocked[0] = True
                                return None
                            continue

                        none_streak = 0

                        if resp.status_code != base_code:  # pyre-ignore[16]
                            new_code = resp.status_code  # pyre-ignore[16]


                            if base_code == 200 and new_code == 401:

                                continue
                            logger.info(
                                f"[M9] Hidden Param: '{param}' "
                                f"(Status Change: {base_code}->{new_code})"  # pyre-ignore[16]
                            )
                            _status_change_count[new_code] = _status_change_count.get(new_code, 0) + 1
                            return param

                        delta = abs(len(resp.content) - base_len)  # pyre-ignore[16]
                        if delta > self.CONTENT_DELTA_THRESHOLD:


                            reflection_threshold = len(test_val) * 2
                            if delta <= reflection_threshold:
                                continue
                            logger.info(
                                f"[M9] Hidden Param: '{param}' "
                                f"(Length Delta: {delta}B > {self.CONTENT_DELTA_THRESHOLD}B, "
                                f"no proporcional al valor enviado [{len(test_val)}B])"
                            )
                            return param

                    except Exception:
                        pass
            return None


        results = await asyncio.gather(
            *[_probe_param(p) for p in self.common_params],
            return_exceptions=True
        )

        return [r for r in results if isinstance(r, str)]
