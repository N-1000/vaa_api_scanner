
"""
Modulo M5.2: Ghost Protocol (WAF Evasion Engine 2026)
Responsable de:
1. Evasion de Identidad (IP Spoofing, JA3, User-Agent Rotation).
2. Evasion de WAF (Cloudflare/AWS/Akamai) mediante tecnicas de fragmentacion y ofuscacion.
3. Regulacion de Velocidad (Adaptive Throttling).
"""

import random
import logging
from typing import Dict

logger = logging.getLogger("vaa.m5")

class M5GhostProtocol:

    IP_SPOOF_PROBABILITY      = 0.70
    URL_ENCODE_PROBABILITY    = 0.15
    SVG_EVASION_PROBABILITY   = 0.50
    BODY_PADDING_PROBABILITY  = 0.20

    _PROFILE_ROTATION = ["cloudflare", "akamai", "nginx", "generic"]

    def __init__(self, options: dict):
        self.options = options
        self.enabled = options.get("stealth", False) or options.get("ghost", False) or options.get("waf", False)
        self.waf_profile = options.get("waf_profile", "auto")
        self._profile_index: int = 0
        self._active_profile: str = self.waf_profile if self.waf_profile != "auto" else "generic"

        if self.enabled:
            logger.info(f">>> M5.2 GHOST PROTOCOL ACTIVADO (Profile: {self.waf_profile}) <<<")


        self.spoof_headers = [
            "X-Forwarded-For", "X-Originating-IP", "X-Remote-IP", 
            "X-Remote-Addr", "X-Client-IP", "X-ProxyUser-Ip", 
            "X-Host", "True-Client-IP", "X-Custom-IP-Authorization"
        ]
        
        self.trusted_ips = [
            "127.0.0.1", "localhost", "192.168.0.1", "10.0.0.1",
            "66.249.66.1",
            "103.21.244.0"
        ]
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
        ]

    def get_stealth_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Genera cabeceras de sigilo y evasion.
        """
        headers = custom_headers.copy() if custom_headers else {}
        
        if not self.enabled:
            if "User-Agent" not in headers:
                headers["User-Agent"] = "VAA-Scanner/6.0"
            return headers


        if "User-Agent" not in headers:
            headers["User-Agent"] = random.choice(self.user_agents)


        if random.random() < self.IP_SPOOF_PROBABILITY:
            spoof_hdr = random.choice(self.spoof_headers)
            fake_ip = random.choice(self.trusted_ips)


            headers[spoof_hdr] = fake_ip


        if self.waf_profile == "akamai":

            headers["Pragma"] = "no-cache"

            headers["Akamai-Origin-Hop"] = str(random.randint(1, 5))
            
        elif self.waf_profile == "cloudflare":

            headers["CF-Connecting-IP"] = "127.0.0.1"

        return headers

    @property
    def active_profile(self) -> str:
        return self._active_profile

    def activate(self) -> None:
        """Activa el protocolo desde el exterior (ej. NetworkManager en modo adaptativo)."""
        if not self.enabled:
            self.enabled = True
            logger.info(f">>> M5.2 GHOST PROTOCOL ACTIVADO ADAPTATIVAMENTE (Profile: {self._active_profile}) <<<")

    def get_next_profile(self) -> str:
        """
        Rota al siguiente perfil WAF cuando la evasion actual falla.
        Ciclo: cloudflare -> akamai -> nginx -> generic -> cloudflare ...
        """
        self._profile_index = (self._profile_index + 1) % len(self._PROFILE_ROTATION)
        self._active_profile = self._PROFILE_ROTATION[self._profile_index]
        self.waf_profile = self._active_profile
        logger.info(f"[M5] Rotando perfil WAF → {self._active_profile}")
        return self._active_profile

    def apply_waf_evasion_to_payload(self, payload: str, context: str = "url") -> str:
        """
        Transforma el payload usando tecnicas especificas del WAF detectado.
        [M-02 RESOLVED] Usa la implementacion unificada de app.utils.waf_evasion.
        """
        if not self.enabled: return payload

        from app.utils.waf_evasion import apply_waf_evasion  # pyre-ignore[21]
        return apply_waf_evasion(payload, self.waf_profile, context)
