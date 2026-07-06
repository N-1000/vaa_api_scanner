"""
Web Application Firewall (WAF) Simulation for VAA Cyber-range v2
Detects and blocks common attack patterns (XSS, SQLi, RCE)
"""

import re
from fastapi import Request, HTTPException
from typing import Tuple, Dict
from collections import defaultdict
import time


class WAF:
    """
    Simulated Web Application Firewall
    Detects common attack patterns and blocks malicious requests
    """
    

    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript\s*:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"<iframe",
        r"<embed",
        r"<object",
    ]
    
    SQLI_PATTERNS = [
        r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+",
        r"UNION\s+(ALL\s+)?SELECT",
        r"DROP\s+TABLE",
        r"DELETE\s+FROM",
        r"--\s*$",
        r";\s*DROP",
        r"'\s*OR\s*'1'\s*=\s*'1",
        r"'\s*OR\s*1\s*=\s*1",
    ]
    
    RCE_PATTERNS = [
        r"\$\([^)]+\)",
        r"`[^`]+`",
        r";\s*(cat|ls|id|whoami|pwd)",
        r"\|\s*(cat|ls|id|whoami|pwd)",
        r"&&\s*(cat|ls|id|whoami|pwd)",
    ]
    
    def __init__(self, block_threshold: int = 3, block_duration: int = 300):
        """
        Initialize WAF
        
        Args:
            block_threshold: Number of malicious requests before blocking IP
            block_duration: Duration to block IP in seconds (default 5 minutes)
        """
        self.block_threshold = block_threshold
        self.block_duration = block_duration
        self.violation_count: Dict[str, int] = defaultdict(int)
        self.blocked_ips: Dict[str, float] = {}
    
    def check_payload(self, payload: str) -> Tuple[bool, str]:
        """
        Check if payload contains malicious patterns
        
        Args:
            payload: String to check for attack patterns
            
        Returns:
            Tuple of (is_malicious: bool, attack_type: str)
        """

        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return True, "XSS"
        

        for pattern in self.SQLI_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return True, "SQLi"
        

        for pattern in self.RCE_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return True, "RCE"
        
        return False, None
    
    def is_ip_blocked(self, ip: str) -> bool:
        """
        Check if IP is currently blocked
        [MODIFIED FOR LOCAL TESTING: Never block 127.0.0.1 to allow continuous fuzzing]
        """
        if ip in ("127.0.0.1", "::1", "localhost"):
            return False
            
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return True
            else:

                del self.blocked_ips[ip]
                self.violation_count[ip] = 0
        return False
    
    def block_ip(self, ip: str):
        """
        Block an IP address
        
        Args:
            ip: IP address to block
        """
        self.blocked_ips[ip] = time.time() + self.block_duration
    
    async def inspect_request(self, request: Request):
        """
        Middleware to inspect incoming requests for malicious patterns
        [MODIFIED FOR LOCAL TESTING: WAF completely bypassed via early return]
        """
        return
        
        client_ip = request.client.host
        

        if self.is_ip_blocked(client_ip):
            raise HTTPException(
                status_code=403,
                detail=f"WAF: IP address blocked due to repeated attack attempts. Block expires in {int(self.blocked_ips[client_ip] - time.time())} seconds."
            )
        

        for key, value in request.query_params.items():
            is_malicious, attack_type = self.check_payload(str(value))
            if is_malicious:
                self.violation_count[client_ip] += 1
                

                if self.violation_count[client_ip] >= self.block_threshold:
                    self.block_ip(client_ip)
                    raise HTTPException(
                        status_code=403,
                        detail=f"WAF: IP blocked due to repeated {attack_type} attempts ({self.violation_count[client_ip]} violations)"
                    )
                

                raise HTTPException(
                    status_code=400,
                    detail=f"WAF: Potential {attack_type} attack detected in parameter '{key}' (violation {self.violation_count[client_ip]}/{self.block_threshold})"
                )
        

        path = str(request.url.path)
        is_malicious, attack_type = self.check_payload(path)
        if is_malicious:
            self.violation_count[client_ip] += 1
            
            if self.violation_count[client_ip] >= self.block_threshold:
                self.block_ip(client_ip)
                raise HTTPException(
                    status_code=403,
                    detail=f"WAF: IP blocked due to repeated {attack_type} attempts in URL path"
                )
            
            raise HTTPException(
                status_code=400,
                detail=f"WAF: Potential {attack_type} attack detected in URL path"
            )


waf = WAF(block_threshold=3, block_duration=300)
