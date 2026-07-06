"""
VAA — Constantes de Tipos de Vulnerabilidad.

Fuente única de verdad para los strings de tipos de vuln.
Usar estas constantes evita typos silenciosos que rompen la detección.

Uso:
    from app.core.engine.vuln_types import VulnType
    if vuln_type == VulnType.SQLI: ...
"""

from typing import FrozenSet


class VulnType:
    SQLI             = "sqli"
    XSS              = "xss"
    SSRF             = "ssrf"
    RCE              = "rce"
    PROMPT_INJECTION = "prompt_injection"
    AI_INJECTION     = "ai_injection"
    MASS_ASSIGNMENT  = "mass_assignment"
    BOLA             = "bola"
    BFLA             = "bfla"
    IDOR             = "idor"
    JWT              = "jwt"
    EXPOSED_DOCS     = "exposed_documentation"
    MISSING_HEADERS  = "missing_security_headers"


    RCE_GROUP: FrozenSet[str]            = frozenset({"rce", "command_injection", "cmd"})
    PROMPT_GROUP: FrozenSet[str]         = frozenset({"prompt_injection", "ai_injection",
                                                       "prompt injection", "ai injection"})
    SQLI_GROUP: FrozenSet[str]           = frozenset({"sqli", "sql_injection", "sql injection"})
    XSS_GROUP: FrozenSet[str]            = frozenset({"xss", "cross-site scripting",
                                                       "cross_site_scripting"})
    SSRF_GROUP: FrozenSet[str]           = frozenset({"ssrf", "server-side request forgery"})
    MASS_ASSIGNMENT_GROUP: FrozenSet[str]= frozenset({"mass_assignment", "mass assignment"})

    @classmethod
    def matches(cls, vuln_type: str, group: FrozenSet[str]) -> bool:
        """Verifica si vuln_type pertenece a un grupo, case-insensitive."""
        return vuln_type.lower() in group or any(g in vuln_type.lower() for g in group)
