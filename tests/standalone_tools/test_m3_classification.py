"""
Fase 3: Test Suite de M3 — JWT Auditor & Clasificación Heurística
==================================================================
Cubre:
  - JWTAuditor: detección de token válido vs. inválido
  - Generación de tokens de ataque (alg_none, empty_sig, claim_escalation)
  - Brute-force LOCAL de secreto débil (sin red)
  - _parse_jwt y _build_token (utilidades de codec)
  - extract_jwt helper
  - Integridad de hallazgos (_make_finding)
  - Compatibilidad de payloads time-based con lógica de M3
    (verifica que 'SLEEP' esté disponible en el arsenal M2 que M3 consumiría)
  - Distinción True Positive vs. False Positive (baseline 401 guard)
  - Auditoria activa async con mock de cliente (sin red real)
"""

import base64
import hashlib
import hmac
import json
import pytest
from typing import Optional, Any
from unittest.mock import AsyncMock, MagicMock, patch


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padded = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _build_real_token(header: dict, payload: dict, secret: str, alg: str = "HS256") -> str:
    """Construye un JWT firmado con HMAC-SHA256 real."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _build_unsigned_token(header: dict, payload: dict) -> str:
    """Token sin firma (para probar alg_none)."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


SAMPLE_HEADER = {"alg": "HS256", "typ": "JWT"}
SAMPLE_PAYLOAD = {"sub": "42", "role": "user", "iat": 1700000000}
VALID_TOKEN = _build_real_token(SAMPLE_HEADER, SAMPLE_PAYLOAD, secret="supersecret")
WEAK_SECRET_TOKEN = _build_real_token(SAMPLE_HEADER, SAMPLE_PAYLOAD, secret="secret")
MALFORMED_TOKEN = "not.a.valid.jwt.at.all.extra"
NOT_JWT_STR = "Bearer just_an_opaque_token"


@pytest.fixture
def auditor_valid():
    from app.core.m_jwt_audit import JWTAuditor
    return JWTAuditor(VALID_TOKEN)


@pytest.fixture
def auditor_weak():
    from app.core.m_jwt_audit import JWTAuditor
    return JWTAuditor(WEAK_SECRET_TOKEN)


@pytest.fixture
def auditor_opaque():
    from app.core.m_jwt_audit import JWTAuditor
    return JWTAuditor(NOT_JWT_STR)


class TestJWTDetection:

    def test_valid_jwt_enables_auditor(self, auditor_valid):
        assert auditor_valid.enabled is True, \
            "Un JWT bien formado debe habilitar el auditor"

    def test_opaque_token_disables_auditor(self, auditor_opaque):
        assert auditor_opaque.enabled is False, \
            "Un token no-JWT debe deshabilitar el auditor"

    def test_generate_attacks_empty_when_disabled(self, auditor_opaque):
        attacks = auditor_opaque.generate_attack_tokens()
        assert attacks == []

    def test_header_parsed_correctly(self, auditor_valid):
        assert auditor_valid.header["alg"] == "HS256"
        assert auditor_valid.header["typ"] == "JWT"

    def test_payload_parsed_correctly(self, auditor_valid):
        assert auditor_valid.payload["sub"] == "42"
        assert auditor_valid.payload["role"] == "user"


class TestExtractJWT:

    def test_extracts_from_bearer_header(self):
        from app.core.m_jwt_audit import extract_jwt
        result = extract_jwt(f"Bearer {VALID_TOKEN}")
        assert result == VALID_TOKEN

    def test_extracts_raw_token(self):
        from app.core.m_jwt_audit import extract_jwt
        result = extract_jwt(VALID_TOKEN)
        assert result == VALID_TOKEN

    def test_returns_none_for_opaque(self):
        from app.core.m_jwt_audit import extract_jwt
        result = extract_jwt("Bearer opaque_token_without_dots")
        assert result is None

    def test_returns_none_for_empty(self):
        from app.core.m_jwt_audit import extract_jwt
        result = extract_jwt("")
        assert result is None


class TestAttackTokenGeneration:

    def test_alg_none_attack_generated(self, auditor_valid):
        attacks = auditor_valid.generate_attack_tokens()
        alg_none_attacks = [a for a in attacks if a["name"] == "alg_none"]
        assert len(alg_none_attacks) == 1, "Ataque alg_none no fue generado"

    def test_alg_none_token_has_no_sig(self, auditor_valid):
        attacks = auditor_valid.generate_attack_tokens()
        alg_none = next(a for a in attacks if a["name"] == "alg_none")
        token_parts = alg_none["token"].split(".")
        assert len(token_parts) == 3
        assert token_parts[2] == "", "alg_none debe tener firma vacía"

    def test_alg_none_header_modified(self, auditor_valid):
        """El header del token alg_none debe tener alg='none'."""
        attacks = auditor_valid.generate_attack_tokens()
        alg_none = next(a for a in attacks if a["name"] == "alg_none")
        raw_header = alg_none["token"].split(".")[0]
        header = json.loads(_b64url_decode(raw_header))
        assert header["alg"] == "none"

    def test_empty_signature_attack_generated(self, auditor_valid):
        attacks = auditor_valid.generate_attack_tokens()
        empty_sig_attacks = [a for a in attacks if a["name"] == "empty_signature"]
        assert len(empty_sig_attacks) == 1

    def test_empty_signature_preserves_original_header(self, auditor_valid):
        """empty_signature debe mantener el alg original (HS256), solo borrar la firma."""
        attacks = auditor_valid.generate_attack_tokens()
        es = next(a for a in attacks if a["name"] == "empty_signature")
        raw_header = es["token"].split(".")[0]
        header = json.loads(_b64url_decode(raw_header))
        assert header["alg"] == "HS256", \
            "empty_signature no debe modificar el alg del header"
        assert es["token"].endswith("."), "Firma debe ser string vacío (trailing dot)"

    def test_claim_escalation_attacks_generated(self, auditor_valid):
        attacks = auditor_valid.generate_attack_tokens()
        escalation = [a for a in attacks if "claim_escalation" in a["name"]]
        assert len(escalation) >= 3, \
            f"Se esperaban ≥3 ataques de escalación, se obtuvieron {len(escalation)}"

    def test_claim_escalation_modifies_payload(self, auditor_valid):
        attacks = auditor_valid.generate_attack_tokens()

        role_attack = next(
            (a for a in attacks if "claim_escalation_role" in a["name"]), None
        )
        assert role_attack is not None
        raw_payload = role_attack["token"].split(".")[1]
        payload = json.loads(_b64url_decode(raw_payload))
        assert payload.get("role") in ("admin", "administrator"), \
            f"El claim 'role' no fue escalado correctamente: {payload.get('role')}"

    def test_claim_escalation_preserves_original_claims(self, auditor_valid):
        """Claims originales (sub) deben mantenerse en el token escalado."""
        attacks = auditor_valid.generate_attack_tokens()
        role_attack = next(
            (a for a in attacks if "claim_escalation_role" in a["name"]), None
        )
        assert role_attack is not None
        raw_payload = role_attack["token"].split(".")[1]
        payload = json.loads(_b64url_decode(raw_payload))
        assert payload.get("sub") == "42", "El claim 'sub' original fue borrado"

    def test_all_attacks_have_description(self, auditor_valid):
        attacks = auditor_valid.generate_attack_tokens()
        for attack in attacks:
            assert "description" in attack and len(attack["description"]) > 0

    def test_all_attacks_have_type_suffix(self, auditor_valid):
        attacks = auditor_valid.generate_attack_tokens()
        for attack in attacks:
            assert "type_suffix" in attack


class TestWeakSecretBruteForce:

    def test_detects_known_weak_secret(self, auditor_weak):
        """El token firmado con 'secret' debe ser detectado por brute-force local."""
        result = auditor_weak._check_weak_secret()
        assert result is not None, \
            "Secreto débil 'secret' no fue detectado — revisar WEAK_SECRETS list"
        assert result["weak_secret"] is True
        assert result["secret"] == "secret"

    def test_strong_secret_returns_none(self, auditor_valid):
        """Token firmado con 'supersecret' — no debe aparecer en la wordlist."""

        from app.core.m_jwt_audit import JWTAuditor
        strong_token = _build_real_token(
            SAMPLE_HEADER, SAMPLE_PAYLOAD, secret="xK9!@#QmZ2Lp7vR"
        )
        auditor = JWTAuditor(strong_token)
        result = auditor._check_weak_secret()
        assert result is None, "Un secreto fuerte no debe ser encontrado por brute-force"

    def test_non_hmac_skips_bruteforce(self):
        """Tokens con alg RS256 deben retornar None — no son vulnerables a BF local."""
        from app.core.m_jwt_audit import JWTAuditor
        rsa_header = {"alg": "RS256", "typ": "JWT"}

        h = _b64url_encode(json.dumps(rsa_header, separators=(",", ":")).encode())
        p = _b64url_encode(json.dumps(SAMPLE_PAYLOAD, separators=(",", ":")).encode())
        token = f"{h}.{p}.fakesignature"
        auditor = JWTAuditor(token)
        result = auditor._check_weak_secret()
        assert result is None

    def test_weak_secret_included_in_generate_attacks(self, auditor_weak):
        """Si el secreto es débil, generate_attack_tokens() debe incluir ese hallazgo."""
        attacks = auditor_weak.generate_attack_tokens()
        weak_findings = [a for a in attacks if a.get("weak_secret")]
        assert len(weak_findings) == 1


class TestMakeFinding:

    def test_finding_structure(self, auditor_valid):
        from app.core.m_jwt_audit import JWTAuditor
        attacks = auditor_valid.generate_attack_tokens()
        alg_none = next(a for a in attacks if a["name"] == "alg_none")
        finding = JWTAuditor._make_finding(
            "http://target.com/api/profile", alg_none
        )
        required_keys = [
            "url", "norm_url", "type", "method", "payload",
            "risk", "confidence", "verified", "validation_method",
            "report_policy", "params", "is_json", "response_text",
            "ai_razonamiento", "ai_remediacion"
        ]
        for key in required_keys:
            assert key in finding, f"Clave '{key}' ausente en el hallazgo"

    def test_finding_risk_is_critical(self, auditor_valid):
        from app.core.m_jwt_audit import JWTAuditor
        attacks = auditor_valid.generate_attack_tokens()
        alg_none = next(a for a in attacks if a["name"] == "alg_none")
        finding = JWTAuditor._make_finding("http://t.com/api", alg_none)
        assert finding["risk"] == "Critical"

    def test_finding_confidence_is_1(self, auditor_valid):
        from app.core.m_jwt_audit import JWTAuditor
        attacks = auditor_valid.generate_attack_tokens()
        a = attacks[0]
        finding = JWTAuditor._make_finding("http://t.com/api", a)
        assert finding["confidence"] == 1.0

    def test_weak_secret_finding_payload_is_local_bruteforce(self, auditor_weak):
        from app.core.m_jwt_audit import JWTAuditor
        result = auditor_weak._check_weak_secret()
        assert result is not None
        finding = JWTAuditor._make_finding("http://t.com/api", result)
        assert finding["payload"] == "local_bruteforce"


@pytest.mark.asyncio
class TestJWTAuditAsync:

    async def test_no_findings_when_baseline_200(self, auditor_valid):
        """Si baseline devuelve 200 (endpoint público), no se audita — lista vacía."""
        mock_client = AsyncMock()
        baseline_resp = MagicMock()
        baseline_resp.status_code = 200
        mock_client.send_request = AsyncMock(return_value=baseline_resp)

        findings = await auditor_valid.audit(
            "http://target.com", "/api/profile", mock_client
        )
        assert findings == [], \
            "No debe haber hallazgos si el endpoint no requiere auth (baseline 200)"

    async def test_findings_when_attack_returns_200(self, auditor_valid):
        """Si baseline=401 y ataque devuelve 200 → hallazgo confirmado."""
        mock_client = AsyncMock()

        baseline_resp = MagicMock()
        baseline_resp.status_code = 401

        attack_resp = MagicMock()
        attack_resp.status_code = 200
        attack_resp.text = '{"user": "admin", "role": "admin"}'


        mock_client.send_request = AsyncMock(side_effect=[baseline_resp] + [attack_resp] * 20)

        findings = await auditor_valid.audit(
            "http://target.com", "/api/profile", mock_client
        )
        assert len(findings) > 0, \
            "Debe haber hallazgos cuando el servidor acepta tokens manipulados"

    async def test_findings_when_baseline_403(self, auditor_valid):
        """403 también es baseline válido (endpoint detrás de auth)."""
        mock_client = AsyncMock()

        baseline_resp = MagicMock()
        baseline_resp.status_code = 403

        attack_resp = MagicMock()
        attack_resp.status_code = 200
        attack_resp.text = "OK"

        mock_client.send_request = AsyncMock(side_effect=[baseline_resp] + [attack_resp] * 20)

        findings = await auditor_valid.audit(
            "http://target.com", "/api/admin", mock_client
        )
        assert len(findings) > 0

    async def test_disabled_auditor_returns_empty(self, auditor_opaque):
        """Si el auditor está deshabilitado (token no-JWT), audit() debe retornar []."""
        mock_client = AsyncMock()
        findings = await auditor_opaque.audit(
            "http://target.com", "/api/profile", mock_client
        )
        assert findings == []

        mock_client.send_request.assert_not_called()

    async def test_network_error_handled_gracefully(self, auditor_valid):
        """Si el baseline falla con excepción, se devuelve [] sin crash."""
        mock_client = AsyncMock()
        mock_client.send_request = AsyncMock(side_effect=Exception("Connection refused"))

        findings = await auditor_valid.audit(
            "http://target.com", "/api/profile", mock_client
        )
        assert findings == []

    async def test_weak_secret_reported_without_extra_request(self, auditor_weak):
        """
        Secreto débil → hallazgo directo.
        El auditor no debe hacer request extra para confirmar weak_secret.
        Solo el baseline y los ataques NO-weak_secret hacen requests.
        """
        from app.core.m_jwt_audit import JWTAuditor
        mock_client = AsyncMock()

        baseline_resp = MagicMock()
        baseline_resp.status_code = 401


        generic_resp = MagicMock()
        generic_resp.status_code = 403
        generic_resp.text = "Forbidden"

        mock_client.send_request = AsyncMock(side_effect=[baseline_resp] + [generic_resp] * 20)

        findings = await auditor_weak.audit(
            "http://target.com", "/api/profile", mock_client
        )
        weak_findings = [f for f in findings if "weak_secret" in f["validation_method"]]
        assert len(weak_findings) == 1, \
            "El secreto débil debe reportarse incluso si el servidor rechaza los otros tokens"


class TestTimeBased_M2_M3_Integration:
    """
    Valida que el arsenal M2 tenga los payloads time-based que M3 necesita
    para confirmar SQL Injection ciega por tiempo (SLEEP/WAITFOR).
    No ejecuta requests reales — solo verifica que los vectores estén cargados.
    """

    @pytest.fixture(scope="class")
    def m2(self):
        from app.core.m2_generation import M2AdaptiveGenerator
        return M2AdaptiveGenerator()

    def test_time_based_payloads_loaded_in_m2(self, m2):
        """M2 debe tener payloads SLEEP/WAITFOR listos para M3."""
        time_payloads = m2.sqli_templates["blind_time_based"]
        assert len(time_payloads) > 0, \
            "M2 tiene blind_time_based vacío — M3 no puede ejecutar Time-Based SQLi"

    def test_sleep_payloads_present(self, m2):
        time_payloads = m2.sqli_templates["blind_time_based"]
        sleep_payloads = [p for p in time_payloads if "SLEEP" in p.upper()]
        assert len(sleep_payloads) >= 3, \
            f"Pocos payloads SLEEP (esperado ≥3, encontrado {len(sleep_payloads)})"

    def test_waitfor_payloads_present(self, m2):
        """WAITFOR DELAY para SQL Server debe estar presente (cobertura multi-DB)."""
        time_payloads = m2.sqli_templates["blind_time_based"]
        waitfor = [p for p in time_payloads if "WAITFOR" in p.upper()]
        assert len(waitfor) >= 1, \
            "No hay payloads WAITFOR DELAY — cobertura SQL Server ausente"

    def test_pg_sleep_payloads_present(self, m2):
        """pg_sleep para PostgreSQL debe estar presente."""
        time_payloads = m2.sqli_templates["blind_time_based"]
        pg = [p for p in time_payloads if "pg_sleep" in p.lower()]
        assert len(pg) >= 1, \
            "No hay payloads pg_sleep — cobertura PostgreSQL ausente"

    def test_time_based_suite_via_iter(self, m2):
        """
        iter_payload_suite con vuln_type='sqli' debe emitir al menos 1 payload
        que podría ser time-based (del arsenal cargado).
        """
        ctx = {"/api/login": {"seen_params": {}}}
        payloads = list(m2.iter_payload_suite(ctx, "/api/login", "sqli", max_payloads=20))
        assert len(payloads) > 0

    def test_verification_pairs_true_false_distinguishable(self, m2):
        """
        Los pares de verificación True/False para SQLi deben ser distinguibles
        (longitud diferente o contenido diferente) — permite a M3 detectar booleanos.
        """
        pairs = m2.get_verification_pairs("sqli")
        for pair in pairs:
            assert pair["true"] != pair["false"], \
                f"Par '{pair['name']}' tiene true==false — M3 no puede distinguirlos"
