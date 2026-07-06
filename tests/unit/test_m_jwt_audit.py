import pytest
import json
import base64
import hmac
import hashlib
from unittest.mock import AsyncMock, MagicMock
from app.core.m_jwt_audit import JWTAuditor, _b64url_encode

def generate_valid_jwt(secret="secret"):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user_id": 123, "role": "user"}
    
    h_b64 = _b64url_encode(json.dumps(header).encode())
    p_b64 = _b64url_encode(json.dumps(payload).encode())
    
    signing_input = f"{h_b64}.{p_b64}".encode()
    signature = _b64url_encode(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    
    return f"{h_b64}.{p_b64}.{signature}"

@pytest.fixture
def jwt_auditor():
    token = generate_valid_jwt()
    return JWTAuditor(token)

def test_jwt_parsing(jwt_auditor):
    assert jwt_auditor.enabled is True
    assert jwt_auditor.header["alg"] == "HS256"
    assert jwt_auditor.payload["role"] == "user"

def test_jwt_parsing_invalid():
    auditor = JWTAuditor("not.a.token")
    assert auditor.enabled is False

def test_attack_alg_none(jwt_auditor):
    attack = jwt_auditor._attack_alg_none()
    assert "alg_none" in attack["name"]
    token = attack["token"]
    
    h, p, s = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(h + "==").decode())
    assert header["alg"] == "none"
    assert s == ""

def test_attack_empty_signature(jwt_auditor):
    attack = jwt_auditor._attack_empty_signature()
    assert "empty_signature" in attack["name"]
    h, p, s = attack["token"].split(".")
    assert s == ""

def test_attacks_claim_escalation(jwt_auditor):
    attacks = jwt_auditor._attacks_claim_escalation()

    found_admin = False
    for att in attacks:
        h, p, s = att["token"].split(".")
        payload = json.loads(base64.urlsafe_b64decode(p + "==").decode())
        if payload.get("role") == "admin":
            found_admin = True
    assert found_admin

def test_check_weak_secret(jwt_auditor):

    weak = jwt_auditor._check_weak_secret()
    assert weak is not None
    assert weak["secret"] == "secret"
    assert weak["weak_secret"] is True

def test_check_strong_secret():

    token = generate_valid_jwt("this_is_a_very_strong_and_long_secret_1234567890")
    auditor = JWTAuditor(token)
    weak = auditor._check_weak_secret()
    assert weak is None

@pytest.mark.asyncio
async def test_audit_active_vuln(jwt_auditor):
    mock_client = AsyncMock()
    

    resp_401 = MagicMock(status_code=401)

    resp_200 = MagicMock(status_code=200, text="success")
    

    async def mock_get(url, **kwargs):
        if "Authorization" not in kwargs.get("custom_headers", {}):
            return resp_401
        return resp_200
        
    mock_client.send_request.side_effect = mock_get
    
    findings = await jwt_auditor.audit("http://api.com", "/protected", mock_client)
    
    assert len(findings) > 0

    assert any(f["type"].endswith("weak_secret)") for f in findings)

    assert any(f["type"].endswith("alg_none)") for f in findings)

@pytest.mark.asyncio
async def test_audit_baseline_fails(jwt_auditor):
    mock_client = AsyncMock()

    resp_200 = MagicMock(status_code=200)
    mock_client.send_request.return_value = resp_200
    
    findings = await jwt_auditor.audit("http://api.com", "/protected", mock_client)

    assert len(findings) == 0
