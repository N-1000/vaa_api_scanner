import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.core.m6_doppelganger import M6Doppelganger

@pytest.fixture
def m6():
    return M6Doppelganger()


# ─── ingest_sessions ──────────────────────────────────────────────────────────

def test_ingest_sessions_basic(m6):
    traffic_a = [{"path": "/api/users/1", "method": "GET", "url": "http://api.com/api/users/1"}]
    traffic_b = [{"path": "/api/users/2", "method": "GET", "url": "http://api.com/api/users/2"}]
    m6.ingest_sessions(traffic_a, traffic_b)
    assert m6.session_a == traffic_a
    assert m6.session_b == traffic_b

def test_ingest_sessions_with_har(m6):
    har = {
        "log": {
            "entries": [
                {
                    "response": {
                        "content": {
                            "text": '{"id": 42, "email": "victim@test.com", "uuid": "11111111-2222-3333-4444-555555555555"}'
                        }
                    }
                }
            ]
        }
    }
    m6.ingest_sessions([], [], raw_har_a=har)
    assert "42" in m6._har_harvest["numeric_ids"]
    assert "victim@test.com" in m6._har_harvest["emails"]
    assert "11111111-2222-3333-4444-555555555555" in m6._har_harvest["uuids"]

def test_ingest_sessions_har_skips_empty_text(m6):
    har = {
        "log": {
            "entries": [
                {"response": {"content": {"text": ""}}}
            ]
        }
    }
    m6.ingest_sessions([], [], raw_har_a=har)
    assert m6._har_harvest["numeric_ids"] == []


# ─── _harvest_ids_from_har ────────────────────────────────────────────────────

def test_harvest_ids_from_har_invalid_input(m6):
    m6._harvest_ids_from_har({})  # no 'log' key — should not crash
    assert m6._har_harvest["uuids"] == []

def test_harvest_ids_from_har_order_ids(m6):
    har = {
        "log": {
            "entries": [
                {
                    "response": {
                        "content": {
                            "text": '{"orderId": "ORD-999", "id": 7}'
                        }
                    }
                }
            ]
        }
    }
    m6._harvest_ids_from_har(har)
    assert "ORD-999" in m6._har_harvest["order_ids"]
    assert "7" in m6._har_harvest["numeric_ids"]


# ─── _harvest_ids_from_burp ───────────────────────────────────────────────────

def test_harvest_ids_from_burp_basic(m6):
    burp = [
        {
            "url": "http://api.com/api/users/5",
            "response_text": '{"id": 5, "email": "burp@test.com", "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}'
        }
    ]
    m6._harvest_ids_from_burp(burp)
    assert "5" in m6._har_harvest["numeric_ids"]
    assert "burp@test.com" in m6._har_harvest["emails"]
    assert "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" in m6._har_harvest["uuids"]

def test_harvest_ids_from_burp_self_endpoint(m6):
    burp = [
        {
            "url": "http://api.com/me",
            "response_text": '{"id": 99, "uuid": "cccccccc-dddd-eeee-ffff-000000000000"}'
        }
    ]
    # Should still harvest (logs SELF tag but does not skip)
    m6._harvest_ids_from_burp(burp)
    assert "cccccccc-dddd-eeee-ffff-000000000000" in m6._har_harvest["uuids"]

def test_harvest_ids_from_burp_skips_short_text(m6):
    m6._harvest_ids_from_burp([{"url": "http://x.com", "response_text": "{}"}])
    assert m6._har_harvest["numeric_ids"] == []

def test_harvest_ids_from_burp_order_ids(m6):
    m6._harvest_ids_from_burp([{
        "url": "http://api.com/orders",
        "response_text": '{"orderId": "ORD-2025-001"}'
    }])
    assert "ORD-2025-001" in m6._har_harvest["order_ids"]


# ─── analyze_logic_diff ───────────────────────────────────────────────────────

def test_analyze_logic_diff_empty_sessions(m6):
    assert m6.analyze_logic_diff() == []

def test_analyze_logic_diff_uuid_idor(m6, monkeypatch):
    monkeypatch.setattr(m6, "get_structural_signature", lambda path: "/api/users/{UUID}")
    m6.session_a = [{"path": "/api/users/11111111-2222-3333-4444-555555555555", "url": "http://api.com/a"}]
    m6.session_b = [{"path": "/api/users/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "url": "http://api.com/b"}]
    plans = m6.analyze_logic_diff()
    assert len(plans) == 1
    assert plans[0]["type"] == "IDOR_UUID"
    assert plans[0]["victim_uuid"] == "11111111-2222-3333-4444-555555555555"

def test_analyze_logic_diff_int_idor(m6, monkeypatch):
    monkeypatch.setattr(m6, "get_structural_signature", lambda path: "/api/users/{ID}")
    m6.session_a = [{"path": "/api/users/5", "url": "http://api.com/5"}]
    m6.session_b = [{"path": "/api/users/10", "url": "http://api.com/10"}]
    plans = m6.analyze_logic_diff()
    assert len(plans) == 1
    assert plans[0]["type"] == "IDOR_INT"
    assert plans[0]["target_id"] == "9"

def test_analyze_logic_diff_same_path_skipped(m6, monkeypatch):
    """If session A and B hit the same URL, no IDOR should be generated."""
    monkeypatch.setattr(m6, "get_structural_signature", lambda path: "/api/users/{UUID}")
    shared = {"path": "/api/users/11111111-2222-3333-4444-555555555555", "url": "http://api.com/same"}
    m6.session_a = [shared]
    m6.session_b = [shared]
    plans = m6.analyze_logic_diff()
    assert plans == []


# ─── analyze_mass_assignment ──────────────────────────────────────────────────

def test_analyze_mass_assignment(m6, monkeypatch):
    monkeypatch.setattr("app.core.m6_doppelganger.settings.POWER_KEYS", ["is_admin"])
    session = [
        {"method": "GET", "url": "http://api.com", "headers": {}},
        {"method": "POST", "url": "http://api.com/update", "headers": {"Content-Type": "application/json"}}
    ]
    plans = m6.analyze_mass_assignment(session)
    assert len(plans) == 1
    assert plans[0]["method"] == "POST"
    assert "is_admin" in plans[0]["injection_keys"]

def test_analyze_mass_assignment_patch_put(m6, monkeypatch):
    monkeypatch.setattr("app.core.m6_doppelganger.settings.POWER_KEYS", ["role"])
    session = [
        {"method": "PATCH", "url": "http://api.com/profile", "headers": {}},
        {"method": "PUT",   "url": "http://api.com/user/1",  "headers": {}},
    ]
    plans = m6.analyze_mass_assignment(session)
    assert len(plans) == 2

def test_analyze_mass_assignment_empty_session(m6, monkeypatch):
    monkeypatch.setattr("app.core.m6_doppelganger.settings.POWER_KEYS", ["is_admin"])
    assert m6.analyze_mass_assignment([]) == []


# ─── generate_bac_tests ───────────────────────────────────────────────────────

def test_generate_bac_tests(m6):
    m6.session_a = [{"path": "/api/users", "method": "GET", "url": "http://api.com/api/users"}]
    m6.session_b = [
        {"path": "/api/users", "method": "GET", "url": "http://api.com/api/users"},
        {"path": "/login", "method": "POST", "url": "http://api.com/login"}
    ]
    tests = m6.generate_bac_tests()
    assert len(tests) == 1
    assert tests[0]["target_url"] == "http://api.com/api/users"

def test_generate_bac_tests_filters_auth_paths(m6):
    m6.session_a = [{"path": "/auth/token", "method": "POST", "url": "http://api.com/auth/token"}]
    m6.session_b = []
    tests = m6.generate_bac_tests()
    assert tests == []


# ─── analyze_idor_from_recon ──────────────────────────────────────────────────

def test_analyze_idor_from_recon_basic(m6):
    findings = [{
        "type": "Exploit Confirmed",
        "url": "http://api.com/users",
        "response_text": '{"id": 42, "email": "victim@example.com", "uuid": "11111111-2222-3333-4444-555555555555"}'
    }]
    plan = m6.analyze_idor_from_recon(findings, "http://api.com")
    assert len(plan) == 1
    assert plan[0]["int_ids"] == [42]
    assert plan[0]["emails"] == ["victim@example.com"]
    assert plan[0]["uuid_ids"] == ["11111111-2222-3333-4444-555555555555"]

def test_analyze_idor_from_recon_skips_non_exploit(m6):
    findings = [{"type": "Info", "url": "http://api.com/users", "response_text": '{"id": 1}'}]
    plan = m6.analyze_idor_from_recon(findings, "http://api.com")
    assert plan == []

def test_analyze_idor_from_recon_skips_no_ids(m6):
    findings = [{"type": "Exploit Confirmed", "url": "http://api.com/ping", "response_text": '{"status": "ok"}'}]
    plan = m6.analyze_idor_from_recon(findings, "http://api.com")
    assert plan == []

def test_analyze_idor_from_recon_with_recon_endpoints(m6):
    """Tests the structural recon path (param pattern expansion with harvest)."""
    findings = []
    recon_endpoints = [
        {"url": "http://api.com/users/{userId}", "path": "/users/{userId}", "method": "GET"}
    ]
    harvest = {"numeric_ids": ["10", "20"], "uuids": [], "order_ids": []}
    plan = m6.analyze_idor_from_recon(findings, "http://api.com", recon_endpoints=recon_endpoints, harvest=harvest)
    assert len(plan) == 1
    assert plan[0]["source"] == "structural_recon"
    assert 10 in plan[0]["int_ids"] or 20 in plan[0]["int_ids"]

def test_analyze_idor_from_recon_recon_skips_non_get(m6):
    """POST endpoints should be skipped in the structural recon path."""
    findings = []
    recon_endpoints = [
        {"url": "http://api.com/orders/{orderId}", "path": "/orders/{orderId}", "method": "POST"}
    ]
    harvest = {"numeric_ids": ["5"], "uuids": [], "order_ids": []}
    plan = m6.analyze_idor_from_recon(findings, "http://api.com", recon_endpoints=recon_endpoints, harvest=harvest)
    assert plan == []

def test_analyze_idor_from_recon_fallback_ids_when_no_uuids(m6):
    """If harvest has no UUIDs, fallback IDs (101, 102, etc.) should be used."""
    findings = []
    recon_endpoints = [
        {"url": "http://api.com/items/{id}", "path": "/items/{id}", "method": "GET"}
    ]
    harvest = {"numeric_ids": [], "uuids": [], "order_ids": []}
    plan = m6.analyze_idor_from_recon(findings, "http://api.com", recon_endpoints=recon_endpoints, harvest=harvest)
    assert len(plan) == 1
    assert 101 in plan[0]["int_ids"] or 102 in plan[0]["int_ids"]


# ─── execute_idor_attacks ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_execute_idor_attacks_approach1(m6):
    victim_resp    = MagicMock(status_code=200, text='{"id": 99}')
    attacker_resp  = MagicMock(status_code=200, text='{"id": 99, "data": "hacked"}')
    parametric_resp = MagicMock(status_code=404)
    mock_nm = MagicMock()
    mock_nm.verify_ssl = False
    mock_nm.send_request = AsyncMock(side_effect=[victim_resp, attacker_resp, parametric_resp])
    plan = [{"endpoint": "http://api.com/user"}]
    confirmed = await m6.execute_idor_attacks(attack_plan=plan, attacker_token="tkA", victim_token="tkV", network_manager=mock_nm)
    assert len(confirmed) == 1
    assert confirmed[0]["type"] == "IDOR_CONFIRMED (BOLA)"

@pytest.mark.asyncio
async def test_execute_idor_attacks_approach2(m6):
    mock_resp = MagicMock(status_code=200, text='{"new_data": "secret_guy"}')
    mock_nm = MagicMock()
    mock_nm.verify_ssl = False
    mock_nm.send_request = AsyncMock(return_value=mock_resp)
    plan = [{"endpoint": "http://api.com/user/10", "int_ids": [10], "attacker_response_text": '{"my_data": "me"}'}]
    confirmed = await m6.execute_idor_attacks(attack_plan=plan, attacker_token="tkA", victim_token=None, network_manager=mock_nm)
    assert len(confirmed) == 1
    assert "8" in confirmed[0]["url"]
    assert "IDOR_PROBABLE" in confirmed[0]["type"]

@pytest.mark.asyncio
async def test_execute_idor_attacks_no_change_response(m6):
    """If attacker response matches victim response, no IDOR should be confirmed."""
    victim_text = '{"id": 99}'
    attacker_text = '{"error": "Unauthorized"}'
    victim_resp   = MagicMock(status_code=200, text=victim_text)
    attacker_resp = MagicMock(status_code=403, text=attacker_text)
    mock_nm = MagicMock()
    mock_nm.verify_ssl = False
    mock_nm.send_request = AsyncMock(side_effect=[victim_resp, attacker_resp])
    plan = [{"endpoint": "http://api.com/user"}]
    confirmed = await m6.execute_idor_attacks(attack_plan=plan, attacker_token="tkA", victim_token="tkV", network_manager=mock_nm)
    assert confirmed == []


# ─── race conditions ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_race_conditions_success(m6):
    mock_nm = MagicMock()
    mock_resp = MagicMock(status_code=200)
    mock_nm.send_request = AsyncMock(return_value=mock_resp)
    result = await m6.test_race_conditions(mock_nm, "http://api.com/coupon", count=3)
    assert result is not None
    assert result["type"] == "RACE_CONDITION"

@pytest.mark.asyncio
async def test_race_conditions_no_vuln(m6):
    resp_success = MagicMock(status_code=200)
    resp_fail    = MagicMock(status_code=400)
    mock_nm = MagicMock()
    mock_nm.send_request = AsyncMock(side_effect=[resp_success, resp_fail, resp_fail])
    result = await m6.test_race_conditions(mock_nm, "http://api.com/coupon", count=3)
    assert result is None
