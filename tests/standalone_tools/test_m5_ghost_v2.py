import pytest
from unittest.mock import patch, MagicMock
from app.core.m5_ghost_v2 import M5GhostProtocol

def test_stealth_disabled():
    ghost = M5GhostProtocol({"stealth": False})
    headers = ghost.get_stealth_headers({"Original": "Header"})
    
    assert "Original" in headers

    assert "User-Agent" in headers
    assert headers["User-Agent"] == "VAA-Scanner/6.0"

def test_stealth_enabled_user_agent_rotation(monkeypatch):
    ghost = M5GhostProtocol({"stealth": True})

    monkeypatch.setattr(ghost, "IP_SPOOF_PROBABILITY", 0.0)
    
    headers = ghost.get_stealth_headers()
    assert "User-Agent" in headers
    assert headers["User-Agent"] in ghost.user_agents

def test_stealth_enabled_ip_spoofing(monkeypatch):
    ghost = M5GhostProtocol({"stealth": True})

    monkeypatch.setattr(ghost, "IP_SPOOF_PROBABILITY", 1.0)
    
    headers = ghost.get_stealth_headers()
    

    has_spoof = any(h in headers for h in ghost.spoof_headers)
    assert has_spoof

def test_stealth_waf_profile_akamai():
    ghost = M5GhostProtocol({"stealth": True, "waf_profile": "akamai"})
    headers = ghost.get_stealth_headers()
    
    assert "Pragma" in headers
    assert headers["Pragma"] == "no-cache"
    assert "Akamai-Origin-Hop" in headers

def test_stealth_waf_profile_cloudflare():
    ghost = M5GhostProtocol({"stealth": True, "waf_profile": "cloudflare"})
    headers = ghost.get_stealth_headers()
    
    assert "CF-Connecting-IP" in headers
    assert headers["CF-Connecting-IP"] == "127.0.0.1"

@patch("app.utils.waf_evasion.apply_waf_evasion")
def test_apply_waf_evasion_to_payload_enabled(mock_apply):
    ghost = M5GhostProtocol({"stealth": True, "waf_profile": "aws"})
    mock_apply.return_value = "evaded_payload"
    
    result = ghost.apply_waf_evasion_to_payload("select *", "sqli")
    
    assert result == "evaded_payload"
    mock_apply.assert_called_once_with("select *", "aws", "sqli")

@patch("app.utils.waf_evasion.apply_waf_evasion")
def test_apply_waf_evasion_to_payload_disabled(mock_apply):
    ghost = M5GhostProtocol({"stealth": False})
    
    result = ghost.apply_waf_evasion_to_payload("select *", "sqli")
    
    assert result == "select *"
    mock_apply.assert_not_called()
