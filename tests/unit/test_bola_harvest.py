"""Tests for app/core/engine/specialized/bola_harvest.py"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from app.core.engine.models import EndpointTarget
from app.core.engine.specialized import bola_harvest


def make_ep(url="http://api.com/users/5", path="/users/5", method="GET"):
    return EndpointTarget(url=url, method=method, path=path, params={}, body_schema={}, source="test")


def make_nm(status=200, text='{"id": 999, "email": "other@test.com"}'):
    nm = MagicMock()
    resp = MagicMock(status_code=status, text=text, content=text.encode())
    nm.send_request_raw = AsyncMock(return_value=resp)
    return nm


# ─── _detect_url_id_type ──────────────────────────────────────────────────────

def test_detect_url_id_type_numeric():
    url = "http://api.com/users/42"
    id_str, is_num, pattern = bola_harvest._detect_url_id_type(url)
    assert id_str == "42"
    assert is_num is True


def test_detect_url_id_type_uuid():
    url = "http://api.com/items/11111111-2222-3333-4444-555555555555"
    id_str, is_num, pattern = bola_harvest._detect_url_id_type(url)
    assert id_str == "11111111-2222-3333-4444-555555555555"
    assert is_num is False


def test_detect_url_id_type_no_id():
    url = "http://api.com/health"
    id_str, is_num, pattern = bola_harvest._detect_url_id_type(url)
    assert id_str is None


# ─── _extract_all_ids ─────────────────────────────────────────────────────────

def test_extract_all_ids_combined():
    harvest = {
        "uuids": ["11111111-2222-3333-4444-555555555555"],
        "numeric_ids": ["42", "99"],
        "vehicle_ids": ["VH-001"],
        "order_ids": ["ORD-555"]
    }
    ids = bola_harvest._extract_all_ids(harvest)
    assert "42" in ids
    assert "99" in ids
    assert "11111111-2222-3333-4444-555555555555" in ids
    assert len(ids) <= 45


def test_extract_all_ids_empty():
    harvest = {"uuids": [], "numeric_ids": [], "vehicle_ids": [], "order_ids": []}
    assert bola_harvest._extract_all_ids(harvest) == []


# ─── run (async integration) ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_bola_run_confirms_bola_on_low_similarity():
    """When attacker gets different data (sim < 0.70) → BOLA confirmed."""
    findings = []
    async def record(f): findings.append(f)

    # Attacker gets victim data (different from own baseline)
    nm = make_nm(status=200, text='{"id": 999, "email": "victim@test.com", "secret": "abc123"}')

    def sim(a, b):
        # Simulate dissimilar responses (attacker sees victim data)
        return 0.1

    harvest = {"uuids": [], "numeric_ids": ["999"], "vehicle_ids": [], "order_ids": []}
    count = await bola_harvest.run(
        endpoints=[make_ep(url="http://api.com/users/5")],
        network_manager=nm,
        options={"auth_token": "attacker_token"},
        harvest=harvest,
        m3_calculate_similarity=sim,
        record_finding=record,
    )
    assert count >= 1 or len(findings) >= 1


@pytest.mark.asyncio
async def test_bola_run_skips_non_get():
    """POST/DELETE endpoints should be skipped in BOLA harvest."""
    findings = []
    async def record(f): findings.append(f)
    nm = make_nm()
    harvest = {"uuids": [], "numeric_ids": ["5"], "vehicle_ids": [], "order_ids": []}
    count = await bola_harvest.run(
        endpoints=[make_ep(url="http://api.com/users/5", method="POST")],
        network_manager=nm,
        options={"auth_token": "tok"},
        harvest=harvest,
        m3_calculate_similarity=lambda a, b: 0.1,
        record_finding=record,
    )
    assert count == 0


@pytest.mark.asyncio
async def test_bola_run_no_id_in_url_skips():
    """Endpoints without an ID in URL should be skipped."""
    findings = []
    async def record(f): findings.append(f)
    nm = make_nm()
    harvest = {"uuids": [], "numeric_ids": ["5"], "vehicle_ids": [], "order_ids": []}
    count = await bola_harvest.run(
        endpoints=[make_ep(url="http://api.com/health", path="/health")],
        network_manager=nm,
        options={"auth_token": "tok"},
        harvest=harvest,
        m3_calculate_similarity=lambda a, b: 0.5,
        record_finding=record,
    )
    assert count == 0


@pytest.mark.asyncio
async def test_bola_run_high_similarity_no_finding():
    """If responses are very similar (sim >= 0.70) → no BOLA."""
    findings = []
    async def record(f): findings.append(f)
    nm = make_nm(status=200, text='{"id": 5, "data": "my_own_data"}')
    harvest = {"uuids": [], "numeric_ids": ["10"], "vehicle_ids": [], "order_ids": []}
    count = await bola_harvest.run(
        endpoints=[make_ep(url="http://api.com/users/5")],
        network_manager=nm,
        options={"auth_token": "tok"},
        harvest=harvest,
        m3_calculate_similarity=lambda a, b: 0.95,
        record_finding=record,
    )
    assert count == 0


@pytest.mark.asyncio
async def test_bola_run_empty_harvest_uses_fallback():
    """Empty harvest should use UUIDOracle or fallback IDs without crashing."""
    findings = []
    async def record(f): findings.append(f)
    nm = make_nm(status=200, text='{"data": "ok"}')
    harvest = {"uuids": [], "numeric_ids": [], "vehicle_ids": [], "order_ids": []}
    count = await bola_harvest.run(
        endpoints=[make_ep(url="http://api.com/items/7")],
        network_manager=nm,
        options={"auth_token": "tok"},
        harvest=harvest,
        m3_calculate_similarity=lambda a, b: 0.95,
        record_finding=record,
    )
    assert isinstance(count, int)
