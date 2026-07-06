"""Tests for app/core/engine/specialized/mass_assignment.py"""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock
from app.core.engine.models import EndpointTarget
from app.core.engine.specialized import mass_assignment


def make_ep(method="POST", url="http://api.com/users"):
    return EndpointTarget(url=url, method=method, path="/users", params={}, body_schema={}, source="test")


def make_nm(status=200, text='{"is_admin": true}'):
    nm = MagicMock()
    resp = MagicMock(status_code=status, text=text, content=text.encode())
    nm.send_request_raw = AsyncMock(return_value=resp)
    return nm


@pytest.mark.asyncio
async def test_mass_assignment_skips_get_endpoints():
    """GET endpoints should be skipped entirely."""
    findings = []
    async def record(f): findings.append(f)
    nm = make_nm()
    count = await mass_assignment.run(
        endpoints=[make_ep(method="GET")],
        network_manager=nm,
        options={"auth_token": "tok"},
        sem=asyncio.Semaphore(5),
        record_finding=record,
    )
    assert count == 0
    assert findings == []


@pytest.mark.asyncio
async def test_mass_assignment_detects_reflected_field():
    """If injected key appears in response body → Mass Assignment confirmed."""
    findings = []
    async def record(f): findings.append(f)
    # Response reflects back the injected field
    nm = make_nm(status=200, text='{"id": 1, "is_admin": true}')
    count = await mass_assignment.run(
        endpoints=[make_ep(method="POST")],
        network_manager=nm,
        options={"auth_token": "tok"},
        sem=asyncio.Semaphore(5),
        record_finding=record,
    )
    assert count >= 1
    assert len(findings) >= 1


@pytest.mark.asyncio
async def test_mass_assignment_no_reflection_no_finding():
    """If injected key is NOT in response body → no finding."""
    findings = []
    async def record(f): findings.append(f)
    nm = make_nm(status=200, text='{"id": 1, "name": "user"}')
    count = await mass_assignment.run(
        endpoints=[make_ep(method="POST")],
        network_manager=nm,
        options={"auth_token": "tok"},
        sem=asyncio.Semaphore(5),
        record_finding=record,
    )
    assert count == 0


@pytest.mark.asyncio
async def test_mass_assignment_patch_and_put_tested():
    """PATCH and PUT endpoints should also be tested."""
    findings = []
    async def record(f): findings.append(f)
    nm = make_nm(status=200, text='{"role": "admin"}')
    endpoints = [
        make_ep(method="PATCH", url="http://api.com/profile"),
        make_ep(method="PUT",   url="http://api.com/user/1"),
    ]
    count = await mass_assignment.run(
        endpoints=endpoints,
        network_manager=nm,
        options={"auth_token": "tok"},
        sem=asyncio.Semaphore(5),
        record_finding=record,
    )
    assert count >= 1


@pytest.mark.asyncio
async def test_mass_assignment_empty_endpoints():
    findings = []
    async def record(f): findings.append(f)
    nm = make_nm()
    count = await mass_assignment.run(
        endpoints=[],
        network_manager=nm,
        options={"auth_token": "tok"},
        sem=asyncio.Semaphore(5),
        record_finding=record,
    )
    assert count == 0


@pytest.mark.asyncio
async def test_mass_assignment_server_error_no_crash():
    """500 response should not crash the scanner."""
    findings = []
    async def record(f): findings.append(f)
    nm = make_nm(status=500, text='Internal Server Error')
    count = await mass_assignment.run(
        endpoints=[make_ep(method="POST")],
        network_manager=nm,
        options={"auth_token": "tok"},
        sem=asyncio.Semaphore(5),
        record_finding=record,
    )
    assert isinstance(count, int)
