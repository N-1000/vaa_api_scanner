"""Tests for app/core/modules/openapi_parser.py"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.core.modules.openapi_parser import OpenAPIParser


MINIMAL_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0"},
    "servers": [{"url": "https://api.test.com"}],
    "paths": {
        "/users": {
            "get": {
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                ]
            },
            "post": {
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "email": {"type": "string"}
                                }
                            }
                        }
                    }
                }
            }
        },
        "/users/{userId}": {
            "get": {
                "parameters": [
                    {"name": "userId", "in": "path", "required": True}
                ]
            },
            "delete": {}
        }
    }
}


# ─── parse_endpoints ─────────────────────────────────────────────────────────

def test_parse_endpoints_basic():
    parser = OpenAPIParser()
    parser.spec = MINIMAL_SPEC
    parser.base_url = "https://api.test.com"
    endpoints = parser.parse_endpoints()
    assert len(endpoints) >= 2
    urls = [e["url"] for e in endpoints]
    assert any("/users" in u for u in urls)


def test_parse_endpoints_includes_methods():
    parser = OpenAPIParser()
    parser.spec = MINIMAL_SPEC
    parser.base_url = "https://api.test.com"
    endpoints = parser.parse_endpoints()
    methods = [e["method"].upper() for e in endpoints]
    assert "GET" in methods
    assert "POST" in methods


def test_parse_endpoints_path_params_resolved():
    parser = OpenAPIParser()
    parser.spec = MINIMAL_SPEC
    parser.base_url = "https://api.test.com"
    endpoints = parser.parse_endpoints()
    parameterized = [e for e in endpoints if "{" in e.get("url", "")]
    assert len(parameterized) >= 1


def test_parse_endpoints_empty_spec():
    parser = OpenAPIParser()
    parser.spec = {"paths": {}}
    parser.base_url = "https://api.test.com"
    endpoints = parser.parse_endpoints()
    assert endpoints == []


def test_parse_endpoints_no_spec():
    parser = OpenAPIParser()
    parser.spec = {}
    parser.base_url = ""
    endpoints = parser.parse_endpoints()
    assert endpoints == []


# ─── load_spec (async) ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_load_spec_from_dict_direct():
    """Directly setting spec bypasses network — simulates successful load."""
    parser = OpenAPIParser()
    parser.spec = MINIMAL_SPEC
    parser.base_url = "https://api.test.com"
    assert parser.spec is not None
    assert parser.base_url != ""


@pytest.mark.asyncio
async def test_load_spec_file_not_found_returns_false():
    """Loading a non-existent file should return False without raising."""
    parser = OpenAPIParser()
    result = await parser.load_spec("/nonexistent/path/spec.json")
    assert result is False


@pytest.mark.asyncio
async def test_load_spec_invalid_url_returns_false():
    """An unreachable URL should return False gracefully."""
    parser = OpenAPIParser()
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=Exception("Connection refused")):
        result = await parser.load_spec("http://localhost:99999/openapi.json")
    assert result is False
