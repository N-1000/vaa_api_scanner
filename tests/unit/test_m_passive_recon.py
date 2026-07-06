import pytest
from unittest.mock import AsyncMock, MagicMock
from app.core.m_passive_recon import check_exposed_docs, check_security_headers, CORS_TEST_ORIGIN


class MockResponse:
    def __init__(self, status_code, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text.encode('utf-8')
        self.headers = headers or {}

@pytest.fixture
def mock_client():
    client = AsyncMock()
    return client

@pytest.mark.asyncio
class TestPassiveRecon:
    
    async def test_exposed_docs_no_findings(self, mock_client):

        mock_client.send_request.return_value = MockResponse(status_code=404)
        
        findings = await check_exposed_docs("http://test.com", mock_client)
        assert len(findings) == 0

    async def test_exposed_docs_false_positive_marketing_site(self, mock_client):

        long_marketing_text = "Welcome to our company website. " * 50
        mock_client.send_request.return_value = MockResponse(status_code=200, text=long_marketing_text)
        
        findings = await check_exposed_docs("http://test.com", mock_client)
        assert len(findings) == 0

    async def test_exposed_docs_true_positive(self, mock_client):

        swagger_text = '{"openapi": "3.0.0", "info": {"title": "Test API"}, "paths": {}}'
        

        async def mock_get(url, **kwargs):
            if "/swagger.json" in url:
                return MockResponse(status_code=200, text=swagger_text)
            return MockResponse(status_code=404)
            
        mock_client.send_request.side_effect = mock_get
        
        findings = await check_exposed_docs("http://test.com", mock_client)
        assert len(findings) == 1
        assert findings[0]["type"] == "Exposed_Documentation"
        assert findings[0]["url"] == "http://test.com/swagger.json"

    async def test_security_headers_perfect_api(self, mock_client):

        good_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
        }
        mock_client.send_request.return_value = MockResponse(status_code=200, headers=good_headers)
        
        findings = await check_security_headers("http://test.com", mock_client)
        assert len(findings) == 0

    async def test_security_headers_missing_headers(self, mock_client):

        mock_client.send_request.return_value = MockResponse(status_code=200, headers={})
        
        findings = await check_security_headers("http://test.com", mock_client)
        assert len(findings) == 1
        assert findings[0]["type"] == "Missing_Security_Headers"
        assert "Missing_Security_Headers" in findings[0]["type"]

    async def test_security_headers_cors_wildcard(self, mock_client):

        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Access-Control-Allow-Origin": "*"
        }
        mock_client.send_request.return_value = MockResponse(status_code=200, headers=headers)
        
        findings = await check_security_headers("http://test.com", mock_client)
        assert len(findings) == 1
        assert findings[0]["type"] == "CORS_Misconfiguration"
        assert findings[0]["risk"] == "Medium"

    async def test_security_headers_cors_reflection_with_credentials(self, mock_client):

        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Access-Control-Allow-Origin": CORS_TEST_ORIGIN,
            "Access-Control-Allow-Credentials": "true"
        }
        mock_client.send_request.return_value = MockResponse(status_code=200, headers=headers)
        
        findings = await check_security_headers("http://test.com", mock_client)
        assert len(findings) == 1
        assert findings[0]["type"] == "CORS_Misconfiguration"
        assert findings[0]["risk"] == "High"
