import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from app.core.m74p1_navigator import M74P1Navigator

@pytest.fixture
def nav():
    return M74P1Navigator()

class TestM74P1Navigator:

    def test_has_key(self, nav):

        assert nav._has_key('{"openapi": "3.0.0"}', "openapi") is True

        assert nav._has_key('{\n  "openapi" : "3.0.0"\n}', "openapi") is True

        assert nav._has_key('{"something": "else"}', "openapi") is False

    @pytest.mark.asyncio
    @patch("app.core.m74p1_navigator.httpx.AsyncClient")
    async def test_sniff_format_url_openapi(self, mock_client_class, nav):
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        

        mock_head = MagicMock()
        mock_head.headers = {"content-type": "application/json"}
        mock_client.head.return_value = mock_head
        

        mock_get = MagicMock()
        mock_get.text = '{"openapi": "3.0"}'
        mock_client.get.return_value = mock_get
        
        fmt = await nav._sniff_format("http://api.com/docs")
        assert fmt == "openapi"

    @pytest.mark.asyncio
    @patch("app.core.m74p1_navigator.os.path.exists")
    @patch("builtins.open", new_callable=MagicMock)
    async def test_sniff_format_local_file_postman(self, mock_open, mock_exists, nav):
        mock_exists.return_value = True
        

        file_handle = MagicMock()
        file_handle.read.side_effect = ['{"info": {"_postman_id": "123"}}', '']
        mock_open.return_value.__enter__.return_value = file_handle
        
        fmt = await nav._sniff_format("collection.json")
        assert fmt == "postman"

    @pytest.mark.asyncio
    @patch("app.core.m74p1_navigator.httpx.AsyncClient")
    async def test_classify_target_type_web_interface(self, mock_client_class, nav):
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        

        mock_head = MagicMock()
        mock_head.headers = {"content-type": "text/html"}
        mock_client.head.return_value = mock_head
        

        mock_get = MagicMock()
        mock_get.headers = {"content-type": "text/html"}
        mock_get.text = "<!doctype html><html><body>Welcome</body></html>"
        mock_client.get.return_value = mock_get
        
        is_api, reason = await nav._classify_target_type("http://example.com")
        assert is_api is False
        assert "HTML Document detected" in reason

    @pytest.mark.asyncio
    @patch("app.core.m74p1_navigator.httpx.AsyncClient")
    async def test_classify_target_type_swagger_ui(self, mock_client_class, nav):
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        

        mock_head = MagicMock()
        mock_head.headers = {"content-type": "text/html"}
        mock_client.head.return_value = mock_head
        
        mock_get = MagicMock()
        mock_get.headers = {"content-type": "text/html"}
        mock_get.text = "<!doctype html><html><body><div id='swagger-ui'></div></body></html>"
        mock_client.get.return_value = mock_get
        
        is_api, reason = await nav._classify_target_type("http://example.com/docs")
        assert is_api is True
        assert "Swagger UI detected" in reason

    @pytest.mark.asyncio
    async def test_navigate_input_postman_dispatch(self, nav, monkeypatch):

        async def mock_sniff(*args, **kwargs):
            return "postman"
        monkeypatch.setattr(nav, "_sniff_format", mock_sniff)
        

        mock_endpoints = [{"url": "http://api.com", "method": "GET"}]
        monkeypatch.setattr(nav.postman_parser, "parse", MagicMock(return_value=mock_endpoints))
        
        endpoints = await nav.navigate_input("collection.json")
        assert endpoints == mock_endpoints

    @pytest.mark.asyncio
    @patch("app.core.m74p1_navigator.TrafficIngestor.load_traffic")
    async def test_navigate_input_har_dispatch(self, mock_load, nav, monkeypatch):
        async def mock_sniff(*args, **kwargs):
            return "har"
        monkeypatch.setattr(nav, "_sniff_format", mock_sniff)
        
        mock_endpoints = [{"url": "http://api.com/har", "method": "GET"}]
        mock_load.return_value = mock_endpoints
        
        endpoints = await nav.navigate_input("traffic.har")
        assert endpoints == mock_endpoints

    @pytest.mark.asyncio
    async def test_probe_openapi_autodiscovery_success(self, nav, monkeypatch):

        async def mock_load_spec(self_instance, url, **kwargs):
            if "/swagger.json" in url:
                return True
            return False
    
        monkeypatch.setattr("app.core.modules.openapi_parser.OpenAPIParser.load_spec", mock_load_spec)
    
        result = await nav._probe_openapi_autodiscovery("http://target.com")
        assert result is True
