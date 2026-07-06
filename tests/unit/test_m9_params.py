import pytest
from unittest.mock import AsyncMock, MagicMock
from app.core.m9_params import M9ParameterDiscovery

@pytest.fixture
def m9():
    m9 = M9ParameterDiscovery()
    m9.common_params = ["admin", "debug"]
    m9.probe_values = ["true"]
    return m9

@pytest.mark.asyncio
async def test_discover_params_status_change(m9):
    mock_nm = MagicMock()
    mock_client = AsyncMock()
    
    class MockContextManager:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
    mock_nm.create_client.return_value = MockContextManager()
    

    mock_base = MagicMock(status_code=200)
    mock_base.content = b'{"success": true}'
    

    mock_admin = MagicMock(status_code=403)
    mock_admin.content = b'{"error": "not admin"}'
    

    mock_debug = MagicMock(status_code=200)
    mock_debug.content = b'{"success": true}'
    
    mock_nm.send_request = AsyncMock()

    mock_nm.send_request.side_effect = [mock_base, mock_admin, mock_debug]
    
    params = await m9.discover_params(mock_nm, "http://api.com")
    
    assert len(params) == 1

    assert "admin" in params

@pytest.mark.asyncio
async def test_discover_params_content_length_change(m9):
    mock_nm = MagicMock()
    mock_client = AsyncMock()
    
    class MockContextManager:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
    mock_nm.create_client.return_value = MockContextManager()
    

    mock_base = MagicMock(status_code=200)
    mock_base.content = b'{"status": "normal"}'
    

    mock_admin = MagicMock(status_code=200)
    mock_admin.content = b'{"status": "normal"}'
    

    mock_debug = MagicMock(status_code=200)
    extra_data = b'x' * 100
    mock_debug.content = b'{"status": "normal", "debug_data": "' + extra_data + b'"}'
    
    mock_nm.send_request = AsyncMock()
    mock_nm.send_request.side_effect = [mock_base, mock_admin, mock_debug]
    
    params = await m9.discover_params(mock_nm, "http://api.com")
    
    assert len(params) == 1
    assert "debug" in params

@pytest.mark.asyncio
async def test_discover_params_reflection_filter(m9):
    mock_nm = MagicMock()
    mock_client = AsyncMock()
    
    class MockContextManager:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
    mock_nm.create_client.return_value = MockContextManager()
    m9.probe_values = ["a_very_long_probe_value_to_test_reflection_filter_properly12345"]
    

    mock_base = MagicMock(status_code=200)
    mock_base.content = b'{"status": "normal"}'
    base_len = len(mock_base.content)
    

    mock_debug = MagicMock(status_code=200)
    mock_debug.content = mock_base.content + b', ' + m9.probe_values[0].encode()
    

    m9.common_params = ["debug"]
    

    delta = len(mock_debug.content) - base_len
    assert delta > m9.CONTENT_DELTA_THRESHOLD
    assert delta <= (len(m9.probe_values[0]) * 2)
    
    mock_nm.send_request = AsyncMock()
    mock_nm.send_request.side_effect = [mock_base, mock_debug]
    
    params = await m9.discover_params(mock_nm, "http://api.com")
    

    assert len(params) == 0

@pytest.mark.asyncio
async def test_discover_params_baseline_fails(m9):
    mock_nm = MagicMock()
    mock_client = AsyncMock()
    
    class MockContextManager:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
    mock_nm.create_client.return_value = MockContextManager()
    
    mock_nm.send_request = AsyncMock()
    mock_nm.send_request.return_value = None
    
    params = await m9.discover_params(mock_nm, "http://api.com")
    assert len(params) == 0
