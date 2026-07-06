import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from app.core.m8_chronos import M8Chronos

@pytest.fixture
def m8():
    return M8Chronos()

@pytest.mark.asyncio
@patch("app.core.m8_chronos.httpx.AsyncClient")
@patch("app.core.m8_chronos.time.time")
async def test_run_stress_test(mock_time, mock_client_class, m8):

    mock_time.side_effect = [0.0, 0.1, 0.2, 0.3, 0.4, 5.0, 5.1, 5.2, 5.3, 5.4, 10.0]
    
    mock_client = AsyncMock()
    
    class MockContextManager:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
    mock_client_class.return_value = MockContextManager()
    
    mock_resp = MagicMock(status_code=200)
    mock_client.get.return_value = mock_resp
    

    result = await m8.run_stress_test("http://api.com", concurrency=1, duration=1)
    
    assert "verdict" in result
    assert "risk" in result
    assert result["risk"] == "Low" or result["risk"] == "Medium"
    assert mock_client.get.called

@pytest.mark.asyncio
@patch("app.core.m8_chronos.httpx.AsyncClient")
async def test_check_performance_dos_vulnerable(mock_client_class, m8, monkeypatch):
    mock_client = AsyncMock()
    
    class MockContextManager:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
    mock_client_class.return_value = MockContextManager()
    

    import time
    original_time = time.time
    
    time_calls = 0
    def mock_time():
        nonlocal time_calls
        time_calls += 1
        if time_calls == 1: return 0.0
        if time_calls == 2: return 0.1
        if time_calls == 3: return 0.2
        if time_calls == 4: return 3.0
        return original_time()
        
    monkeypatch.setattr("app.core.m8_chronos.time.time", mock_time)
    
    result = await m8.check_performance_dos("http://api.com")
    assert result["vulnerable"] is True
    assert "evidence" in result
    assert "factor" in result["evidence"]
    assert result["evidence"]["factor"] > 10

@pytest.mark.asyncio
@patch("app.core.m8_chronos.httpx.AsyncClient")
async def test_check_performance_dos_timeout(mock_client_class, m8):
    mock_client = AsyncMock()
    
    class MockContextManager:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
    mock_client_class.return_value = MockContextManager()
    
    import httpx

    mock_client.post.side_effect = httpx.ReadTimeout("Timeout")
    
    result = await m8.check_performance_dos("http://api.com")
    assert result["vulnerable"] is True
    assert "Timeout" in result["reason"]
    assert result["factor"] == "Infinity"

@pytest.mark.asyncio
@patch("app.core.m8_chronos.httpx.AsyncClient")
async def test_check_json_nesting_dos_timeout(mock_client_class, m8):
    mock_client = AsyncMock()
    
    class MockContextManager:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
    mock_client_class.return_value = MockContextManager()
    
    import httpx
    mock_client.post.side_effect = httpx.ReadTimeout("Timeout")
    
    result = await m8.check_json_nesting_dos("http://api.com")
    assert result["vulnerable"] is True
    assert "JSON_NESTING_DOS" in result["type"]
    assert result["severity"] == "High"

@pytest.mark.asyncio
@patch("app.core.m8_chronos.httpx.AsyncClient")
async def test_check_json_nesting_dos_latency(mock_client_class, m8, monkeypatch):
    mock_client = AsyncMock()
    
    class MockContextManager:
        async def __aenter__(self):
            return mock_client
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass
            
    mock_client_class.return_value = MockContextManager()
    
    time_calls = 0
    def mock_time():
        nonlocal time_calls
        time_calls += 1
        if time_calls == 1: return 0.0
        if time_calls == 2: return 6.0
        return 0.0
        
    monkeypatch.setattr("app.core.m8_chronos.time.time", mock_time)
    
    result = await m8.check_json_nesting_dos("http://api.com")
    assert result["vulnerable"] is True
    assert result["severity"] == "Medium"
    assert "Latencia excesiva" in result["evidence"]

@pytest.mark.asyncio
async def test_check_timing_attack(m8):
    with pytest.raises(NotImplementedError):
        await m8.check_timing_attack("http://api.com", {})
