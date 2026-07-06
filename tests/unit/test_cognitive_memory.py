import pytest
from unittest.mock import patch, AsyncMock, MagicMock
import json
from app.core.cognitive_memory import CognitiveMemory

@pytest.fixture
def memory():
    return CognitiveMemory()

# --- Mocking Helpers ---

class MockAcquire:
    def __init__(self, execute_return=None, fetch_return=None):
        self.mock_conn = AsyncMock()
        if execute_return is not None:
            self.mock_conn.execute.return_value = execute_return
        if fetch_return is not None:
            self.mock_conn.fetch.return_value = fetch_return
            
    async def __aenter__(self):
        return self.mock_conn
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

def setup_mock_pool(memory_instance, execute_return=None, fetch_return=None):
    """Configures the memory instance with a mocked asyncpg pool."""
    memory_instance.enabled = True
    memory_instance.pool = MagicMock()
    mock_acquire_instance = MockAcquire(execute_return, fetch_return)
    memory_instance.pool.acquire.return_value = mock_acquire_instance
    return mock_acquire_instance.mock_conn

# --- Tests ---

def test_singleton_nature():
    mem1 = CognitiveMemory()
    mem2 = CognitiveMemory()
    assert mem1 is mem2

@pytest.mark.asyncio
@patch("app.core.cognitive_memory.asyncpg.create_pool", new_callable=AsyncMock)
@patch("app.core.cognitive_memory.settings")
async def test_init_pool_success(mock_settings, mock_create_pool, memory):
    mock_settings.VAA_DB_URL = "postgres://fake"
    mock_settings.DB_TIMEOUT = 3.0
    
    mock_pool = MagicMock()
    mock_pool.acquire.return_value = MockAcquire()
    mock_create_pool.return_value = mock_pool
    
    await memory.init_pool()
    
    assert memory.enabled is True
    assert memory.pool is not None

@pytest.mark.asyncio
@patch("app.core.cognitive_memory.asyncpg.create_pool")
async def test_close_pool(mock_create_pool, memory):
    memory.enabled = True
    memory.pool = AsyncMock()
    # Mock the keepalive task so cancel() doesn't touch a closed event loop
    mock_task = MagicMock()
    mock_task.cancel = MagicMock()
    mock_task.__await__ = lambda s: iter([])
    memory._keepalive_task = None  # disable it cleanly

    await memory.close_pool()
    memory.pool.close.assert_called_once()

@pytest.mark.asyncio
async def test_learn_grammar(memory):
    mock_conn = setup_mock_pool(memory)
    
    await memory.learn_grammar("/api/v1/users", "limit", {"type": "integer"})
    
    mock_conn.execute.assert_called_once()
    args, _ = mock_conn.execute.call_args
    assert "/api/v1/users" in args
    assert "limit" in args
    assert json.dumps({"type": "integer"}) in args

@pytest.mark.asyncio
async def test_recall_grammar(memory):
    # Mocking rows returned by asyncpg (which behave like dicts)
    mock_conn = setup_mock_pool(memory, fetch_return=[
        {"param_name": "limit", "param_data": '{"type": "integer"}'}
    ])
    
    results = await memory.recall_grammar("/api/v1/users")
    
    mock_conn.fetch.assert_called_once()
    assert "limit" in results
    assert results["limit"]["type"] == "integer"

@pytest.mark.asyncio
async def test_memorize_exploit(memory):
    mock_conn = setup_mock_pool(memory)
    
    # Should execute if confidence >= 0.80
    await memory.memorize_exploit("example.com", "/api/users", "BOLA", "id=5", 0.95)
    mock_conn.execute.assert_called_once()
    
    mock_conn.execute.reset_mock()
    
    # Should NOT execute if confidence < 0.80
    await memory.memorize_exploit("example.com", "/api/users", "BOLA", "id=5", 0.50)
    mock_conn.execute.assert_not_called()

@pytest.mark.asyncio
async def test_get_prior_exploits(memory):
    mock_conn = setup_mock_pool(memory, fetch_return=[
        {"norm_path": "/api/users", "vuln_type": "BOLA", "payload": "id=5", "confidence": 0.95}
    ])
    
    exploits = await memory.get_prior_exploits("example.com")
    
    mock_conn.fetch.assert_called_once()
    assert len(exploits) == 1
    assert exploits[0]["vuln_type"] == "BOLA"
    assert exploits[0]["confidence"] == 0.95

@pytest.mark.asyncio
async def test_log_endpoint(memory):
    mock_conn = setup_mock_pool(memory)
    
    await memory.log_endpoint("example.com", "/api/data", "GET", True, "Bearer", 200, {})
    
    mock_conn.execute.assert_called_once()
    args, _ = mock_conn.execute.call_args
    assert "example.com" in args
    assert "/api/data" in args

@pytest.mark.asyncio
async def test_start_mission(memory):
    mock_conn = setup_mock_pool(memory)
    
    scan_id = await memory.start_mission("example.com")
    
    mock_conn.execute.assert_called_once()
    assert len(scan_id) > 10  # is a valid uuid string

@pytest.mark.asyncio
async def test_end_mission(memory):
    mock_conn = setup_mock_pool(memory)
    
    await memory.end_mission("fake-uuid", 5)
    
    mock_conn.execute.assert_called_once()
    args, _ = mock_conn.execute.call_args
    assert 5 in args
    assert "fake-uuid" in args
