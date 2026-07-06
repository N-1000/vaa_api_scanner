import pytest
import asyncio
from unittest.mock import patch, MagicMock
from app.core.network_manager import NetworkManager, AdaptiveBackoff

@pytest.fixture
def base_options():
    return {
        "use_ghost": False,
        "bug_bounty_mode": False,
        "delay": 0.0
    }

class TestAdaptiveBackoff:
    def test_cooldown_logic(self):
        breaker = AdaptiveBackoff()
        breaker.threshold = 5
        

        for _ in range(4):
            breaker.on_block(429)
            
        assert breaker.block_count == 4
        assert breaker.current_delay_ms == 0
        

        breaker.on_block(429)
        action = breaker.on_block(429)
        assert action is not None
        assert action["action"] == "rotate_identity"
        assert breaker.current_delay_ms > 0
        

        breaker.cooldown()
        assert breaker.block_count == 5
        
    def test_reset(self):
        breaker = AdaptiveBackoff()
        breaker.block_count = 10
        breaker.current_delay_ms = 5000
        breaker.reset()
        assert breaker.block_count == 0
        assert breaker.current_delay_ms == 0

class TestNetworkManagerInit:
    def test_parse_custom_headers(self, base_options):

        opts = base_options.copy()
        opts["custom_headers"] = "X-Target: 1; MyHeader: test"
        opts["anonymous"] = True
        
        nm = NetworkManager("http://target.com", opts)
        assert "X-Target" in nm.base_headers
        assert "MyHeader" in nm.base_headers

    def test_bug_bounty_headers(self, base_options):
        opts = base_options.copy()
        opts["bug_bounty_mode"] = True
        
        nm = NetworkManager("http://target.com", opts)
        assert "X-Bug-Bounty" in nm.base_headers
        assert "X-Research-Contact" in nm.base_headers

    def test_ghost_mode_strips_identity(self, base_options):
        opts = base_options.copy()
        opts["bug_bounty_mode"] = True
        opts["custom_headers"] = "X-Bug-Bounty: hacker; User-Email: a@a.com"

        opts["use_ghost"] = True 
        
        nm = NetworkManager("http://target.com", opts)
        assert "X-Bug-Bounty" not in nm.base_headers
        assert "User-Email" not in nm.base_headers

@pytest.mark.asyncio
class TestNetworkManagerAsync:
    async def test_session_pool_lifecycle(self, base_options):
        nm = NetworkManager("http://target.com", base_options)
        

        await nm.__aenter__()
        assert len(nm.session_pool) == nm.max_pool_size
        

        with patch("curl_cffi.requests.AsyncSession.request") as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_req.return_value = mock_resp
            
            resp = await nm.send_request("http://target.com/api", method="GET")
            assert resp.status_code == 200
            

            await nm.send_request("http://target.com/api", method="POST", payload={"a": 1}, json_body=True, query_params={"id": "fuzz"})
            

            call_kwargs = mock_req.call_args.kwargs
            assert "json" in call_kwargs and call_kwargs["json"] == {"a": 1}
            assert "params" in call_kwargs and call_kwargs["params"] == {"id": "fuzz"}
            assert "data" not in call_kwargs


        with patch("curl_cffi.requests.AsyncSession.close") as mock_close:
            await nm.__aexit__(None, None, None)
            assert len(nm.session_pool) == 0
            assert mock_close.call_count == nm.max_pool_size
