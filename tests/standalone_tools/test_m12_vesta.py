import pytest
from standalone_tools.m12_vesta import M12Vesta

@pytest.fixture
def vesta():
    return M12Vesta({"deduplication_level": 1, "max_per_cluster": 2})

def test_calculate_priority(vesta):

    high_ep = {"url": "http://example.com/api/admin/auth"}
    score_high = vesta._calculate_priority(high_ep)
    

    low_ep = {"url": "http://example.com/static/css/style.css"}
    score_low = vesta._calculate_priority(low_ep)
    

    assert score_high > score_low

    param_ep = {"url": "http://example.com/api/users", "params": {"id": 1}}
    score_param = vesta._calculate_priority(param_ep)
    no_param_ep = {"url": "http://example.com/api/users"}
    score_no_param = vesta._calculate_priority(no_param_ep)
    
    assert score_param == score_no_param + 3.0

def test_deduplicate_local_bypass(vesta):
    endpoints = [
        {"url": "http://localhost/api/users/1", "method": "GET", "path": "/api/users/1"},
        {"url": "http://localhost/api/users/2", "method": "GET", "path": "/api/users/2"},
        {"url": "http://localhost/api/users/3", "method": "GET", "path": "/api/users/3"}
    ]

    result = vesta._deduplicate(endpoints, {})
    assert len(result) == 3

def test_deduplicate_clusters(vesta, monkeypatch):


    endpoints = [
        {"url": "http://example.com/api/users/1", "method": "GET", "path": "/api/users/1"},
        {"url": "http://example.com/api/users/2", "method": "GET", "path": "/api/users/2"},
        {"url": "http://example.com/api/users/3", "method": "GET", "path": "/api/users/3"},
        {"url": "http://example.com/api/posts/1", "method": "GET", "path": "/api/posts/1"}
    ]
    

    result = vesta._deduplicate(endpoints, {})
    assert len(result) == 3
    assert {"url": "http://example.com/api/users/3", "method": "GET", "path": "/api/users/3"} not in result

def test_optimize_scan_manifest(vesta):
    endpoints = [
        {"url": "http://example.com/api/users/1", "method": "GET", "path": "/api/users/1"},
        {"url": "http://example.com/api/admin/login", "method": "POST", "path": "/api/admin/login"},
        {"url": "http://example.com/api/users/2", "method": "GET", "path": "/api/users/2"}
    ]
    
    optimized = vesta.optimize_scan_manifest(endpoints, {})
    

    assert len(optimized) == 3
    assert "admin" in optimized[0]["url"].lower()

def test_get_fuzzy_cluster_key(vesta):
    text1 = "This is a response text which will be hashed"
    text2 = "This is a response text which will be hashed"
    
    h1 = vesta.get_fuzzy_cluster_key(text1)
    h2 = vesta.get_fuzzy_cluster_key(text2)
    
    assert h1 == h2
    assert "simhash" in h1
    

    assert vesta.get_fuzzy_cluster_key("") == "empty"

def test_shannon_adjustment(vesta):
    assert vesta.get_shannon_adjustment(0.1) == 0
    assert vesta.get_shannon_adjustment(0.4) == 5
    assert vesta.get_shannon_adjustment(0.8) == 20
