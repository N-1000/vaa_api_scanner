import pytest
from standalone_tools.m11_graph import M11GraphAudit

@pytest.fixture
def graph():
    return M11GraphAudit()

def test_generate_graphql_suite(graph):
    suite = graph.generate_graphql_suite("http://api.com/graphql")
    
    assert len(suite) == 3
    

    assert suite[0][2] == "introspection"
    assert "query" in suite[0][0]
    assert "IntrospectionQuery" in suite[0][0]["query"]
    

    assert suite[1][2] == "dos_recursive"
    

    assert suite[2][2] == "batching_attack"
    assert isinstance(suite[2][0], list)
    assert len(suite[2][0]) == 3

def test_analyze_graph_response_empty(graph):
    vulnerable, reason, score = graph.analyze_graph_response({}, "introspection")
    assert not vulnerable
    assert score == 0.0

def test_analyze_graph_response_introspection(graph):

    vulnerable, reason, score = graph.analyze_graph_response({"data": {"__schema": {"types": []}}}, "introspection")
    assert vulnerable
    assert score == 1.0
    

    vulnerable, reason, score = graph.analyze_graph_response({"errors": [{"message": "Introspection disabled"}]}, "introspection")
    assert not vulnerable

def test_analyze_graph_response_dos_recursive(graph):

    vulnerable, reason, score = graph.analyze_graph_response(
        {"errors": [{"message": "query too complex"}]}, "dos_recursive"
    )
    assert not vulnerable
    

    vulnerable, reason, score = graph.analyze_graph_response(
        {"errors": [{"message": "query depth limit exceeded"}]}, "dos_recursive"
    )
    assert not vulnerable
    

    vulnerable, reason, score = graph.analyze_graph_response(
        {"data": {"me": {"friends": {"friends": {"name": "Test"}}}}}, "dos_recursive"
    )
    assert vulnerable
    assert score == 0.8

def test_analyze_graph_response_batching(graph):

    vulnerable, reason, score = graph.analyze_graph_response(
        [{"data": {"name": "test"}}, {"data": {"id": 1}}], 
        "batching_attack"
    )
    assert vulnerable
    assert score == 0.9
    

    vulnerable, reason, score = graph.analyze_graph_response(
        {"errors": [{"message": "batching not allowed"}]}, 
        "batching_attack"
    )
    assert not vulnerable
