import pytest
from app.core.m1_grammar import M1GrammarModel, MarkovPredictor, TechFingerprinter

@pytest.fixture
def m1():
    return M1GrammarModel()

class TestMarkovPredictor:
    def test_learn_path(self):
        predictor = MarkovPredictor()
        predictor.learn_path("/api/v1/users")
        predictor.learn_path("/api/v1/posts")
        

        assert "api" in predictor.transitions
        assert "v1" in predictor.transitions["api"]
        assert predictor.transitions["api"]["v1"] == 2
        
        assert "users" in predictor.transitions["v1"]
        assert "posts" in predictor.transitions["v1"]

    def test_predict_next(self):
        predictor = MarkovPredictor()
        predictor.learn_path("/api/v1/users")
        predictor.learn_path("/api/v1/users")
        predictor.learn_path("/api/v2/users")
        

        predictions = predictor.predict_next("api")
        assert predictions[0] == "v1"
        assert "v2" in predictions

class TestM1GrammarModel:
    def test_learn_exploit(self, m1):
        m1.learn_exploit("/api/test", "1' OR 1=1--", "sqli")
        assert "known_exploits" in m1.grammar_context
        assert "/api/test" in m1.grammar_context["known_exploits"]
        assert {"type": "sqli", "payload": "1' OR 1=1--"} in m1.grammar_context["known_exploits"]["/api/test"]
        

        m1.learn_exploit("/api/test", "1' OR 1=1--", "sqli")
        assert len(m1.grammar_context["known_exploits"]["/api/test"]) == 1

    def test_merge_context(self, m1):
        m1.grammar_context = {
            "/api/v1[id]": {
                "seen_params": {"id": {"type": "int"}}
            }
        }
        
        saved_context = {
            "/api/v1[id]": {
                "seen_params": {"id": {"type": "int"}, "debug": {"type": "string"}}
            },
            "/api/v2[new]": {
                "seen_params": {"new": {"type": "string"}}
            }
        }
        
        m1.merge_context(saved_context)
        

        assert "/api/v2[new]" in m1.grammar_context

        assert "debug" in m1.grammar_context["/api/v1[id]"]["seen_params"]

    def test_learn_from_traffic_basic(self, m1):
        traffic = {
            "path": "/api/users",
            "method": "POST",
            "params": {"user_id": 123, "name": "alice"}
        }
        m1.learn_from_traffic(traffic)
        
        dedup_key = "/api/users[name,user_id]"
        assert dedup_key in m1.grammar_context
        assert m1.grammar_context[dedup_key]["methods"] == {"POST"}

        params = m1.grammar_context[dedup_key]["seen_params"]
        assert params["user_id"]["type"] == "int"
        assert params["name"]["type"] == "string"

    def test_learn_from_traffic_graphql_detection(self, m1):
        traffic = {
            "path": "/graphql",
            "method": "POST",
            "params": {"query": "query { users { id } }"}
        }
        m1.learn_from_traffic(traffic)
        dedup_key = "/graphql[query]"
        assert m1.grammar_context[dedup_key]["is_graph"] is True

    def test_type_inconsistency_logging(self, m1):

        m1.learn_from_traffic({"path": "/api", "params": {"id": 123}})
        

        m1.learn_from_traffic({"path": "/api", "params": {"id": "123_invalid"}})
        
        dedup_key = "/api[id]"
        param_ctx = m1.grammar_context[dedup_key]["seen_params"]["id"]
        

        assert param_ctx["type"] == "int"
        assert "string" in param_ctx["inconsistencies"]

    def test_classify_endpoint_type(self, m1):

        assert m1.classify_endpoint_type("/api/login") == "auth"
        assert m1.classify_endpoint_type("/api/v1/oauth/token") == "auth"
        

        assert m1.classify_endpoint_type("/dashboard/settings") == "admin"
        

        assert m1.classify_endpoint_type("/api/users/123") == "data-read"
        assert m1.classify_endpoint_type("/api/users/a1b2c3d4-e5f6-7890") == "data-read"
        assert m1.classify_endpoint_type("/api/profile", params={"user_id": 45}) == "data-read"
        

        assert m1.classify_endpoint_type("/api/profile/update", params={"age": 30}) == "data-write"
        

        assert m1.classify_endpoint_type("/api/products", params={"q": "laptop"}) == "search"
        

        assert m1.classify_endpoint_type("/api/health") == "health"
        

        assert m1.classify_endpoint_type("/api/public/posts") == "generic"

    def test_infer_subtype(self, m1):
        assert m1._infer_subtype("test@example.com") == "email"
        assert m1._infer_subtype("user123") == "alphanumeric"
        assert m1._infer_subtype("2024-12-31") == "date"
        assert m1._infer_subtype("550e8400-e29b-41d4-a716-446655440000") == "uuid"
        assert m1._infer_subtype("some random text!") == "text"

class TestTechFingerprinter:
    def test_identify_headers(self, monkeypatch):
        mock_patterns = {
            "nginx": {"headers": {"server": "nginx"}},
            "express": {"headers": {"x-powered-by": "express"}}
        }
        monkeypatch.setattr(TechFingerprinter, "PATTERNS", mock_patterns)
        
        headers = {"Server": "nginx/1.24", "x-powered-by": "Express"}
        techs = TechFingerprinter.identify(headers)
        assert "nginx" in techs
        assert "express" in techs

    def test_identify_cookies_and_fallback(self, monkeypatch):
        mock_patterns = {
            "php": {"cookies": ["PHPSESSID"]},
        }
        monkeypatch.setattr(TechFingerprinter, "PATTERNS", mock_patterns)
        

        headers = {"Set-Cookie": "PHPSESSID=1234; Path=/"}
        techs = TechFingerprinter.identify(headers)
        assert "php" in techs
        

        headers = {"Server": "cloudflare"}
        techs = TechFingerprinter.identify(headers)
        assert "cloudflare" in techs
