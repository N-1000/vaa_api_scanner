"""
Tests unitarios para los algoritmos matemáticos del VAA.
Validan que Shannon y Jaccard se comportan igual que en el engine original.
No requieren red ni fixtures externos.
"""
import pytest
from app.core.engine.algorithms.similarity import (
    calculate_similarity, normalize_dynamic_fields,
    SQLI_THRESHOLD, BOLA_THRESHOLD
)
from app.core.engine.algorithms.shannon import (
    ShannonOracle, calculate_entropy, build_response_signature,
    EXHAUSTION_THRESHOLD
)


class TestJaccard:
    def test_identical_responses(self):
        text = '{"id": 1, "email": "a@b.com"}'
        assert calculate_similarity(text, text) == 1.0

    def test_completely_different(self):
        assert calculate_similarity("hello world", "foo bar baz") < 0.3

    def test_sqli_threshold(self):

        resp_true  = '{"results": [{"id": 1}, {"id": 2}], "count": 2}'
        resp_false = '{"results": [], "count": 0}'
        sim = calculate_similarity(resp_true, resp_false)
        assert sim < SQLI_THRESHOLD, f"SQLi threshold no detectado: sim={sim:.2f}"

    def test_bola_threshold(self):
        baseline = '{"id": 1, "email": "attacker@test.com", "name": "Attacker"}'
        victim   = '{"id": 2, "email": "victim@test.com", "name": "Victim", "creditCard": "1234"}'
        sim = calculate_similarity(baseline, victim)
        assert sim < BOLA_THRESHOLD, f"BOLA threshold no detectado: sim={sim:.2f}"

    def test_order_invariant(self):

        a = '{"email": "x@y.com", "id": 1}'
        b = '{"id": 1, "email": "x@y.com"}'
        assert calculate_similarity(a, b) == 1.0

    def test_dynamic_field_low_impact(self):

        a = '{"id": 1, "email": "x@y.com", "request_id": "aaa111"}'
        b = '{"id": 1, "email": "x@y.com", "request_id": "bbb999"}'
        assert calculate_similarity(a, b) >= 0.8


class TestNormalizeDynamicFields:
    def test_removes_iso_timestamp(self):
        text = '"last_login": "2024-01-15T12:34:56Z"'
        norm = normalize_dynamic_fields(text)
        assert "2024-01-15" not in norm
        assert "TIMESTAMP" in norm

    def test_dynamic_field_preserves_key_redacts_value(self):


        text = '"created_at": "2024-01-15T12:34:56Z"'
        norm = normalize_dynamic_fields(text)
        assert "created_at" in norm
        assert "REDACTED" in norm
        assert "2024-01-15" not in norm

    def test_removes_uuid(self):
        text = '"id": "550e8400-e29b-41d4-a716-446655440000"'
        norm = normalize_dynamic_fields(text)
        assert "550e8400" not in norm
        assert "UUID" in norm

    def test_removes_token_field(self):
        text = '"access_token": "eyJhbGciOiJIUzI1NiJ9.abc.def"'
        norm = normalize_dynamic_fields(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in norm

    def test_preserves_static_fields(self):
        text = '"email": "user@test.com", "role": "admin"'
        norm = normalize_dynamic_fields(text)
        assert "user@test.com" in norm
        assert "admin" in norm


class TestShannonOracle:
    def test_not_exhausted_with_few_samples(self):
        oracle = ShannonOracle()
        key = oracle.make_key("http://api/v1/users", "sqli", "q")
        for _ in range(5):
            oracle.record(key, 200, 500)
        assert not oracle.is_exhausted(key)

    def test_exhausted_on_uniform_responses(self):
        oracle = ShannonOracle()
        key = oracle.make_key("http://api/v1/users", "sqli", "q")

        for _ in range(25):
            oracle.record(key, 200, 300, is_local=False)

        assert oracle.is_exhausted(key)

    def test_reset_on_state_change(self):
        oracle = ShannonOracle()
        key = oracle.make_key("http://api/v1/users", "sqli", "q")
        for _ in range(25):
            oracle.record(key, 200, 300, is_local=False)
        assert oracle.is_exhausted(key)
        oracle.reset(key)
        assert not oracle.is_exhausted(key)

    def test_auth_only_never_exhausted(self):
        oracle = ShannonOracle()
        key = oracle.make_key("http://api/v1/admin", "sqli", "id")
        for _ in range(30):
            oracle.record(key, 403, 100, is_local=False)

        assert not oracle.is_exhausted(key)

    def test_bypass_detection(self):
        oracle = ShannonOracle()
        key = oracle.make_key("http://api/v1/admin", "bola", "id")
        oracle.record(key, 403, 100)
        oracle.record(key, 200, 500)
        assert oracle.detect_bypass(key)

    def test_no_bypass_on_normal_flow(self):
        oracle = ShannonOracle()
        key = oracle.make_key("http://api/v1/users", "xss", "q")
        oracle.record(key, 200, 500)
        oracle.record(key, 200, 510)
        assert not oracle.detect_bypass(key)


class TestCalculateEntropy:
    def test_uniform_distribution_zero_entropy(self):
        data = ["200_md"] * 10
        h = calculate_entropy(data)
        assert h < EXHAUSTION_THRESHOLD

    def test_diverse_responses_high_entropy(self):
        data = ["200_md", "403_xs", "500_sm", "200_lg", "422_xs"] * 4
        h = calculate_entropy(data)
        assert h > 1.0

    def test_insufficient_samples_returns_max(self):

        h = calculate_entropy(["200_md", "200_md"])
        assert h == 1.0


class TestBuildSignature:
    def test_xs_bucket(self):
        assert build_response_signature(200, 50) == "200_xs"

    def test_sm_bucket(self):
        assert build_response_signature(403, 200) == "403_sm"

    def test_md_bucket(self):
        assert build_response_signature(200, 1000) == "200_md"

    def test_lg_bucket(self):
        assert build_response_signature(500, 5000) == "500_lg"
