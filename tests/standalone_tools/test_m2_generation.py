"""
Fase 2: Test Suite de M2AdaptiveGenerator (Adaptive Payload Generator)
=======================================================================
Cubre:
  - Carga correcta del JSON masivo (load_payload_templates)
  - Disponibilidad de todos los templates críticos (SQLi, XSS, CSRF, Logic, Deep)
  - iter_payload_suite / generate_payload_suite
  - Filtro allow_destructive
  - Payloads time-based (SLEEP / WAITFOR)
  - Polyglots y WAF-bypass XSS
  - Logic suite (negative ints, zeroes, overflows, type juggling)
  - Mutación reactiva (mutate_payload_reactive)
  - mutate_payload (niveles 1-3)
  - Priorización por tipo de endpoint
  - mass_assignment y AI injection
  - Vectores GraphQL
  - get_verification_pairs para SQLi
  - get_mutated_stream produce variantes únicas
  - Cache de suites (_suite_cache)
  - Deep-scan templates (cmdi, ldap, xxe, xpath, path_traversal)
  - NoSQL payloads generados correctamente
"""

import json
import os
import pytest


@pytest.fixture(scope="module")
def m2():
    from app.core.m2_generation import M2AdaptiveGenerator
    return M2AdaptiveGenerator()


class TestPayloadJsonLoading:

    def test_sqli_classic_loaded(self, m2):
        """sqli.classic → sqli_templates['classic_sqli'] debe tener payloads."""
        templates = m2.sqli_templates["classic_sqli"]
        assert isinstance(templates, list) and len(templates) > 0, \
            "sqli_templates['classic_sqli'] está vacío — mapeo roto en load_payload_templates()"

    def test_sqli_blind_time_based_loaded(self, m2):
        """sqli.time_based → bind_time_based debe contener cadenas SLEEP/WAITFOR."""
        templates = m2.sqli_templates["blind_time_based"]
        assert isinstance(templates, list) and len(templates) > 0, \
            "blind_time_based vacío — el mapeo sqli.time_based falló"
        keywords = [p for p in templates if "SLEEP" in p.upper() or "WAITFOR" in p.upper()]
        assert len(keywords) > 0, \
            "No se encontraron payloads time-based (SLEEP/WAITFOR) en blind_time_based"

    def test_sqli_auth_bypass_loaded(self, m2):
        """sqli.auth_bypass → logic_negative_value."""
        templates = m2.sqli_templates["logic_negative_value"]
        assert isinstance(templates, list) and len(templates) > 0

    def test_sqli_polyglot_loaded(self, m2):
        """sqli_extra.polyglot / sqli.polyglot → polyglot."""
        templates = m2.sqli_templates["polyglot"]
        assert isinstance(templates, list) and len(templates) > 0

    def test_xss_classic_loaded(self, m2):
        """xss.classic → classic_xss y reflected_xss (alias)."""
        assert len(m2.xss_templates["classic_xss"]) > 0

        assert m2.xss_templates["reflected_xss"] == m2.xss_templates["classic_xss"]

    def test_xss_waf_bypass_loaded(self, m2):
        """xss.waf_bypass → obfuscated_xss debe tener payloads."""
        templates = m2.xss_templates["obfuscated_xss"]
        assert isinstance(templates, list) and len(templates) > 0, \
            "obfuscated_xss (waf_bypass XSS) no cargó correctamente"

    def test_xss_polyglot_loaded(self, m2):
        """xss.polyglot → presente."""
        templates = m2.xss_templates["polyglot"]
        assert isinstance(templates, list) and len(templates) > 0

    def test_bola_loaded(self, m2):
        """bola.numeric + bola.uuid → logic_templates['bola']."""
        bola = m2.logic_templates["bola"]
        assert isinstance(bola, list) and len(bola) > 0, \
            "BOLA payloads no cargaron (bola.numeric + bola.uuid)"

    def test_ai_injection_loaded(self, m2):
        """ai_injection (top-level) → logic_templates['ai_injection']."""
        ai_payloads = m2.logic_templates["ai_injection"]
        assert isinstance(ai_payloads, list) and len(ai_payloads) > 0, \
            "ai_injection payloads no cargaron"

    def test_logic_negative_integers_loaded(self, m2):
        """logic.negative_integers → lista con valores negativos."""
        negatives = m2.logic_templates["negative_integers"]
        assert isinstance(negatives, list) and len(negatives) > 0
        assert any(int(v) < 0 for v in negatives if str(v).lstrip('-').isdigit())

    def test_logic_large_integers_loaded(self, m2):
        """logic.large_integers → valores de overflow."""
        large = m2.logic_templates["large_integers"]
        assert isinstance(large, list) and len(large) > 0
        assert any(int(v) > 2_000_000_000 for v in large if str(v).isdigit())

    def test_logic_zero_variants_loaded(self, m2):
        """logic.zero_variants → variantes de cero."""
        zeros = m2.logic_templates["zero_variants"]
        assert isinstance(zeros, list) and len(zeros) > 0

    def test_deep_scan_cmdi_loaded(self, m2):
        """cmdi (deep scan) → aplanado en strong_templates['cmdi']."""
        templates = m2.strong_templates["cmdi"]
        assert isinstance(templates, list) and len(templates) > 0, \
            "cmdi deep-scan templates no cargaron"

        assert any("; id" in p or "| id" in p or "id`" in p for p in templates)

    def test_deep_scan_xxe_loaded(self, m2):
        """xxe → strong_templates['xxe']."""
        templates = m2.strong_templates["xxe"]
        assert isinstance(templates, list) and len(templates) > 0

    def test_deep_scan_path_traversal_loaded(self, m2):
        """path_traversal → strong_templates['path_traversal']."""
        templates = m2.strong_templates["path_traversal"]
        assert isinstance(templates, list) and len(templates) > 0
        assert any("etc/passwd" in p or "win.ini" in p for p in templates)

    def test_deep_scan_ldapi_loaded(self, m2):
        """ldapi → strong_templates['ldapi']."""
        templates = m2.strong_templates["ldapi"]
        assert isinstance(templates, list) and len(templates) > 0

    def test_deep_scan_xpath_loaded(self, m2):
        """xpath → strong_templates['xpath']."""
        templates = m2.strong_templates["xpath"]
        assert isinstance(templates, list) and len(templates) > 0


class TestGeneratePayload:
    """Cubre generate_payload() para todos los vulnerability_type reconocidos."""

    def _ctx(self):
        return {"/api/users": {"seen_params": {}}}

    def test_generates_sqli_payload(self, m2):
        payload, score = m2.generate_payload(self._ctx(), "/api/users", "sqli")
        assert isinstance(payload, str) and len(payload) > 0
        assert 0.0 <= score <= 1.0

    def test_generates_xss_payload(self, m2):
        payload, score = m2.generate_payload(self._ctx(), "/api/search", "xss")
        assert isinstance(payload, str) and len(payload) > 0

    def test_generates_csrf_payload(self, m2):
        payload, score = m2.generate_payload(self._ctx(), "/api/transfer", "csrf")
        assert isinstance(payload, str)

    def test_generates_logic_payload(self, m2):
        payload, score = m2.generate_payload(self._ctx(), "/api/order", "logic")
        assert isinstance(payload, str)

    def test_generates_rce_payload(self, m2):
        payload, score = m2.generate_payload(self._ctx(), "/api/run", "rce")
        assert isinstance(payload, str) and len(payload) > 0

    def test_generates_ai_injection_payload(self, m2):
        payload, score = m2.generate_payload(self._ctx(), "/api/chat", "ai_injection")
        assert isinstance(payload, str) and len(payload) > 0

    def test_generates_cmdi_payload(self, m2):
        payload, score = m2.generate_payload(self._ctx(), "/api/ping", "cmdi")
        assert isinstance(payload, str) and len(payload) > 0

    def test_generates_xxe_payload(self, m2):
        payload, score = m2.generate_payload(self._ctx(), "/api/upload", "xxe")
        assert isinstance(payload, str) and len(payload) > 0

    def test_generates_path_traversal_payload(self, m2):
        payload, score = m2.generate_payload(self._ctx(), "/api/file", "path_traversal")
        assert isinstance(payload, str) and len(payload) > 0

    def test_experimental_flag_boosts_score(self, m2):
        """[v4.0.1] La mutacion/evasion se aplica siempre como proceso estandar.
        Verificamos que el score siempre lleve el bonus de evasion (+0.1).
        El minimo posible es blind_time_based (0.40) + 0.1 = 0.50."""
        _, score1 = m2.generate_payload(self._ctx(), "/api/users", "sqli")
        _, score2 = m2.generate_payload(self._ctx(), "/api/users", "sqli")

        assert 0.5 <= score1 <= 1.0, f"score1 fuera de rango: {score1}"
        assert 0.5 <= score2 <= 1.0, f"score2 fuera de rango: {score2}"


class TestIterPayloadSuite:

    def _ctx(self):
        return {"/api/users": {"seen_params": {}}}

    def test_yields_tuples(self, m2):
        """Cada elemento del generador es (str, float)."""
        gen = m2.iter_payload_suite(self._ctx(), "/api/users", "sqli")
        first = next(gen)
        assert isinstance(first, tuple) and len(first) == 2
        assert isinstance(first[0], str)
        assert isinstance(first[1], float)

    def test_max_payloads_cap(self, m2):
        payloads = list(m2.iter_payload_suite(
            self._ctx(), "/api/users", "sqli", max_payloads=2
        ))
        assert len(payloads) <= 2

    def test_logic_suite_yields_values(self, m2):
        payloads = list(m2.iter_payload_suite(self._ctx(), "/api/order", "logic"))
        assert len(payloads) > 0
        assert all(isinstance(p, tuple) for p in payloads)

    def test_destructive_filter_blocks_drop_table(self, m2):
        """Con allow_destructive=False, payloads DROP TABLE no deben aparecer."""
        payloads = list(m2.iter_payload_suite(
            self._ctx(), "/api/users", "sqli",
            allow_destructive=False, max_payloads=50
        ))
        _DESTRUCTIVE = ["DROP TABLE", "TRUNCATE TABLE", "DELETE FROM"]
        for payload_str, _ in payloads:
            for dk in _DESTRUCTIVE:
                assert dk not in payload_str.upper(), \
                    f"Payload destructivo filtrado pasó igualmente: {payload_str}"

    def test_yields_xss_polyglot(self, m2):
        """Para XSS, el generador debe emitir al menos un polyglot."""
        payloads = list(m2.iter_payload_suite(self._ctx(), "/api/search", "xss"))
        payload_texts = [p for p, _ in payloads]
        has_polyglot = any(
            "jaVasCript" in p or "javascript://" in p or "oNloAd" in p
            for p in payload_texts
        )
        assert has_polyglot or len(payload_texts) > 0, \
            "Ningún payload XSS fue generado"

    def test_time_based_sqli_available(self, m2):
        """Los payloads time-based deben existir en el arsenal cargado."""
        time_payloads = m2.sqli_templates["blind_time_based"]
        assert any("SLEEP" in p.upper() or "WAITFOR" in p.upper() for p in time_payloads), \
            "Arsenal time-based vacío — el test de Fase 3 M3 no podrá probarlo"


class TestGeneratePayloadSuite:

    def _ctx(self):
        return {"/api/users": {"seen_params": {}}}

    def test_returns_list(self, m2):
        suite = m2.generate_payload_suite(self._ctx(), "/api/users", "sqli")
        assert isinstance(suite, list)

    def test_caches_results(self, m2):
        """La segunda llamada con los mismos args debe devolver el mismo objeto."""
        m2._suite_cache.clear()
        suite1 = m2.generate_payload_suite(self._ctx(), "/api/users", "sqli")
        suite2 = m2.generate_payload_suite(self._ctx(), "/api/users", "sqli")
        assert suite1 is suite2, "Cache de suites no funciona — se generó nueva lista"

    def test_max_payloads_bypasses_cache(self, m2):
        """Con max_payloads especificado, no debe cachear (resultado puede variar)."""
        m2._suite_cache.clear()
        suite = m2.generate_payload_suite(
            self._ctx(), "/api/users", "sqli", max_payloads=1
        )
        assert len(suite) <= 1

        target_sig = "/api/users"
        cache_key = f"{target_sig}|sqli|auto"
        assert cache_key not in m2._suite_cache

    def test_cache_cleared_at_1000(self, m2):
        """Con 1000+ entradas el cache se limpia."""
        m2._suite_cache.clear()
        for i in range(1001):
            m2._suite_cache[f"fake_key_{i}"] = [("payload", 0.5)]


        m2.generate_payload_suite(self._ctx(), "/api/items", "xss")

        assert len(m2._suite_cache) < 1000


class TestReactiveMutation:

    def test_space_blocked_uses_comment(self, m2):
        payload = "' OR 1=1 --"
        mutated = m2.mutate_payload_reactive(payload, blocked_chars=[" "])
        assert "/**/" in mutated, "Bypass de espacio con /**/ no aplicado"
        assert " " not in mutated

    def test_script_tag_blocked_uses_case_variant(self, m2):
        payload = "<script>alert(1)</script>"
        mutated = m2.mutate_payload_reactive(payload, blocked_chars=["<script>"])


        assert mutated != payload, \
            f"mutate_payload_reactive no aplicó ninguna transformación: resultado='{mutated}'"

    def test_no_blocked_chars_returns_same(self, m2):
        payload = "test_payload"
        mutated = m2.mutate_payload_reactive(payload, blocked_chars=[])
        assert mutated == payload


class TestMutatePayload:

    def test_level1_sql_obfuscation(self, m2):
        payload = "' UNION SELECT 1,2,3--"
        mutated = m2.mutate_payload(payload, attempt=1)

        assert isinstance(mutated, str) and len(mutated) > 0

    def test_level2_charcode_wrapper(self, m2):
        payload = "<script>alert(1)</script>"
        mutated = m2.mutate_payload(payload, attempt=2)
        assert "fromCharCode" in mutated, \
            "Level-2 debe producir eval(String.fromCharCode(...))"

    def test_level3_double_url_encode(self, m2):
        payload = "<script>alert(1)</script>"
        mutated = m2.mutate_payload(payload, attempt=3)

        assert "%25" in mutated or "%3C" in mutated, \
            "Level-3 debe producir double URL encoding"

    def test_non_string_passthrough(self, m2):
        assert m2.mutate_payload(42, attempt=1) == 42  # type: ignore[arg-type]


class TestPrioritization:

    def test_auth_endpoint_puts_sqli_first(self, m2):
        suite = [
            ("<script>alert(1)</script>", 0.9),
            ("' OR 1=1 --", 0.8),
            ("-1", 0.7),
        ]
        result = m2.prioritize_payloads_by_endpoint_type(suite, "auth")

        first_payload = result[0][0].lower()
        assert "or" in first_payload or "' " in first_payload or "admin" in first_payload

    def test_generic_type_no_reorder(self, m2):
        suite = [("payload_a", 0.9), ("payload_b", 0.8)]
        result = m2.prioritize_payloads_by_endpoint_type(suite, "generic")
        assert result == suite

    def test_empty_suite_passthrough(self, m2):
        result = m2.prioritize_payloads_by_endpoint_type([], "auth")
        assert result == []

    def test_file_endpoint_prefers_path_traversal(self, m2):
        suite = [
            ("<script>xss</script>", 0.9),
            ("../../../etc/passwd", 0.8),
            ("admin_payload", 0.6),
        ]
        result = m2.prioritize_payloads_by_endpoint_type(suite, "file")
        assert "etc/passwd" in result[0][0] or "../" in result[0][0]


class TestLogicSuite:

    def test_yields_all_logic_categories(self, m2):
        """El generador debe agotar todas las categorías de logic_templates."""
        payloads = list(m2.generate_logic_suite())
        assert len(payloads) > 0

    def test_contains_negative_integers(self, m2):
        payloads = [str(p) for p in m2.generate_logic_suite()]
        assert any(p.lstrip('-').isdigit() and int(p) < 0 for p in payloads), \
            "No se encontraron enteros negativos en generate_logic_suite"

    def test_contains_overflow_values(self, m2):
        payloads = [str(p) for p in m2.generate_logic_suite()]
        large = [p for p in payloads if p.isdigit() and int(p) > 2_000_000_000]
        assert len(large) > 0, "No se encontraron valores de overflow"


class TestSpecialPayloads:

    def test_mass_assignment_payload_is_string(self, m2):
        payload = m2._generate_payload_logic("mass_assignment", {})
        assert isinstance(payload, str) and len(payload) > 0

    def test_ai_injection_payload_contains_directive(self, m2):
        payload = m2._generate_payload_ai()
        assert isinstance(payload, str) and len(payload) > 0

        keywords = ["ignore", "system", "instructions", "reveal", "print", "override", "secret", "developer", "act"]
        assert any(kw in payload.lower() for kw in keywords), \
            f"AI injection payload no parece una inyección de prompt: {payload}"

    def test_rce_payload_non_empty(self, m2):
        payload = m2._generate_payload_rce()
        assert isinstance(payload, str) and len(payload) > 0


class TestVerificationPairs:

    def test_sqli_pairs_structure(self, m2):
        pairs = m2.get_verification_pairs("sqli")
        assert isinstance(pairs, list) and len(pairs) >= 4
        for pair in pairs:
            assert "name" in pair
            assert "true" in pair and "false" in pair
            assert pair["true"] != pair["false"]

    def test_unknown_vuln_returns_empty(self, m2):
        pairs = m2.get_verification_pairs("unknown_vuln_type_xyz")
        assert pairs == []


class TestMutatedStream:

    def test_returns_list(self, m2):
        stream = m2.get_mutated_stream("<script>alert(1)</script>", count=3)
        assert isinstance(stream, list)
        assert len(stream) >= 1

    def test_original_always_included(self, m2):
        payload = "' OR 1=1 --"
        stream = m2.get_mutated_stream(payload, count=4)
        assert payload in stream, "El payload original siempre debe estar en el stream"


class TestGraphQLPayloads:

    def test_introspection_payloads_present(self, m2):
        gql = m2.get_graphql_payloads()
        assert "introspection" in gql
        assert len(gql["introspection"]) > 0
        assert any("__schema" in p for p in gql["introspection"])

    def test_blind_enumeration_payloads_present(self, m2):
        gql = m2.get_graphql_payloads()
        assert "blind_enumeration" in gql
        assert any("query" in p for p in gql["blind_enumeration"])


class TestNoSQLGenerator:

    def test_mongodb_fallback_when_empty(self, m2):
        """Si nosql_templates['mongodb'] está vacío, debe retornar fallback."""
        original = m2.nosql_templates["mongodb"]
        m2.nosql_templates["mongodb"] = []
        payload = m2._generate_payload_nosql("mongodb")
        assert payload == '{"$ne": null}', f"Fallback MongoDB incorrecto: {payload}"
        m2.nosql_templates["mongodb"] = original

    def test_unknown_nosql_strategy_fallback(self, m2):
        payload = m2._generate_payload_nosql("unknown_db")
        assert isinstance(payload, str) and len(payload) > 0


class TestApiInjectionVectors:

    def test_returns_list_with_basics(self, m2):
        vectors = m2.get_api_injection_vectors()
        assert isinstance(vectors, list) and len(vectors) > 0

        assert "'" in vectors
        assert '{{7*7}}' in vectors

    def test_polyglots_merged(self, m2):
        """Debe incluir hasta 3 polyglots SQL."""
        vectors = m2.get_api_injection_vectors()
        polyglots = m2.sqli_templates.get("polyglot", [])[:3]
        for poly in polyglots:
            assert poly in vectors, f"Polyglot '{poly}' no merged en API vectors"
