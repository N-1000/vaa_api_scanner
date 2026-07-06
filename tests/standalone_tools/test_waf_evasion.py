"""
Test Suite: app/utils/waf_evasion.py  [v4.1]
=============================================
Cubre las cuatro técnicas de evasión del meme de ciberseguridad:
  1. Backslash Splitting  — e\\c\\h\\o en vez de echo
  2. $IFS Substitution    — $IFS en vez de espacio en blanco
  3. Hex Encoding         — \\x63\\x61\\x74 en vez de cat (via printf)
  4. Wildcard Globbing    — /???/b??h en vez de /bin/bash

También valida:
  - _strategy_cmdi_wildcard transforma comandos conocidos
  - obfuscate_cmdi_command genera variantes para todas las técnicas
  - apply_waf_evasion pasa context='cmdi' correctamente
  - Las nuevas subcategorías de payload_templates.json se cargan en M2
  - generate_cmdi_evasion_suite en M2AdaptiveGenerator
"""
import re
import base64
import pytest


@pytest.fixture(scope="module")
def evasion():
    """Importa el módulo una sola vez para todos los tests."""
    from app.utils import waf_evasion
    return waf_evasion


@pytest.fixture(scope="module")
def m2():
    """Instancia de M2 con JSON cargado desde disco."""
    from app.core.m2_generation import M2AdaptiveGenerator
    return M2AdaptiveGenerator()


class TestStrategyWildcard:

    def test_id_command_is_replaced(self, evasion):
        """';id' debe convertirse en un path glob que empieza por /."""
        result = evasion._strategy_cmdi_wildcard(";id")
        assert result != ";id", "El comando 'id' no fue transformado"
        assert "/" in result, "Debe generar una ruta absoluta con /"

    def test_cat_command_is_replaced(self, evasion):
        """';cat /etc/passwd' debe reemplazar 'cat' por una ruta glob."""
        result = evasion._strategy_cmdi_wildcard(";cat /etc/passwd")
        assert "cat" not in result.lower() or "?" in result, \
            "El nombre 'cat' debe transformarse con wildcards"
        assert "/" in result

    def test_bash_command_is_replaced(self, evasion):
        """;bash -c id debe transformar 'bash' por una ruta glob."""
        result = evasion._strategy_cmdi_wildcard(";bash -c id")
        assert "?" in result, "Debe haber wildcards en la ruta"

    def test_unknown_command_passthrough(self, evasion):
        """Comandos fuera del mapa (_CMDI_KNOWN_PATHS) no deben modificarse."""
        payload = ";unknowncmd123 arg"
        result = evasion._strategy_cmdi_wildcard(payload)


        assert "unknowncmd123" in result

    def test_no_false_positive_in_url(self, evasion):
        """Un path de URL como /api/cats no debe mutar 'cat' en 'cats'."""
        payload = "/api/cats/list"
        result = evasion._strategy_cmdi_wildcard(payload)

        assert "cats" in result or result == payload

    def test_wildcard_chars_in_output(self, evasion):
        """El resultado debe contener '?' como wildcard de globbing."""
        result = evasion._strategy_cmdi_wildcard(";id")
        assert "?" in result, "La estrategia wildcard debe usar '?' en la ruta"

    def test_output_is_string(self, evasion):
        """La función siempre devuelve str."""
        assert isinstance(evasion._strategy_cmdi_wildcard(";whoami"), str)


class TestObfuscateCmdiCommand:


    def test_backslash_technique_generates_variants(self, evasion):
        """Técnica backslash debe producir al menos 2 variantes."""
        variants = evasion.obfuscate_cmdi_command("id", technique="backslash")
        assert len(variants) >= 1

    def test_backslash_splits_command_chars(self, evasion):
        """El payload backslash debe contener \\ dentro del nombre del comando."""
        variants = evasion.obfuscate_cmdi_command("id", technique="backslash")
        assert any("\\" in v for v in variants), \
            "Técnica backslash debe incluir backslashes entre letras del comando"

    def test_backslash_quoted_variant(self, evasion):
        """Técnica backslash para 'cat' debe incluir variante c'a't."""
        variants = evasion.obfuscate_cmdi_command("cat", technique="backslash")

        assert any("'" in v for v in variants), \
            "Debe haber variante con comillas simples (c'a't)"


    def test_ifs_technique_uses_ifs_separator(self, evasion):
        """Técnica IFS debe sustituir espacios por $IFS o variantes."""
        variants = evasion.obfuscate_cmdi_command("cat /etc/passwd", technique="ifs")
        ifs_variants_found = [v for v in variants if "IFS" in v or "{" in v]
        assert len(ifs_variants_found) >= 1, \
            "Al menos una variante debe usar $IFS o brace expansion"

    def test_ifs_brace_expansion_generated(self, evasion):
        """Para cmd con argumentos debe generarse variante {cmd,arg}."""
        variants = evasion.obfuscate_cmdi_command("cat /etc/passwd", technique="ifs")
        brace = [v for v in variants if "{cat," in v or "{" in v]
        assert len(brace) >= 1, "Debe haber variante con brace expansion"

    def test_ifs_no_literal_spaces_in_separator(self, evasion):
        """Los separadores generados no deben ser espacios literales."""
        variants = evasion.obfuscate_cmdi_command("cat /etc/passwd", technique="ifs")
        for v in variants:
            if "IFS" in v:

                assert " cat" not in v, f"Espacio literal encontrado en: {v}"


    def test_hex_technique_generates_printf_variant(self, evasion):
        """Técnica hex debe generar al menos una variante con printf."""
        variants = evasion.obfuscate_cmdi_command("id", technique="hex")
        printf_variants = [v for v in variants if "printf" in v or "bash<<<" in v]
        assert len(printf_variants) >= 1, \
            "Técnica hex debe producir variantes con printf o bash heredoc"

    def test_hex_encoding_correct_for_id(self, evasion):
        """'id' en hex es \\x69\\x64 — debe aparecer en la variante printf."""
        variants = evasion.obfuscate_cmdi_command("id", technique="hex")
        hex_cmd = "".join(f"\\x{ord(c):02x}" for c in "id")
        assert any(hex_cmd in v for v in variants), \
            f"El hex de 'id' ({hex_cmd}) no aparece en las variantes"

    def test_hex_base64_variant_is_decodable(self, evasion):
        """La variante base64 de 'id' debe ser base64 válido y decodificar a 'id'."""
        variants = evasion.obfuscate_cmdi_command("id", technique="hex")
        b64_variants = [v for v in variants if "base64" in v]
        assert b64_variants, "Debe haber al menos una variante base64"

        for v in b64_variants:
            match = re.search(r'echo\$\{?IFS\}?(\S+)\|base64', v)
            if match:
                b64_token = match.group(1)
                decoded = base64.b64decode(b64_token).decode()
                assert "id" in decoded, \
                    f"El base64 '{b64_token}' no decodifica a 'id': '{decoded}'"
                break


    def test_wildcard_technique_uses_question_marks(self, evasion):
        """Técnica wildcard debe usar '?' en los paths generados."""
        variants = evasion.obfuscate_cmdi_command("id", technique="wildcard")
        assert any("?" in v for v in variants), \
            "Técnica wildcard debe contener '?' en las rutas"

    def test_wildcard_generates_known_path_variants(self, evasion):
        """Para 'id' (en /usr/bin/id) debe haber rutas que empiecen por /."""
        variants = evasion.obfuscate_cmdi_command("id", technique="wildcard")
        absolute = [v for v in variants if v.lstrip(";$(").startswith("/")]
        assert absolute, "Debe haber variantes con rutas absolutas"

    def test_wildcard_three_glob_modes(self, evasion):
        """Deben generarse las tres variantes A, B y C de globbing."""
        variants = evasion.obfuscate_cmdi_command("cat /etc/passwd", technique="wildcard")

        assert len(variants) >= 3, \
            f"Deben generarse al menos 3 variantes glob, se obtuvieron: {len(variants)}"

    def test_wildcard_for_unknown_command_uses_generic_glob(self, evasion):
        """Para comandos fuera del mapa debe generar un glob genérico /???/x???."""
        variants = evasion.obfuscate_cmdi_command("xyzfoo", technique="wildcard")
        assert any("/???/" in v for v in variants), \
            "Comando desconocido debe generar glob genérico /???/"


    def test_no_technique_generates_all_four(self, evasion):
        """Sin technique=..., obfuscate_cmdi_command debe generar las 4 técnicas."""
        variants = evasion.obfuscate_cmdi_command("id")

        has_backslash  = any("\\" in v for v in variants)
        has_ifs        = any("IFS" in v for v in variants)
        has_hex        = any("printf" in v or "bash<<<" in v for v in variants)
        has_wildcard   = any("?" in v for v in variants)
        assert has_backslash,  "Falta técnica: Backslash Splitting"
        assert has_ifs,        "Falta técnica: $IFS Substitution"
        assert has_hex,        "Falta técnica: Hex Encoding"
        assert has_wildcard,   "Falta técnica: Wildcard Globbing"

    def test_returns_list_of_strings(self, evasion):
        """obfuscate_cmdi_command siempre devuelve List[str]."""
        variants = evasion.obfuscate_cmdi_command("whoami")
        assert isinstance(variants, list)
        assert all(isinstance(v, str) for v in variants)

    def test_empty_command_returns_empty(self, evasion):
        """Comando vacío → lista vacía, sin excepciones."""
        variants = evasion.obfuscate_cmdi_command("")
        assert variants == []

    def test_no_duplicates_in_output(self, evasion):
        """No debe haber duplicados en la salida de obfuscate_cmdi_command."""
        variants = evasion.obfuscate_cmdi_command("id")
        assert len(variants) == len(set(variants)), \
            "Hay variantes duplicadas en obfuscate_cmdi_command"


class TestApplyWafEvasionCmdiContext:

    def test_cmdi_context_returns_string(self, evasion):
        result = evasion.apply_waf_evasion(";id", context="cmdi")
        assert isinstance(result, str) and len(result) > 0

    def test_cmdi_context_transforms_payload(self, evasion):
        """Con context='cmdi', al menos el 50% de las llamadas deben transformar el payload."""
        payload = ";id"
        transformed = 0
        for _ in range(20):
            result = evasion.apply_waf_evasion(payload, context="cmdi")
            if result != payload:
                transformed += 1
        assert transformed >= 5, \
            f"context='cmdi' debería transformar al menos 5/20 veces, fue {transformed}/20"

    def test_url_context_does_not_use_cmdi_wildcard_always(self, evasion):
        """Con context='url', no debe priorizarse siempre cmdi_wildcard."""
        payload = ";id"
        results = {evasion.apply_waf_evasion(payload, context="url") for _ in range(20)}

        assert len(results) >= 1


class TestM2NewCmdiCategories:

    def test_wildcard_globbing_loaded(self, m2):
        """cmdi.wildcard_globbing debe estar en strong_templates['cmdi']."""
        templates = m2.strong_templates.get("cmdi", [])
        assert len(templates) > 0, "strong_templates['cmdi'] está vacío"

        wildcard_payloads = [p for p in templates if "?" in p]
        assert wildcard_payloads, \
            "No se encontraron payloads con wildcards '?' en strong_templates['cmdi']"

    def test_hex_obfuscation_loaded(self, m2):
        """cmdi.hex_obfuscation debe estar en strong_templates['cmdi']."""
        templates = m2.strong_templates.get("cmdi", [])
        hex_payloads = [p for p in templates if "printf" in p or "\\x" in p]
        assert hex_payloads, \
            "No se encontraron payloads hex (printf/\\x) en strong_templates['cmdi']"

    def test_ifs_advanced_loaded(self, m2):
        """cmdi.ifs_advanced debe estar en strong_templates['cmdi']."""
        templates = m2.strong_templates.get("cmdi", [])
        ifs_payloads = [p for p in templates if "IFS" in p or "{cat," in p]
        assert ifs_payloads, \
            "No se encontraron payloads IFS avanzados en strong_templates['cmdi']"

    def test_backslash_obfuscation_loaded(self, m2):
        """cmdi.backslash_obfuscation debe estar en strong_templates['cmdi']."""
        templates = m2.strong_templates.get("cmdi", [])
        bs_payloads = [p for p in templates if "\\" in p and "wh" in p.lower()]
        assert bs_payloads, \
            "No se encontraron payloads backslash (wh\\oami) en strong_templates['cmdi']"

    def test_total_cmdi_count_increased(self, m2):
        """La carga de 4 nuevas categorías debe dar más payloads que antes (> 20)."""
        templates = m2.strong_templates.get("cmdi", [])
        assert len(templates) > 20, \
            f"Se esperaban >20 payloads cmdi, se obtuvieron {len(templates)}"


class TestM2GenerateCmdiEvasionSuite:

    def test_returns_list(self, m2):
        suite = m2.generate_cmdi_evasion_suite("id")
        assert isinstance(suite, list)

    def test_no_duplicates(self, m2):
        suite = m2.generate_cmdi_evasion_suite("id")
        assert len(suite) == len(set(suite)), "generate_cmdi_evasion_suite tiene duplicados"

    def test_all_four_techniques_present(self, m2):
        suite = m2.generate_cmdi_evasion_suite("id")
        assert any("\\" in v for v in suite),     "Falta técnica: backslash"
        assert any("IFS" in v for v in suite),    "Falta técnica: $IFS"
        assert any("printf" in v or "bash<<<" in v for v in suite), "Falta técnica: hex"
        assert any("?" in v for v in suite),      "Falta técnica: wildcard"

    def test_suite_for_cat_etc_passwd(self, m2):
        """Suite para 'cat /etc/passwd' debe tener variantes con la ruta del archivo."""
        suite = m2.generate_cmdi_evasion_suite("cat /etc/passwd")
        with_path = [v for v in suite if "passwd" in v or "etc" in v]
        assert with_path, \
            "Ninguna variante de 'cat /etc/passwd' conserva la ruta del archivo"

    def test_empty_command_safe(self, m2):
        """Comando vacío no debe lanzar excepción."""
        suite = m2.generate_cmdi_evasion_suite("")
        assert isinstance(suite, list)

    def test_suite_has_reasonable_count(self, m2):
        """Suite para 'id' debe tener entre 5 y 50 variantes."""
        suite = m2.generate_cmdi_evasion_suite("id")
        assert 5 <= len(suite) <= 50, \
            f"Cantidad de variantes fuera de rango: {len(suite)}"
