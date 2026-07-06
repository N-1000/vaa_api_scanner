"""
Test de Validacion del Harvest (M6 Doppelganger)
Verifica que los response bodies del HAR se estan cosechando correctamente.

Uso:
    cd vaa_api_scanner_rama1
    python tests/lab_benchmark/test_harvest.py
"""
import sys, json, re
from pathlib import Path


ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

HAR_PATH = ROOT / "tests" / "target_app" / "simulated_navigation.har"

GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

import os; os.system('')


def test_har_contents():
    """Analiza el HAR crudo antes de pasarlo a M6."""
    print(f"\n{BOLD}=== FASE 1: Inspeccion del HAR crudo ==={RESET}")

    if not HAR_PATH.exists():
        print(f"{RED}[ERROR] HAR no encontrado: {HAR_PATH}{RESET}")
        return None

    with open(HAR_PATH, "r", encoding="utf-8") as f:
        har = json.load(f)

    entries = har.get("log", {}).get("entries", [])
    print(f"{CYAN}[HAR] Total de entradas: {len(entries)}{RESET}")

    uuid_pat = re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        re.IGNORECASE
    )

    all_uuids     = []
    all_num_ids   = []
    all_emails    = []
    entries_with_response = 0

    for i, entry in enumerate(entries):
        req_url = entry.get("request", {}).get("url", "")
        resp    = entry.get("response", {})
        content = resp.get("content", {})
        text    = content.get("text", "") or ""

        if text and len(text) > 5:
            entries_with_response += 1

            uuids   = uuid_pat.findall(text)
            num_ids = re.findall(r'"(?:id|userId|user_id|order_id|orderId)"\s*:\s*(\d{1,10})', text)
            emails  = re.findall(r'"email"\s*:\s*"([^"]+)"', text)

            if uuids or num_ids or emails:
                print(f"\n  {CYAN}[Entrada {i+1}] {req_url}{RESET}")
                if uuids:
                    print(f"    {GREEN}UUIDs:    {uuids}{RESET}")
                    all_uuids.extend(uuids)
                if num_ids:
                    print(f"    {GREEN}Num IDs:  {num_ids}{RESET}")
                    all_num_ids.extend(num_ids)
                if emails:
                    print(f"    {GREEN}Emails:   {emails}{RESET}")
                    all_emails.extend(emails)

    print(f"\n{BOLD}--- Resumen HAR crudo ---{RESET}")
    print(f"  Entradas con response body : {entries_with_response}/{len(entries)}")
    print(f"  UUIDs totales encontrados  : {len(all_uuids)}")
    print(f"  IDs numericos encontrados  : {len(all_num_ids)}")
    print(f"  Emails encontrados         : {len(all_emails)}")

    if not entries_with_response:
        print(f"\n{YELLOW}[WARN] El HAR no tiene response bodies guardados.{RESET}")
        print(f"{YELLOW}       Regenera el HAR con: python tests/target_app/generate_har.py{RESET}")
        print(f"{YELLOW}       El generate_har.py debe incluir los campos 'content.text' en responses.{RESET}")

    return har


def test_m6_harvest(har):
    """Instancia M6 y verifica que _harvest_ids_from_har popula correctamente."""
    print(f"\n{BOLD}=== FASE 2: Test de M6._harvest_ids_from_har ==={RESET}")

    try:
        from app.core.m6_doppelganger import M6Doppelganger
        m6 = M6Doppelganger()
        print(f"{GREEN}[OK] M6Doppelganger instanciado correctamente{RESET}")
    except Exception as e:
        print(f"{RED}[ERROR] No se pudo instanciar M6: {e}{RESET}")
        return


    m6._harvest_ids_from_har(har)

    print(f"\n  Resultado de self._har_harvest:")
    print(f"    {GREEN}UUIDs cosechados    : {m6._har_harvest['uuids']}{RESET}")
    print(f"    {GREEN}IDs numericos       : {m6._har_harvest['numeric_ids']}{RESET}")
    print(f"    {GREEN}Order IDs           : {m6._har_harvest['order_ids']}{RESET}")
    print(f"    {GREEN}Emails              : {m6._har_harvest['emails']}{RESET}")


    print(f"\n{BOLD}=== FASE 3: Test de ingest_sessions (flujo completo) ==={RESET}")
    m6b = M6Doppelganger()
    try:
        m6b.ingest_sessions(har, har)
        print(f"  {GREEN}[OK] ingest_sessions completado{RESET}")
        print(f"  Sesion A endpoints: {len(m6b.session_a)}")
        print(f"  Sesion B endpoints: {len(m6b.session_b)}")
        print(f"  HAR harvest UUIDs : {m6b._har_harvest['uuids']}")
        print(f"  HAR harvest IDs   : {m6b._har_harvest['numeric_ids']}")
    except Exception as e:
        print(f"  {RED}[ERROR] ingest_sessions fallo: {e}{RESET}")
        import traceback; traceback.print_exc()


def test_generate_har_has_responses():
    """Verifica si generate_har.py incluye response bodies."""
    print(f"\n{BOLD}=== FASE 4: Verificar generate_har.py ==={RESET}")
    gen_path = ROOT / "tests" / "target_app" / "generate_har.py"
    if not gen_path.exists():
        print(f"  {YELLOW}[SKIP] generate_har.py no encontrado{RESET}")
        return

    code = gen_path.read_text(encoding="utf-8")
    has_content = '"content"' in code or "'content'" in code
    has_text    = '"text"' in code or "'text'" in code

    if has_content and has_text:
        print(f"  {GREEN}[OK] generate_har.py incluye campos 'content' y 'text' en responses{RESET}")
    else:
        print(f"  {RED}[WARN] generate_har.py puede no incluir response bodies{RESET}")
        print(f"         Busca el bloque 'response' y asegurate de incluir:")
        print(f"         'content': {{'text': resp.text, 'mimeType': 'application/json'}}")


if __name__ == "__main__":
    har = test_har_contents()
    if har:
        test_m6_harvest(har)
    test_generate_har_has_responses()

    print(f"\n{BOLD}=== CONCLUSION ==={RESET}")
    print(f"  Si UUIDs = [] en FASE 2 pero existen en FASE 1 --> bug en _harvest_ids_from_har")
    print(f"  Si UUIDs = [] en FASE 1 --> el HAR no tiene response bodies --> regenerar HAR")
    print(f"  Si UUIDs > 0 en FASE 2 --> harvest funciona correctamente\n")
