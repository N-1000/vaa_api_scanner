"""
Test del plan de ataque IDOR: verifica que los UUIDs del HAR llegan
al plan de ataque de analyze_idor_from_recon.
"""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

HAR_PATH = Path(__file__).parent.parent / "target_app" / "simulated_navigation.har"

import os; os.system('')
GREEN  = "\033[32m"; RED = "\033[31m"; CYAN = "\033[36m"; BOLD = "\033[1m"; RESET = "\033[0m"

har = json.loads(HAR_PATH.read_text(encoding="utf-8"))

from app.core.m6_doppelganger import M6Doppelganger
m6 = M6Doppelganger()
m6.ingest_sessions(har, har)

print(f"\n{BOLD}=== HAR Harvest disponible ==={RESET}")
print(f"  UUIDs    : {m6._har_harvest['uuids']}")
print(f"  Num IDs  : {m6._har_harvest['numeric_ids']}")


recon_endpoints = [
    {"url": "http://127.0.0.1:8000/api/v1/orders/{order_id}",        "method": "GET", "path": "/api/v1/orders/{order_id}"},
    {"url": "http://127.0.0.1:8000/api/v1/orders/track/{order_uuid}", "method": "GET", "path": "/api/v1/orders/track/{order_uuid}"},
    {"url": "http://127.0.0.1:8000/api/v1/mass-test/{item_id}",       "method": "GET", "path": "/api/v1/mass-test/{item_id}"},
]


harvest_engine = {"numeric_ids": [], "uuids": [], "order_ids": [], "vehicle_ids": []}

plan = m6.analyze_idor_from_recon(
    findings=[],
    base_url="http://127.0.0.1:8000",
    recon_endpoints=recon_endpoints,
    harvest=harvest_engine,
)

print(f"\n{BOLD}=== Plan de Ataque IDOR ({len(plan)} candidatos) ==={RESET}")
for p in plan:
    ep       = p["endpoint"]
    int_ids  = p["int_ids"]
    uuid_ids = p["uuid_ids"]
    source   = p["source"]


    is_uuid_ep = "uuid" in ep.lower()
    has_uuid   = len(uuid_ids) > 0
    has_ints   = len(int_ids) > 0

    status = GREEN + "OK" + RESET
    note   = ""
    if is_uuid_ep and not has_uuid:
        status = RED + "FAIL" + RESET
        note   = "  <-- endpoint UUID sin UUIDs para probar!"
    elif not is_uuid_ep and not has_ints:
        status = RED + "FAIL" + RESET
        note   = "  <-- endpoint entero sin IDs para probar!"

    print(f"\n  [{status}] {ep}")
    print(f"         int_ids  : {int_ids}")
    print(f"         uuid_ids : {uuid_ids}")
    print(f"         source   : {source}{note}")


uuid_ep = next((p for p in plan if "uuid" in p["endpoint"].lower()), None)
int_ep  = next((p for p in plan if "order_id}" in p["endpoint"].lower()), None)

print(f"\n{BOLD}=== Veredicto ==={RESET}")
if uuid_ep and uuid_ep["uuid_ids"]:
    print(f"  {GREEN}PASS: UUID endpoint tiene UUIDs reales: {uuid_ep['uuid_ids']}{RESET}")
else:
    print(f"  {RED}FAIL: UUID endpoint sin UUIDs — BOLA UUID no se puede confirmar{RESET}")

if int_ep and int_ep["int_ids"]:
    print(f"  {GREEN}PASS: Int endpoint tiene IDs reales: {int_ep['int_ids']}{RESET}")
else:
    print(f"  {RED}FAIL: Int endpoint solo con fallback [101,102,...]{RESET}")
