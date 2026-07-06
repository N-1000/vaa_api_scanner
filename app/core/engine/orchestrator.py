"""
VAA — Orchestrator v8.0 (Clean Room).

execute_mission() es ahora una secuencia plana de llamadas delegadas.
Sin lógica de ataque interna. Sin algoritmos inline.
"""
import asyncio
import time
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from app.utils.logger import logger  # pyre-ignore[21]
from app.config.settings import settings  # pyre-ignore[21]
from app.core.m1_grammar import M1GrammarModel  # pyre-ignore[21]
from app.core.m3_classification import M3IntelligentClassifier  # pyre-ignore[21]
from app.core.m6_doppelganger import M6Doppelganger  # pyre-ignore[21]
from app.core.m8_chronos import M8Chronos  # pyre-ignore[21]
from app.core.m9_params import M9ParameterDiscovery  # pyre-ignore[21]
from app.core.m74p1_navigator import M74P1Navigator  # pyre-ignore[21]
from app.core.m_passive_recon import check_exposed_docs, check_security_headers  # pyre-ignore[21]
from app.core.m_jwt_audit import JWTAuditor, extract_jwt  # pyre-ignore[21]
from app.core.network_manager import NetworkManager  # pyre-ignore[21]
from app.core.cognitive_memory import memory  # pyre-ignore[21]
from app.core.modules.openapi_parser import OpenAPIParser  # pyre-ignore[21]
from app.utils.reporter import HtmlReporter  # pyre-ignore[21]
from app.utils.ingestor import TrafficIngestor  # pyre-ignore[21]


from app.core.engine.algorithms.shannon import ShannonOracle
from app.core.engine.algorithms.similarity import normalize_dynamic_fields, calculate_similarity
from app.core.engine.models import VulnerabilityFinding, EndpointTarget
from app.core.engine.phases import validation as phase_validation
from app.core.engine.specialized import mass_assignment, bola_harvest, auth_audit


class ScanOrchestrator:
    """
    Director de orquesta. Coordina los módulos sin implementar lógica de ataque.
    Toda la lógica pesada reside en app/core/engine/{phases,specialized,algorithms}/.
    """

    def __init__(self, target: str, options: Dict[str, Any]):
        self.target  = target
        self.options = options
        self.started_at = time.time()
        
        if self.options.get("auth_refresh_cmd"):
            def _refresh_token():
                import subprocess
                import shlex
                cmd = self.options.get("auth_refresh_cmd")
                try:


                    result = subprocess.run(shlex.split(cmd), shell=False, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        return result.stdout.strip()
                except Exception as e:
                    logger.error(f"[Auth] Fallo comando de refresh: {e}")
                return None
            self.options["auth_refresh_fn"] = _refresh_token

        self.vulnerabilities: List[VulnerabilityFinding] = []
        self.validation_queue: asyncio.Queue = asyncio.Queue(maxsize=5000)
        self._queue_dedup: set = set()
        self.dedup_keys:   set = set()

        self._domain = urlparse(target).netloc or "unknown"
        self.scan_id = ""


        logger.info("[*] Iniciando Motores Neuronales (v8.0)...")
        self.m1  = M1GrammarModel()
        self.m3  = M3IntelligentClassifier()
        self.m6  = M6Doppelganger()
        self.m8  = M8Chronos()
        self.m9  = M9ParameterDiscovery()
        self.navigator      = M74P1Navigator(options)
        self.network_manager = NetworkManager(target, options)
        self.memory          = memory


        self.oracle = ShannonOracle()


        self.sem: Optional[asyncio.Semaphore] = None
        self.abort_scan_ref  = [False]
        self.stats: Dict[str, int] = {"total_requests": 0, "429_count": 0, "401_count": 0}
        self._detected_stack: List[str] = []

        self._pipeline_file: Any = None
        self._pipeline_trace_path = ""
        self._harvest: Dict[str, List[str]] = {
            "uuids": [], "numeric_ids": [], "vehicle_ids": [],
            "order_ids": [], "user_ids": [],
        }
        self._idor_victim_email = None
        self.bypass_priority_queue: List[Dict] = []
        self.token_health_checked = False
        self._last_discovered_endpoints: List[EndpointTarget] = []

        self.category_counts: Dict[str, int] = {}


    async def _record_finding(self, finding: dict, *, via_queue: bool = False) -> None:
        vuln_type_raw = str(finding.get("type", ""))
        _t = vuln_type_raw.lower()
        # Mapeo granular de categoría para dedup — evita colapso de BOLA/IDOR/BFLA/OTP en un bucket
        if any(k in _t for k in ["scripting", "xss"]):
            _cat = "xss"
        elif "sql" in _t:
            _cat = "sqli"
        elif "request forgery" in _t or "ssrf" in _t:
            _cat = "ssrf"
        elif any(k in _t for k in ["command", "rce", "cmdi"]):
            _cat = "rce"
        elif any(k in _t for k in ["bola", "broken object level"]):
            _cat = "bola"
        elif any(k in _t for k in ["idor", "idor_uuid", "idor_int"]):
            _cat = "idor"
        elif "bfla" in _t or "function level" in _t:
            _cat = "bfla"
        elif "otp" in _t:
            _cat = "otp"
        elif "mass" in _t or "assignment" in _t:
            _cat = "mass_assignment"
        elif "prompt" in _t or "injection" in _t:
            _cat = "prompt_injection"
        else:
            _cat = _t[:30]  # categoría literal para tipos no reconocidos

        params_dict = finding.get("params", {}) or {}
        p_name = list(params_dict.keys())[0] if params_dict else "_"
        base_cat_key = f"{finding.get('url', '')}|{_cat}"
        dedup_key = f"{base_cat_key}|{p_name}|{str(finding.get('payload', ''))[:50]}"


        MAX_FINDINGS_PER_ENDPOINT = 3
        
        if dedup_key in self.dedup_keys and not finding.get("verified"):
            return
            
        count = self.category_counts.get(base_cat_key, 0)
        if count >= MAX_FINDINGS_PER_ENDPOINT and not finding.get("verified"):
            return
            
        self.category_counts[base_cat_key] = count + 1
        self.dedup_keys.add(dedup_key)

        if via_queue:
            await self.validation_queue.put(finding)
        else:
            self.vulnerabilities.append(finding)


    def _pipeline_log(self, finding_id, layer, action, reason, *, url="", vuln_type="", confidence=0.0):
        if not self.options.get("debug_pipeline"):
            return
        import json as _j
        event = {"ts": time.time(), "finding_id": finding_id, "layer": layer,
                 "action": action, "reason": reason, "url": url,
                 "vuln_type": vuln_type, "confidence": round(float(confidence), 4)}
        try:
            if self._pipeline_file is None:
                import datetime as _dt
                ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                self._pipeline_trace_path = os.path.join(settings.REPORTS_DIR, f"pipeline_trace_{ts}.jsonl")
                os.makedirs(settings.REPORTS_DIR, exist_ok=True)
                self._pipeline_file = open(self._pipeline_trace_path, "a", encoding="utf-8")
            self._pipeline_file.write(_j.dumps(event, ensure_ascii=False) + "\n")
            self._pipeline_file.flush()
        except Exception as e:
            logger.debug(f"[Pipeline] Error: {e}")


    def _harvest_from_response(self, resp_text: str, url: str = "") -> None:
        import re as _re
        
        for uid in _re.findall(
            r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            resp_text, _re.IGNORECASE
        ):
            if uid not in self._harvest["uuids"] and len(self._harvest["uuids"]) < 50:
                self._harvest["uuids"].append(uid)
                
        for nid in _re.findall(r'"(?:id|userId|user_id)"\s*:\s*(\d{1,10})', resp_text):
            if nid not in self._harvest["numeric_ids"] and len(self._harvest["numeric_ids"]) < 50:
                self._harvest["numeric_ids"].append(nid)
                
        for vid in _re.findall(r'"vehicleId"\s*:\s*"([^"]{3,80})"', resp_text):
            if vid not in self._harvest["vehicle_ids"] and len(self._harvest["vehicle_ids"]) < 30:
                self._harvest["vehicle_ids"].append(vid)


    async def execute_mission(self):
        logger.info(f"[*] Misión Iniciada → {self.target}")


        if self.options.get("no_memory"):
            logger.info("[Memory] --no-memory activo.")
        else:
            await self.memory.init_pool()
        self.scan_id = await self.memory.start_mission(self._domain)
        if self.memory.enabled and not self.options.get("reset_memory"):
            exploits = await self.memory.get_prior_exploits(self._domain)
            logger.info(f"[Memory] {len(exploits)} exploits previos cargados.")


        await self._phase_passive_recon()


        endpoints = await self._phase_reconnaissance()
        self._last_discovered_endpoints = endpoints

        if not self.options.get("no_jwt_audit"):
            await self._phase_jwt_audit(endpoints)


        if self.options.get("logic_mode") or self.options.get("har_files", {}).get("a"):
            await self._phase_logical_attack()


        if endpoints:
            await auth_audit.run_bfla_vertical(
                endpoints, self.network_manager, {**self.options, "target": self.target},
                self.m1.classify_endpoint_type, self._record_finding
            )


        # Removed Fuzzer phase execution
        # Removed Graph Attack execution


        if self.options.get("mass_assign") or self.options.get("logic_mode"):
            if self.sem is None:
                _concurrency = int(self.options.get("concurrency", 5))
                self.sem = asyncio.Semaphore(_concurrency)
            await mass_assignment.run(
                endpoints, self.network_manager, self.options,
                self.sem, self._record_finding
            )


        if any(self._harvest.values()):
            await bola_harvest.run(
                endpoints, self.network_manager, self.options,
                self._harvest, self.m3.calculate_similarity, self._record_finding
            )


        victim_email = self.options.get("victim_email") or self._idor_victim_email
        if victim_email and endpoints:
            await auth_audit.run_otp_audit(
                endpoints, self.network_manager, self.options,
                victim_email, self._record_finding
            )


        if self.options.get("stress_mode"):
            await self._phase_stress_test(endpoints)


    async def _phase_stress_test(self, endpoints: list) -> None:
        """Fase de stress test usando M8 Chronos."""
        logger.info("[M8] Iniciando fase de stress test...")
        async with self.network_manager as client:
            for ep in endpoints:
                await self.m8.run_stress_test(
                    client, ep.url, ep.method,
                    concurrency=self.options.get("stress_concurrency", 10),
                    duration=self.options.get("stress_duration", 10)
                )


        await phase_validation.process_queue(
            self.validation_queue,
            self.network_manager,
            None,
            self._record_finding,
            None,
            token_health_check=self.network_manager.check_token_health,
            pipeline_log=self._pipeline_log  # callable, no el file object
        )


        self._apply_report_degradation()


        if self.memory.enabled:
            for vuln in self.vulnerabilities:
                await self.memory.memorize_exploit(
                    self._domain, urlparse(vuln.get("url", "")).path,
                    vuln.get("type", ""), vuln.get("payload", ""), vuln.get("confidence", 1.0)
                )
            await self.memory.end_mission(self.scan_id, len(self.vulnerabilities))
            await self.memory.close_pool()


        if self._pipeline_file:
            try:
                self._pipeline_file.close()
            except Exception:
                pass


        self.generate_report()


    async def _phase_passive_recon(self):
        logger.info("\n=== FASE 0: RECONOCIMIENTO PASIVO (API8+API9) ===")

        docs    = await check_exposed_docs(self.target, self.network_manager)
        headers = await check_security_headers(self.target, self.network_manager)
        for f in docs + headers:
            await self._record_finding(f)
        logger.info(f"[Passive Recon] {len(docs) + len(headers)} hallazgo(s).")

    async def _phase_reconnaissance(self) -> List[EndpointTarget]:
        logger.info("\n=== FASE 1: RECONOCIMIENTO (M74P1 STRUCTURAL) ===")
        
        target_endpoint = self.options.get("target_endpoint")
        if target_endpoint:
            logger.info(f"[*] Modo Quirúrgico Activo. Auditando unicamente: {target_endpoint}")
            method = self.options.get("target_method", "GET")
            path = urlparse(target_endpoint).path
            return [{"url": target_endpoint, "path": path, "method": method, "params": {}}]

        input_source = self.options.get("input_source")
        if not input_source:
            logger.error("No input source defined.")
            return []

        endpoints = await self.navigator.navigate_input(input_source, verify=self.network_manager.verify_ssl)
        for ep in endpoints:
            if "path" not in ep:
                ep["path"] = urlparse(ep.get("url", "")).path

        if not endpoints:
            logger.warning("[M74P1] No endpoints found. Fallback to target root.")
            endpoints.append({"url": self.target, "method": "GET", "params": {}})

        self._last_discovered_endpoints = endpoints
        return endpoints



    async def _phase_jwt_audit(self, endpoints):
        auth_header = self.options.get("auth_token", "")
        jwt_token   = extract_jwt(auth_header)
        if not jwt_token:
            return
        logger.info("\n=== FASE 1.5: JWT AUDIT (API2) ===")
        auditor = JWTAuditor(jwt_token)
        if not auditor.enabled:
            return
        target_path = None
        for ep in endpoints[:20]:
            if ep.get("source") == "markov_prediction":
                continue
            path = ep.get("path", ep.get("url", "").replace(self.target, ""))
            if any(kw in path.lower() for kw in ["dashboard", "profile", "user", "account", "me"]):
                try:
                    test = await self.network_manager.send_request_raw(ep.get("url", ""), timeout=4.0)
                    if test and test.status_code in (401, 403):
                        target_path = path
                        break
                except Exception:
                    continue
        if not target_path and endpoints:
            target_path = endpoints[0].get("path", "")
        if not target_path:
            return
        

        jwt_findings = await auditor.audit(self.target, target_path, self.network_manager)
        for f in jwt_findings:
            await self._record_finding(f)


    async def _phase_logical_attack(self):
        import json
        import os
        logger.info("\n=== FASE 2: LOGICA DE NEGOCIO (M6 DOPPELGANGER) ===")
        har_files = self.options.get("har_files", {})
        path_a = har_files.get("a")
        path_b = har_files.get("b")
        
        if not path_a:
            logger.info("[M6] Sin HAR files — omitiendo analisis HAR, continuando con IDOR desde recon context.")

        if path_a:
            logger.info(f"[*] Cargando sesiones logicas desde: {path_a} {'& ' + path_b if path_b else ''}")
            api_only = self.options.get("api_only", settings.IMPORT_API_ONLY)
            if api_only:
                 logger.info("[Filtro API] Importando unicamente endpoints sospechosos de ser API.")
            try:

                ext_a = os.path.splitext(path_a)[1].lower()
                is_burp_a = (ext_a == ".xml")
                ext_b = os.path.splitext(path_b)[1].lower() if path_b else ""
                is_burp_b = (ext_b == ".xml")

                raw_a, raw_b = None, None

                if is_burp_a:
                    logger.info("[M6] Formato Burp Suite XML detectado para sesión A")
                    traffic_a = TrafficIngestor.load_traffic(path_a, api_only=api_only)
                    burp_resp_a = TrafficIngestor.load_burp_responses(path_a)
                    if burp_resp_a:
                        self.m6._harvest_ids_from_burp(burp_resp_a)
                        logger.info(f"[M6] Harvest Burp A: {len(burp_resp_a)} responses procesados")
                else:
                    try:
                        with open(path_a, 'r', encoding='utf-8', errors='ignore') as f:
                            raw_a = json.load(f)
                    except Exception as je:
                        logger.debug(f"[M6] No se pudo cargar HAR crudo: {je}")
                    traffic_a = TrafficIngestor.load_traffic_from_dict(raw_a) if raw_a else TrafficIngestor.load_traffic(path_a, api_only=api_only)

                traffic_b = traffic_a
                if path_b:
                    if is_burp_b:
                        logger.info("[M6] Formato Burp Suite XML detectado para sesión B")
                        traffic_b = TrafficIngestor.load_traffic(path_b, api_only=api_only)
                        burp_resp_b = TrafficIngestor.load_burp_responses(path_b)
                        if burp_resp_b:
                            self.m6._harvest_ids_from_burp(burp_resp_b)
                            logger.info(f"[M6] Harvest Burp B: {len(burp_resp_b)} responses procesados")
                    else:
                        try:
                            with open(path_b, 'r', encoding='utf-8', errors='ignore') as f:
                                raw_b = json.load(f)
                        except Exception as je:
                            logger.debug(f"[M6] No se pudo cargar HAR B crudo: {je}")
                        traffic_b = TrafficIngestor.load_traffic_from_dict(raw_b) if raw_b else TrafficIngestor.load_traffic(path_b, api_only=api_only)

                self.m6.ingest_sessions(traffic_a, traffic_b, raw_har_a=raw_a, raw_har_b=raw_b)
                plans = await asyncio.to_thread(self.m6.analyze_logic_diff)
                mass_tests = await asyncio.to_thread(self.m6.analyze_mass_assignment, self.m6.session_a)
                bac_tests = await asyncio.to_thread(self.m6.generate_bac_tests)
                
                all_logic_vectors = plans + mass_tests + bac_tests
                logger.info(f"[+] M6 identifico {len(all_logic_vectors)} vectores logicos potenciales.")
                
                if all_logic_vectors:
                    for vector in all_logic_vectors:
                        v_type = vector.get("type", "UNKNOWN")
                        target_url = vector.get("target_url") or vector.get("victim_url")
                        method = vector.get("method", "GET")
                        try:
                            if v_type in ["IDOR_UUID", "IDOR_INT"]:
                                test_headers = vector.get("original_headers", {})
                                if not test_headers and hasattr(self, 'session_a') and self.session_a:
                                    test_headers = self.session_a[0].get('headers', {})
                                resp = await self.network_manager.send_request_raw(target_url, method=method, headers=test_headers, timeout=10.0)
                                if resp and resp.status_code in [200, 201, 204] and len(resp.text) > 20:
                                    body_lower = resp.text.lower()
                                    _error_kw = ['"error"', '"unauthorized"', 'forbidden', 'not found', 'invalid', 'no autorizado', 'acceso denegado', 'no encontrado', 'inválido', 'non autoris', 'accès refus', 'introuvable', 'invalide', 'não autorizado', 'acesso negado']
                                    if not any(err in body_lower for err in _error_kw):
                                        await self._record_finding({"url": target_url, "norm_url": target_url, "type": f"{v_type} (M6 CONTINUUM)", "method": method, "payload": vector.get("description", ""), "risk": "High", "confidence": 0.85, "verified": True, "validation_method": "har_continuum_diff", "report_policy": "local", "params": {}, "is_json": False, "response_text": "Detected via static HAR difference"})
                            elif v_type == "BAC_NO_AUTH":
                                resp = await self.network_manager.send_request_raw(target_url, method=method, timeout=10.0)
                                if resp and resp.status_code == 200 and len(resp.text) > 20:
                                    _bac_error_kw = ['"error"', '"unauthorized"', 'no autorizado', 'acceso denegado', 'non autoris', 'invalide']
                                    if not any(k in resp.text.lower() for k in _bac_error_kw):
                                        await self._record_finding({"url": target_url, "norm_url": target_url, "type": "BROKEN_ACCESS_CONTROL (Bypass)", "method": method, "payload": "Removed Authorization Headers", "risk": "Critical", "confidence": 0.9, "verified": True, "validation_method": "bac_no_auth", "status_code": resp.status_code, "report_policy": "local", "params": {}, "is_json": False, "response_text": resp.text[:200], "ai_razonamiento": f"El endpoint es accesible sin cabeceras de autorizacion (HTTP {resp.status_code})."})
                        except Exception as _e:
                            logger.debug(f"[M6-Execution] Error ejecutando vector {v_type} en {target_url}: {_e}")
            except Exception as e:
                logger.error(f"[-] Error en Fase Logica (HAR): {e}")

        logger.info("[M6] Iniciando IDOR cross-session desde contexto de recon...")
        victim_token = self.options.get("auth_b_token")
        attacker_token = self.options.get("auth_token", "")
        
        if victim_token and attacker_token:
            await self._run_idor_from_recon(attacker_token, victim_token)
        else:
            logger.warning("[M6] Omitiendo IDOR cruzado por contexto: Faltan tokens de atacante/victima explícitos.")

    async def _run_idor_from_recon(self, attacker_token, victim_token):
        recon_endpoints = getattr(self, "_last_discovered_endpoints", [])
        attack_plan = await asyncio.to_thread(
            self.m6.analyze_idor_from_recon,
            self.vulnerabilities, self.target, recon_endpoints, self._harvest
        )
        if not attack_plan:
            logger.info("[M6] Sin candidatos IDOR.")
            return
        idor_findings = await self.m6.execute_idor_attacks(
            attack_plan, attacker_token, victim_token,
            self.network_manager, self.options.get("safe_mode", False)
        )
        for f in idor_findings:
            await self._record_finding(f)

    def _apply_report_degradation(self):
        original = len(self.vulnerabilities)
        filtered = []
        for vuln in self.vulnerabilities:
            conf = vuln.get("confidence", 0)
            ver  = vuln.get("verified", False)
            risk = vuln.get("risk", "Low")
            

            threshold = self.options.get("report_threshold", 0.6)
            if ver or conf >= 0.8 or (risk == "High" and conf >= 0.6):
                filtered.append(vuln)
            elif conf >= max(0.0, threshold - 0.15):
                if not vuln.get("_degraded"):
                    vuln["type"]     = f"{vuln['type']} [🔍 Por Revisar]"
                    vuln["_degraded"] = True
                filtered.append(vuln)
            else:
                logger.debug(f"[Report Degradation] Descartado: {vuln.get('type')} conf={conf:.2f}")
        
        self.vulnerabilities = filtered
        logger.info(f"[Report Degradation] {original - len(filtered)} filtrados. Final: {len(filtered)}.")


    def generate_report(self):
        logger.info("=== MISION CUMPLIDA. GENERANDO REPORTES... ===")
        vulns_to_report = (getattr(self, 'processed_vulnerabilities', None) or self.vulnerabilities)
        if vulns_to_report:
            reporter = HtmlReporter(reports_dir=settings.REPORTS_DIR, started_at=self.started_at)
            path = reporter.generate_report(vulns_to_report, target=self.target)
            
            logger.info(f"{len(vulns_to_report)} Vulnerabilidades Confirmadas (despues de Validation Queue):")
            for i, v in enumerate(vulns_to_report, 1):
                v_type = v.get('type', 'UNKNOWN').upper()
                v_url = v.get('url', 'N/A')
                v_payload = v.get('payload', 'N/A')
                v_method = v.get('method', 'GET')
                
                reasoning = (
                    v.get('ai_razonamiento') or 
                    v.get('evidence_data') or 
                    v.get('ai_nota') or
                    f"Validado via {v.get('validation_method', 'heuristica M3')}. Status: {v.get('status_code', 'N/A')}"
                )
                
                logger.info(f"[+] {i:02d} | {v_type}")
                detail_msg = (
                    f"    URL:     {v_method} {v_url}\n"
                    f"    Payload: {v_payload}\n"
                    f"    Punto de Quiebre: {reasoning}"
                )
                logger.info(detail_msg)
                
                if i < len(vulns_to_report):
                    logger.info("-" * 60)
        else:
            logger.warning("No se encontraron vulnerabilidades. Reporte vacio.")
