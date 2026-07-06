"""
Modulo M3: Clasificador Inteligente de Riesgo.
"""

import pickle
import html
import os
import json
import hashlib
import re
import random as _rnd_mh
from typing import Dict, Any, Tuple, List, cast
from app.config.settings import settings  # pyre-ignore[21]
from app.utils.logger import logger  # pyre-ignore[21]


_MINHASH_NUM_PERM: int = 128
_MINHASH_LARGE_PRIME: int = (1 << 61) - 1
_rnd_mh.seed(0x4A43C4D)
_MINHASH_PARAMS: List[Tuple[int, int]] = [
    (_rnd_mh.randint(1, _MINHASH_LARGE_PRIME - 1), _rnd_mh.randint(0, _MINHASH_LARGE_PRIME - 1))
    for _ in range(_MINHASH_NUM_PERM)
]
del _rnd_mh

class M3IntelligentClassifier:
    """
    Motor de analisis de respuestas.
    Usa firmas estaticas o modelo ML (si existe) para predecir vulnerabilidad.
    """
    
    def __init__(self, model_filename: str = "vaa_model.pkl"):
        self.model = None
        self.risk_levels = {0: "Low", 1: "Medium", 2: "High"}
        

        model_path = os.path.join(settings.MODELS_DIR, model_filename)
        if os.path.exists(model_path):
            try:

                with open(model_path, "rb") as f:
                    file_data = f.read()
                    
                if settings.MODEL_SHA256:
                    file_hash = hashlib.sha256(file_data).hexdigest()
                    if file_hash != settings.MODEL_SHA256:
                        logger.critical(f"ALERTA DE SEGURIDAD: Hash de modelo no coincide. Esperado={settings.MODEL_SHA256[:8]}... Real={file_hash[:8]}...")  # pyre-ignore[16]
                        logger.critical("Abortando carga de modelo para prevenir RCE.")
                        raise ValueError("Model Integrity Violation")
                else:
                    logger.warning("[!] WARNING: settings.MODEL_SHA256 esta vacio. Se cargara el modelo sin verificacion de integridad. Habilitar solo en desarrollo local.")


                self.model = pickle.loads(file_data) # nosec B301 (Verificado arriba)
                logger.info(f"Modelo ML cargado y verificado desde {model_path}")
            except Exception as e:
                logger.warning(f"[CUIDADO] Fallo al cargar modelo ML desde {model_path}: {e}")
        else:

             pass


        self.db_signatures = self._load_error_signatures()

    def _load_error_signatures(self) -> Dict[str, Any]:
        """Carga firmas de error desde JSON con mapeo de severidad."""
        json_path = os.path.join(settings.MODELS_DIR, "error_signatures.json")
        default_sigs = {
            "generic_stack_trace": ["Syntax Error", "Fatal Error"],
            "graphql_errors": [
                 "GraphQL.Validation", 
                 "Syntax Error: Expected Name", 
                 "GRAPHQL_VALIDATION_FAILED",
                 "Cannot query field",
                 "Field \"__schema\""
            ],
            "llm_leaks": [
                 "As an AI language model",
                 "I cannot verify that",
                 "My system instructions", 
                 "I am a large language model",
                 "OpenAI", "Anthropic", "Claude"
            ],
            "severity_mapping": {"high": ["generic_stack_trace", "graphql_errors", "llm_leaks"]}
        }
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading error_signatures.json: {e}")
                return default_sigs
        return default_sigs

    def predict_risk(self, execution_result: Dict[str, Any], is_tor: bool = False) -> Tuple[str, float, str]:
        """Interfaz publica para predecir riesgo."""

        if not isinstance(execution_result, dict):
            return "Low", 0.0, "clean"


        status = execution_result.get("status_code", 0)
        vuln_type = execution_result.get("type", "")
        response_text = execution_result.get("response_text", "")
        headers = execution_result.get("headers", {})
        

        _BYPASS_PROBE_TYPES = {"ssrf", "bola", "idor", "mass_assignment"}
        if status in [401, 403] and vuln_type.lower() not in _BYPASS_PROBE_TYPES:
            return "Info", 0.0, "auth_required"
            
        if self._should_skip_analysis(execution_result):
            return "Low", 0.0, "clean (skipped)"
            
        if self._is_honeypot(execution_result):
            return "Low", 0.0, "honeypot_detected"
        

        if vuln_type == "xss" and execution_result.get("is_reflected", 0) > 0.5:
            content_type = headers.get("Content-Type", headers.get("content-type", ""))
            payload = execution_result.get("payload", "")
            req_url = execution_result.get("endpoint", "").lower()
            

            if "/ssrf/" in req_url or "url=" in req_url:
                pass
            elif payload in response_text or execution_result.get("decoded_payload", "") in response_text:

                dangerous_contexts = [
                    "<script", "<img", "<svg", "<iframe", "<object", "<embed",
                    "<details", "<video", "<audio", "<form",
                    "onerror=", "onload=", "ontoggle=", "onfocus=", "onmouseover=",
                    "onclick=", "onpointerdown=", "onanimation_end=",
                    "javascript:", "data:text/html",
                ]


                active_payload = execution_result.get("decoded_payload", payload)
                payload_lower = str(active_payload).lower()
                xss_payload_markers = [
                    "alert(", "confirm(", "prompt(", "onerror=", "onload=", "ontoggle=",
                    "onfocus=", "onmouseover=", "onclick=", "javascript:", "<script",
                    "<svg", "<img", "<details", "<iframe",
                ]
                payload_is_xss = any(m in payload_lower for m in xss_payload_markers)
                
                is_html_response = "text/html" in content_type or "<html" in response_text.lower()
                

                if "application/json" in content_type:
                    return "Low", 0.3, "reflection_json"
                    
                if payload_is_xss and is_html_response:

                    return "High", 0.95, "Cross-Site Scripting (Reflected)"
                
                if any(ctx in response_text for ctx in dangerous_contexts):
                    return "High", 0.90, "Cross-Site Scripting"
        

        if vuln_type == "rce":
            response_time = execution_result.get("response_time_ms", 0)
            baseline_time = execution_result.get("baseline_time_ms", 0)
            
            if baseline_time > 0:

                if response_time > (baseline_time + 5000):
                    return "Critical", 0.95, "rce_time_based"
            elif response_time > 4500:

                return "Critical", 0.85, "rce_time_based"


        if response_text:

            normalized_text = html.unescape(response_text)
            

            success_patterns = self.db_signatures.get("success_patterns", [])

            FP_GENERIC_PATTERNS = {"id", "id\":", "\"id\"", "results", "data", "status", "ok", "true", "false"}
            

            content_type = headers.get("Content-Type", headers.get("content-type", ""))
            
            for pattern in success_patterns:
                clean_pattern = pattern.strip('"')
                

                if clean_pattern in FP_GENERIC_PATTERNS:
                    continue

                if clean_pattern in normalized_text:


                    request_params = execution_result.get("params", {})
                    param_values_str = " ".join(str(v) for v in request_params.values()) if request_params else ""
                    endpoint_url = execution_result.get("endpoint", "")
                    payload_sent = execution_result.get("payload", "")


                    is_json = "application/json" in content_type
                    is_error_status = status in [400, 422, 500]
                    
                    if clean_pattern in param_values_str or clean_pattern in endpoint_url or (payload_sent and clean_pattern in str(payload_sent)):

                        if is_json and (is_error_status or '"detail"' in normalized_text or '"msg"' in normalized_text):

                            echo_markers = ['"input":', '"msg":', '"detail":', '"loc":', '"value":']
                            if any(m in normalized_text for m in echo_markers):
                                logger.debug(f"[M3] Echo Neutralizer: Patron '{clean_pattern}' detectado como eco de error JSON. Neutralizando.")
                                continue


                        if is_json and any(x in clean_pattern for x in ["alert(", "confirm(", "prompt(", "script>", "VAA_XSS"]):
                            logger.debug(f"[M3] Echo Neutralizer: Patron XSS '{clean_pattern}' en JSON neutralizado.")
                            continue


                        BENCHMARK_MARKERS = ["SUCCESS_RCE_VAA_BENCHMARK", "VAA_AI_OVERRIDE_SUCCESS", "VAA_BENCHMARK_PWNED", "VAA_XSS_CONFIRMED"]
                        if any(m in clean_pattern for m in BENCHMARK_MARKERS):

                            if vuln_type != "xss":
                                active_payload = execution_result.get("decoded_payload", payload_sent)
                                if isinstance(active_payload, str) and active_payload in response_text:
                                    logger.debug(f"[M3] Echo Guard: Payload reflejado literalmente en {vuln_type}. Ignorando marcador '{clean_pattern}'.")
                                    continue
                            pass 
                        elif any(x in clean_pattern for x in ["alert(", "confirm(", "prompt(", "script>", "VAA_RCE"]):

                            if len(normalized_text) > len(clean_pattern) + 30: 
                                pass
                            else:
                                continue
                        else:
                            logger.debug(f"[M3] Patron '{clean_pattern}' ignorado — reflejado (no es exploit)")
                            continue


                    logger.debug(f"SUCCESS PATTERN CONFIRMED: {clean_pattern}")
                    

                    if vuln_type == "sqli":
                        label = "SQL Injection (Successful Dump)"
                    elif vuln_type == "ssrf":
                        label = "Server-Side Request Forgery"
                    elif vuln_type == "rce" or any(x in clean_pattern for x in ["VAA_RCE_CONFIRMED", "SUCCESS_RCE", "uid=0", "root:x:0:0"]): 
                        label = "COMMAND_INJECTION (RCE)"
                    elif vuln_type in ("prompt_injection", "ai_injection") or any(x in clean_pattern for x in ["VAA_AI_OVERRIDE_SUCCESS", "VAA_BENCHMARK_PWNED"]):
                        label = "PROMPT_INJECTION"
                    elif vuln_type == "mass_assignment":
                        label = "Mass Assignment (Data Alteration)"
                    elif any(x in response_text for x in ["alert(", "confirm(", "script>", "VAA_XSS_CONFIRMED"]):
                        req_url = execution_result.get("endpoint", "").lower()
                        if "/ssrf/" in req_url or "url=" in req_url:
                            label = "Server-Side Request Forgery"
                        else:
                            label = "Cross-Site Scripting"
                    elif any(x in normalized_text.lower() for x in ["i am a large language model", "as an ai model", "system instructions"]): 

                        llm_markers = self.db_signatures.get("llm_leaks", [])
                        if any(marker.lower() in normalized_text.lower() for marker in llm_markers):
                            label = "AI Prompt Injection"
                        else:

                            continue
                    else:
                        label = f"Exploit Confirmed ({clean_pattern})"

                    
                    return "High", 1.0, label


            critical_errors = self.db_signatures.get("critical_errors", {})
            for db_name, sigs in critical_errors.items():
                for sig in sigs:
                    if sig in response_text:

                        if sig in ["169.254.169.254", "computeMetadata", "latest/meta-data"]:
                            return "High", 1.0, "Server-Side Request Forgery"
                        

                        if "alert(" in normalized_text or "confirm(" in normalized_text:

                            if "application/json" in content_type:
                                pass
                            else:
                                req_url = execution_result.get("endpoint", "").lower()  # pyre-ignore[16]
                                if "/ssrf/" in req_url or "url=" in req_url:
                                    return "High", 1.0, "Server-Side Request Forgery"
                                return "High", 1.0, "Cross-Site Scripting"
                        if "VAA_AI_OVERRIDE_SUCCESS" in normalized_text or "VAA_BENCHMARK_PWNED" in normalized_text:
                            llm_markers = self.db_signatures.get("llm_leaks", [])
                            if any(marker.lower() in normalized_text.lower() for marker in llm_markers):
                                return "High", 1.0, "AI Prompt Injection"

                        if self._is_fp_context(response_text, str(sig)):
                            continue
                        logger.warning(f"Critical DB Error: {db_name} - {str(sig)[:50]}")  # pyre-ignore[16]
                        return "High", 0.95, f"SQL Injection ({db_name.upper()})"
            

            framework_errors = self.db_signatures.get("framework_errors", {})
            for framework, sigs in framework_errors.items():
                for sig in sigs:
                    if sig in response_text:
                        if self._is_fp_context(response_text, sig):
                            continue

                        if self._is_debug_mode(response_text):
                            return "High", 0.90, "Framework Debug Leak"
                        return "Medium", 0.75, "Framework Information"
            

            generic_traces = self.db_signatures.get("generic_stack_trace", [])
            for sig in generic_traces:
                if sig in response_text:
                    if self._is_fp_context(response_text, sig):
                        continue

                    severity = self._assess_stack_trace_severity(response_text)
                    if severity == "high":
                        return "High", 0.85, "Stack Trace (Critical)"
                    elif severity == "medium":
                        return "Medium", 0.65, "Stack Trace"
                    else:
                        return "High", 0.70, "Stack Trace"


            _endpoint_url = execution_result.get("endpoint", "")
            _is_auth_endpoint = any(seg in _endpoint_url for seg in ["/auth/", "/token", "/login", "/signin"])
            if "application/json" in execution_result.get("headers", {}).get("content-type", "").lower() and not _is_auth_endpoint:
                sensitive_keys = ["password", "secret", "private_key", "api_key", "debug_info"]
                raw_lower = response_text.lower()
                for key in sensitive_keys:
                    if f'"{key}"' in raw_lower or f"'{key}'" in raw_lower:
                        return "High", 0.90, "Sensitive Data Leakage"

                if status == 200 and (': "admin"' in raw_lower or ': "root"' in raw_lower):
                    if '"error"' not in raw_lower and '"detail"' not in raw_lower:
                        return "High", 0.95, "Administrative Access Leak"


        if self._is_soft_waf(response_text):
            logger.info("Soft WAF Detectado (Captcha/Challenge en 200 OK). Marcando como CLEAN.")
            return "Low", 0.0, "WAF Block"

        feature_vector = self._prepare_feature_vector(execution_result)
        

        if self.model:
            try:
                import numpy as np  # pyre-ignore[21]
                features = np.array(feature_vector).reshape(1, -1)
                prediction = self.model.predict(features)[0]  # pyre-ignore[16]
                probabilities = self.model.predict_proba(features)[0]  # pyre-ignore[16]
                confidence = float(max(probabilities))
                return self.risk_levels.get(prediction, "Low"), confidence, "ML Prediction"
            except Exception as e:
                logger.error(f"Error de Prediccion ML: {e}")
                return "Low", 0.0, "ML Error"
        else:

            risk, confidence, label = self._heuristic_prediction(feature_vector, execution_result)
            return risk, confidence, label

    def _heuristic_prediction(self, feature_vector: List[float], execution_result: Dict[str, Any]) -> Tuple[str, float, str]:
        """Logica manual robusta para cuando no hay modelo ML."""

        endpoint = str(execution_result.get("endpoint", "")).lower()
        time_elapsed = execution_result.get("response_time_ms", 0.0) / 1000.0
        vuln_type = execution_result.get("type", "unknown")
        response_text = execution_result.get("response_text", "")
        status_code = execution_result.get("status_code", 200)
        

        if any(n in endpoint for n in settings.IGNORED_EXTENSIONS + settings.IGNORED_DOMAINS):
             return "Low", 0.05, "clean"

        score = feature_vector[0]
        is_error = feature_vector[1]
        has_keywords = feature_vector[3] if len(feature_vector) > 3 else 0.0
        is_reflected = feature_vector[4] if len(feature_vector) > 4 else 0.0
        status_code = execution_result.get("status_code", 200)


        if time_elapsed > 5.0:
            if vuln_type == "sqli":
                return "High", 0.90, "SQL Injection (Time-Based)"
            if vuln_type in ["rce", "cmdi"]:
                return "High", 0.90, "Command Injection (Time-Based)"
            return "Medium", 0.70, "Anomaly (High Latency)"


        if vuln_type in ["rce", "cmdi", "prompt_injection", "ai_injection"]:
            rce_success_markers = [
                "SUCCESS_RCE", "VAA_RCE_CONFIRMED", "uid=", "groups=", "root:x:0:0",
                "Windows IP Configuration", "Directory of C:\\",
                "Microsoft Windows [Version", "Configuración IP de Windows",
                "BENCHMARK_PWNED", "SYSTEM_SECRET_KEY", "VAA_AI_OVERRIDE_SUCCESS",
                "CommandNotFoundException", "not recognized as an internal",
                "filename, directory name, or volume label syntax is incorrect"
            ]

            body_lower = response_text.lower()
            if any(marker.lower() in body_lower for marker in rce_success_markers):
                label = "Command Injection (Confirmed Output)" if "rce" in vuln_type else "Prompt Injection (Successful Jailbreak)"
                return "High", 1.0, label


        ssrf_endpoint_signals = ["ssrf", "redirect", "fetch", "proxy", "webhook", "callback"]

        ssrf_no_relay_signals = ["mass-assign", "mass_assign", "update", "profile", "store", "create"]
        if vuln_type in ["ssrf", "ssrf_redirect"]:
            endpoint_path = endpoint.split("?")[0].lower()
            endpoint_has_ssrf = any(sig in endpoint_path for sig in ssrf_endpoint_signals)
            is_storage_endpoint = any(sig in endpoint_path for sig in ssrf_no_relay_signals)
            response_has_ssrf = any(sig in response_text.lower() for sig in ["169.254", "internal", "metadata", "connection refused"])
            

            if is_storage_endpoint:
                pass


            elif endpoint_has_ssrf or (response_has_ssrf and status_code >= 500):
                return "High", 0.85, "Server-Side Request Forgery"


        if status_code == 403:
             return "Low", 0.01, "WAF Block"


        if status_code == 200:
            response_lower = response_text.lower()
            

            if vuln_type == "sqli":
                sqli_indicators = [
                    '"username":', '"email":', '"role":', '"password":',
                    '"users":', '"results":', '"db_', '"items":',
                ]
                if any(ind in response_lower for ind in sqli_indicators):
                    if "admin" in response_lower or "root" in response_lower or "super" in response_lower:
                        return "High", 0.95, "SQL Injection (Successful Dump)"


                    results_match = re.search(r'"results"\s*:\s*\[(.*?)\]', response_text, re.DOTALL)
                    if results_match and results_match.group(1).count(',') >= 1:
                        return "High", 0.90, "SQL Injection (Data Dump - Multiple Results)"
                    return "Medium", 0.80, "SQL Injection (Data Anomaly)"


            if vuln_type.lower() in ["bola", "idor"] or any(x in endpoint for x in ["/orders/", "/users/", "/lab/bola"]):
                 if any(k in response_text for k in ['"owner":', '"owner_id":', '"user_id":']):
                      return "High", 1.0, "Broken Object Level Authorization (BOLA)"
                 if any(k in response_lower for k in ["customer_id", "shipping_address", "billing", "email", "password"]):
                      return "High", 0.90, "Broken Object Level Authorization (BOLA)"


        if is_reflected == 1.0:
            content_type = execution_result.get("headers", {}).get("content-type", "").lower()
            

            if "/ssrf/" in endpoint or "url=" in endpoint:
                if "alert(" not in response_text.lower() and "confirm(" not in response_text.lower():
                    return "Low", 0.10, "Reflection (Expected for SSRF)"
                return "High", 0.95, "Server-Side Request Forgery"


            is_json = "application/json" in content_type
            is_html = "text/html" in content_type or "<html>" in response_text.lower()
            

            if "alert(1)" in response_text or "confirm(1)" in response_text or "prompt(1)" in response_text:
                 if is_json and not is_html:
                     return "Low", 0.30, "JSON Reflection (Safe)"
                 return "High", 0.98, "Cross-Site Scripting (Exploited)"


            if is_json and not is_html:
                if "<script>" not in response_text.lower() and "alert(" not in response_text.lower():
                    return "Low", 0.30, "JSON Reflection (Safe)"

            if is_html and ("<script>" in response_text.lower() or "alert(" in response_text.lower()):
                 return "High", 0.95, "Cross-Site Scripting (HTML)"
            
            if status_code == 404:
                 return "Low", 0.20, "404 Reflection"
            
            return "High", 0.85, "Cross-Site Scripting"


        if is_error == 1.0:


            _is_mass_assign_ep = any(sig in endpoint.lower() for sig in ["mass-assign", "mass_assign"])
            if has_keywords == 1.0:
                return "High", 0.95, "Database Error Leak"
            elif score > 0.9 and not _is_mass_assign_ep:
                return "Medium", 0.80, "Suspicious Server Error"
            else:
                return "Low", 0.25, "Generic 500"
        
        if score > 0.85 and has_keywords == 1.0:
             return "Medium", 0.85, "Information Leakage"
        
        if score > 0.7:
             return "Low", 0.55, "Anomaly Detected"
        
        return "Low", 0.10, "clean"

    def _prepare_feature_vector(self, result: Dict[str, Any]) -> List[float]:
        """Transforma datos crudos en vector numerico."""
        cv_score = float(result.get("context_violation_score", 0.0))
        
        status = result.get("status_code", result.get("status", 200))

        is_server_error = 1.0 if status and int(status) >= 500 else 0.0
        
        response_time = float(result.get("response_time_ms", 0.0))
        
        keyword_stack = 1.0 if result.get("keyword_stack_trace", False) else 0.0
        
        is_reflected = float(result.get("is_reflected", 0.0))
        
        return [cv_score, is_server_error, response_time, keyword_stack, is_reflected]

    def _is_fp_context(self, full_text: str, keyword: str) -> bool:
        """Determina si una keyword es un Falso Positivo."""
        try:
            idx = full_text.find(keyword)
            if idx == -1:
                return False
            

            start = max(0, idx - 200)
            end = min(len(full_text), idx + 200)
            snippet = full_text[start:end].lower()  # pyre-ignore[16]
            

            safe_tags = [
                "<pre", "<code", "<textarea", "<xmp", 
                "syntaxhighlighter", "prism", "highlight.js",
                "class=\"code", "class=\"example", "class=\"snippet",
                "data-language=", "<script type=\"text/template\""
            ]
            if any(tag in snippet for tag in safe_tags):
                return True
            

            doc_patterns = [
                "example:", "tutorial:", "how to", "documentation",
                "\"description\":", "\"title\":", "\"example\":",
                "readme", "docs/", "/documentation/"
            ]
            if any(pattern in snippet for pattern in doc_patterns):
                return True
            

            if ("<!--" in snippet and "-->" in snippet) or \
               ("/*" in snippet and "*/" in snippet) or \
               ("//" in snippet[:20]):  # pyre-ignore[16]
                return True
            

            if any(marker in full_text[:1000].lower() for marker in  # pyre-ignore[16] 
                   ["learn", "course", "training", "workshop", "guide"]):
                return True
            
            return False
        except (IndexError, AttributeError, TypeError) as e:
            logger.debug(f"Error analizando contexto de keyword: {e}")
            return False
    
    def _is_debug_mode(self, content: str) -> bool:
        """Detecta si la aplicacion esta en modo debug."""
        debug_indicators = self.db_signatures.get("debug_mode_indicators", [])
        content_lower = content.lower()
        return any(indicator.lower() in content_lower for indicator in debug_indicators)
    
    def _assess_stack_trace_severity(self, content: str) -> str:
        """
        Evalua la severidad de un stack trace basado en la informacion expuesta.
        """
        content_lower = content.lower()
        

        high_indicators = [
            "/app/", "/var/www/", "c:\\\\inetpub",
            "password", "secret", "api_key",
            "database.yml", ".env", "config/"
        ]
        if any(ind in content_lower for ind in high_indicators):
            return "high"
        

        medium_indicators = [
            "at line", "in file", "traceback",
            "exception", "error:"
        ]
        if any(ind in content_lower for ind in medium_indicators):
            return "medium"
        
        return "low"
    

    def _is_soft_waf(self, response_text: str) -> bool:
        """Detecta WAFs que devuelven 200 OK con challenge page."""
        if not response_text:
            return False

        text_lower = response_text.lower()


        cloudflare_signatures = [
            "just a moment",
            "cf-ray",
            "cloudflare ray id",
            "checking your browser",
            "ddos protection by cloudflare",
            "attention required!",
            "__cf_bm",
            "cdn-cgi/challenge-platform",
        ]


        generic_waf_signatures = [
            "ddos-guard",
            "sucuri website firewall",
            "you have been blocked",
            "access denied by security policy",
            "request blocked",
            "this page is protected by",
            "security check required",
            "please complete the security check",
            "enable javascript and cookies",
            "your ip has been flagged",
            "incapsula incident id",
            "x-iinfo",
            "powered by akamai",
            "reference #",
            "mod_security",
            "web application firewall",
            "the owner of this website",
            "verify you are human",
        ]

        all_signatures = cloudflare_signatures + generic_waf_signatures
        return any(sig in text_lower for sig in all_signatures)

    def _is_honeypot(self, execution_result: Dict[str, Any]) -> bool:
        """Detecta respuestas honeypot (trampas para scanners)."""
        response_text = execution_result.get("response_text", "")

        honeypot_markers = [
            "<!-- honeypot -->",
            "tarpit",
            "you have been logged",
            "security incident",
            "your ip has been recorded"
        ]
        
        if any(marker in response_text.lower() for marker in honeypot_markers):
            return True
        

        return False

    def _should_skip_analysis(self, result: Dict[str, Any]) -> bool:
        """
        Determina si un resultado puede ignorar el analisis pesado de M3.
        """

        response_text = result.get("response_text", "")
        if len(response_text) < 5:
            return True


        endpoint = str(result.get("endpoint", "")).lower()
        if any(endpoint.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".woff"]):
             return True


        method = result.get("method", "GET").upper()
        if method in ["OPTIONS", "HEAD"]:
            return True


        if result.get("status_code") == 403 and self._is_soft_waf(response_text):
            return True

        return False

    @staticmethod
    def _minhash_signature(tokens: set) -> List[int]:
        """
        Builds a MinHash signature of length _MINHASH_NUM_PERM from a token set.
        RAM cost: O(K) = O(128 ints) regardless of vocabulary size.
        """
        lp = _MINHASH_LARGE_PRIME
        sig = cast(List[int], [lp] * _MINHASH_NUM_PERM)
        for token in tokens:
            h = hash(token) & 0x7FFFFFFFFFFFFFFF
            for i, (a, b) in enumerate(_MINHASH_PARAMS):
                hv = (a * h + b) % lp
                if hv < sig[i]:  # pyre-ignore[16]
                    sig[i] = hv  # pyre-ignore[16]
        return sig

    @staticmethod
    def _jaccard_from_signatures(sig1: List[int], sig2: List[int]) -> float:
        """Estimates Jaccard similarity by counting MinHash signature collisions."""
        if not sig1 or not sig2:
            return 0.0
        matches = sum(1 for a, b in zip(sig1, sig2) if a == b)
        return matches / len(sig1)

    def calculate_similarity(self, text1: str, text2: str) -> float:
        """Analisis diferencial de SQLi mediante similitud de respuestas."""
        if not text1 or not text2:
            return 0.0


        tokens1 = set(t for t in re.split(r'\W+', text1.lower()) if t)
        tokens2 = set(t for t in re.split(r'\W+', text2.lower()) if t)

        if not tokens1 and not tokens2:
            return 1.0
        if not tokens1 or not tokens2:
            return 0.0


        if len(tokens1) + len(tokens2) <= 512:
            intersection = tokens1.intersection(tokens2)
            union = tokens1.union(tokens2)
            return len(intersection) / len(union)


        sig1 = self._minhash_signature(tokens1)
        sig2 = self._minhash_signature(tokens2)
        return self._jaccard_from_signatures(sig1, sig2)

