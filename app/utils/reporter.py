"""
Modulo de Reportes — v4.0.0 (Evidencia Contextual por Tipo)
Genera reportes HTML con resumen ejecutivo, razonamiento de IA y tabla de madurez.

v4.0.0 changes:
 - Evidencia contextual: XSS/SQLi muestran el payload; IDOR/DataLeakage muestran los datos reales
 - Trigger payload en gris secundario para tipos donde el payload no ES la evidencia
 - OWASP refs corregidas: EXPLOIT CONFIRMED → API1, Missing Headers → API8 CWE-693
 - "Endpoints analizados" renombrado a "Hallazgos" (el total real)
"""

import os
import re
import time
from datetime import datetime
from typing import List, Dict

from app.config.settings import settings


class HtmlReporter:
    def __init__(self, reports_dir: str = None, started_at: float = None):
        self.reports_dir = reports_dir or settings.DEFAULT_REPORTS_DIR
        self.started_at  = started_at or time.time()
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)


    @staticmethod
    def _build_evidence(v: Dict) -> tuple:
        """
        Retorna (evidence_display: str, trigger_payload: str | None).

        Regla:
          - Si engine guardo evidence_data → usarlo directamente.
          - Para tipos donde la evidencia son DATOS (IDOR, leakage, exploit) →
            extraer campos sensibles de response_text.
          - Para tipos donde la evidencia es el PAYLOAD (XSS, SQLi, SERVER_ERROR) →
            mostrar el payload.
          - trigger_payload: solo se muestra para tipos de datos, en gris secundario.
        """
        vtype        = v.get("type", "").lower()
        evidence_data = v.get("evidence_data", "")
        raw_payload   = str(v.get("payload", ""))
        response_text = v.get("response_text", "")


        DATA_EXPOSURE_TYPES = (
            "exploit confirmed", "sensitive data", "leakage",
            "bfla", "idor", "bola", "privilege escalation",
        )
        is_data_type = any(k in vtype for k in DATA_EXPOSURE_TYPES)

        if evidence_data:
            return evidence_data, (raw_payload if is_data_type and raw_payload else None)

        if is_data_type:

            hits = re.findall(
                r'"(?:email|id|userId|user_id|token|name|creditCard|vehicleId|orderId|phone)'
                r'"\s*:\s*"?([^",\}\]\[]{1,60})',
                response_text
            )

            field_hits = re.findall(
                r'"(email|id|userId|user_id|token|name|creditCard|vehicleId|orderId|phone)"',
                response_text
            )
            unique_fields = list(dict.fromkeys(field_hits))

            if unique_fields:
                display = f"Datos en respuesta limpia: {', '.join(unique_fields[:6])}"
                if hits:
                    display += f" — ej: {hits[0][:40]}"
            elif response_text:
                display = f"Respuesta: {response_text[:200]}"
            else:
                display = "(datos expuestos — ver logs)"

            return display, (raw_payload if raw_payload else None)


        if "resource_consumption" in vtype or "api4" in vtype:
            timing = response_text[:120] if response_text else raw_payload
            return f"{raw_payload} — {timing}", None


        return raw_payload or "(sin payload)", None

    def generate_report(self, vulnerabilities: List[Dict], target: str = "N/A") -> str:
        """
        Genera un reporte HTML standalone y retorna la ruta del archivo.
        """
        timestamp    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ts_filename  = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename     = os.path.join(self.reports_dir, f"reporte_vaa_{ts_filename}.html")
        elapsed_secs = int(time.time() - self.started_at)
        duration_str = f"{elapsed_secs // 60}m {elapsed_secs % 60}s"


        total    = len(vulnerabilities)
        critical = sum(1 for v in vulnerabilities if v.get("risk") == "Critical")
        high     = sum(1 for v in vulnerabilities if v.get("risk") == "High")
        medium   = sum(1 for v in vulnerabilities if v.get("risk") == "Medium")
        low      = sum(1 for v in vulnerabilities if v.get("risk") in ("Low", "Info"))

        if critical > 0:
            overall_risk       = "CRITICO"
            overall_risk_class = "risk-Critical"
        elif high >= 3:
            overall_risk       = "ALTO — Requiere accion inmediata"
            overall_risk_class = "risk-High"
        elif high > 0 or medium >= 3:
            overall_risk       = "MEDIO — Revisar antes del proximo release"
            overall_risk_class = "risk-Medium"
        else:
            overall_risk       = "BAJO"
            overall_risk_class = "risk-Low"


        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VAA — Reporte Ejecutivo de Seguridad</title>
    <style>
        :root {{
            --bg: #0f1117; --surface: #1a1d27; --surface2: #22263a;
            --border: #2e3250; --text: #e2e8f0; --muted: #718096;
            --red: #fc4c4c; --orange: #f6ad55; --yellow: #ecc94b;
            --green: #48bb78; --blue: #63b3ed; --purple: #a78bfa;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
        header {{ background: linear-gradient(135deg, #1a1d27 0%, #0f1117 100%);
                  border-bottom: 1px solid var(--border); padding: 28px 40px; }}
        header h1 {{ font-size: 1.6rem; font-weight: 700; color: #fff; }}
        header p  {{ color: var(--muted); font-size: 0.9rem; margin-top: 4px; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 40px; }}

        /* Executive Summary */
        .exec-summary {{
            background: var(--surface); border: 1px solid var(--border);
            border-radius: 12px; padding: 28px; margin-bottom: 32px;
        }}
        .exec-summary h2 {{ font-size: 1.1rem; color: var(--muted); text-transform: uppercase;
                            letter-spacing: .06em; margin-bottom: 20px; }}
        .exec-meta {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
                      gap: 12px; margin-bottom: 24px; }}
        .meta-item {{ background: var(--surface2); border-radius: 8px; padding: 12px 16px; }}
        .meta-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
        .meta-value {{ font-size: 1rem; font-weight: 600; margin-top: 2px; }}

        /* Severity Pills */
        .severity-grid {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }}
        .sev-pill {{ display: flex; flex-direction: column; align-items: center;
                     background: var(--surface2); border-radius: 10px;
                     padding: 14px 24px; min-width: 100px; }}
        .sev-pill .num {{ font-size: 2rem; font-weight: 700; line-height: 1; }}
        .sev-pill .lbl {{ font-size: 0.75rem; color: var(--muted); margin-top: 4px; }}
        .sev-pill.crit .num {{ color: var(--red); }}
        .sev-pill.high .num {{ color: var(--orange); }}
        .sev-pill.med  .num {{ color: var(--yellow); }}
        .sev-pill.low  .num {{ color: var(--green); }}

        .risk-overall {{ display: inline-block; padding: 6px 16px; border-radius: 20px;
                         font-weight: 700; font-size: 0.9rem; }}
        .risk-Critical {{ background: rgba(252,76,76,.15); color: var(--red); border: 1px solid var(--red); }}
        .risk-High      {{ background: rgba(246,173,85,.15); color: var(--orange); border: 1px solid var(--orange); }}
        .risk-Medium    {{ background: rgba(236,201,75,.15); color: var(--yellow); border: 1px solid var(--yellow); }}
        .risk-Low       {{ background: rgba(72,187,120,.15); color: var(--green); border: 1px solid var(--green); }}

        /* Findings */
        h2.section-title {{ font-size: 1.15rem; font-weight: 600; margin: 32px 0 16px;
                             padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
        .finding-card {{
            background: var(--surface); border: 1px solid var(--border);
            border-radius: 10px; padding: 22px 26px; margin-bottom: 16px;
        }}
        .finding-card:hover {{ border-color: #4a5568; }}
        .finding-header {{ display: flex; align-items: flex-start; gap: 14px; margin-bottom: 14px; }}
        .risk-badge {{ padding: 5px 12px; border-radius: 20px; font-size: 0.78rem;
                       font-weight: 700; white-space: nowrap; }}
        .badge-High     {{ background: rgba(246,173,85,.2); color: var(--orange); }}
        .badge-Medium   {{ background: rgba(236,201,75,.2); color: var(--yellow); }}
        .badge-Low      {{ background: rgba(72,187,120,.2); color: var(--green); }}
        .badge-Critical {{ background: rgba(252,76,76,.2); color: var(--red); }}
        .badge-Info     {{ background: rgba(99,179,237,.2); color: var(--blue); }}
        .finding-title {{ font-size: 1rem; font-weight: 600; word-break: break-all; }}
        .finding-url   {{ font-family: monospace; font-size: 0.82rem; color: var(--blue);
                          background: var(--surface2); padding: 4px 8px; border-radius: 4px;
                          display: inline-block; margin-top: 4px; word-break: break-all; }}
        .finding-body  {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
        @media(max-width: 720px) {{ .finding-body {{ grid-template-columns: 1fr; }} }}
        .info-block label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: .05em;
                              color: var(--muted); display: block; margin-bottom: 4px; }}
        .info-block p {{ font-size: 0.9rem; }}
        .evidence-box {{
            font-family: monospace; font-size: 0.82rem;
            background: var(--surface2); padding: 6px 10px;
            border-radius: 6px; word-break: break-all;
        }}
        .trigger-label {{
            margin-top: 6px; font-size: 0.75rem; color: var(--muted);
        }}
        .trigger-label code {{
            color: var(--muted); background: var(--surface2);
            padding: 1px 5px; border-radius: 3px;
        }}
        .tags {{ display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }}
        .tag {{ font-size: 0.75rem; padding: 3px 10px; border-radius: 12px;
                background: var(--surface2); color: var(--muted); }}
        .tag.ai {{ background: rgba(167,139,250,.15); color: var(--purple); }}
        .conf-bar {{ height: 5px; border-radius: 3px; background: var(--surface2); margin-top: 8px; }}
        .conf-fill {{ height: 100%; border-radius: 3px; background: var(--green); }}

        /* Maturity Table */
        .maturity-table {{ width: 100%; border-collapse: collapse; margin-top: 12px;
                           background: var(--surface); border-radius: 10px; overflow: hidden;
                           border: 1px solid var(--border); }}
        .maturity-table th, .maturity-table td {{
            padding: 12px 16px; text-align: left; border-bottom: 1px solid var(--border);
            font-size: 0.9rem;
        }}
        .maturity-table th {{ color: var(--muted); font-size: 0.78rem; text-transform: uppercase;
                               letter-spacing: .04em; background: var(--surface2); }}
        .maturity-table tr:last-child td {{ border-bottom: none; }}

        footer {{ text-align: center; color: var(--muted); font-size: 0.82rem;
                  padding: 28px; border-top: 1px solid var(--border); margin-top: 48px; }}
    </style>
</head>
<body>

<header>
    <h1>&#x1F6E1; LokiTrace — Reporte Ejecutivo de Seguridad API</h1>
    <p>Generado automaticamente por VAA v4.0.0 &nbsp;|&nbsp; {timestamp}</p>
</header>

<div class="container">

    <!-- ── Resumen Ejecutivo ───────────────────────────────────────────────── -->
    <div class="exec-summary">
        <h2>Resumen Ejecutivo</h2>
        <div class="exec-meta">
            <div class="meta-item"><div class="meta-label">Objetivo</div><div class="meta-value" style="font-size:0.85rem;word-break:break-all;">{target}</div></div>
            <div class="meta-item"><div class="meta-label">Fecha</div><div class="meta-value">{datetime.now().strftime("%Y-%m-%d")}</div></div>
            <div class="meta-item"><div class="meta-label">Duracion</div><div class="meta-value">{duration_str}</div></div>
            <div class="meta-item"><div class="meta-label">Hallazgos</div><div class="meta-value">{total}</div></div>
        </div>
        <div class="severity-grid">
            <div class="sev-pill crit"><span class="num">{critical}</span><span class="lbl">Critico</span></div>
            <div class="sev-pill high"><span class="num">{high}</span><span class="lbl">Alto</span></div>
            <div class="sev-pill med" ><span class="num">{medium}</span><span class="lbl">Medio</span></div>
            <div class="sev-pill low" ><span class="num">{low}</span><span class="lbl">Info/Bajo</span></div>
        </div>
        <div>Riesgo general: <span class="risk-overall {overall_risk_class}">{overall_risk}</span></div>
    </div>

    <!-- ── Detalle de Hallazgos ────────────────────────────────────────────── -->
    <h2 class="section-title">Hallazgos ({total})</h2>
"""


        for v in sorted(vulnerabilities, key=lambda x: {"Critical": 0, "High": 1, "Medium": 2}.get(x.get("risk", ""), 3)):
            risk     = v.get("risk", "Info")
            vtype    = v.get("type", "Unknown")
            vtype_l  = vtype.lower()
            endpoint = str(v.get("url") or v.get("endpoint") or "/")


            if endpoint.startswith("file:") or (len(endpoint) > 2 and endpoint[1] == ":"):
                endpoint = "[LOCAL_PATH_REDACTED]"
            endpoint = endpoint.replace("<", "&lt;").replace(">", "&gt;")

            conf       = v.get("confidence", 0.0)
            conf_pct   = int(conf * 100)
            method     = v.get("method", "GET")
            validated  = " Verificado" if v.get("verified") else " Probable"
            val_method = v.get("validation_method", "")


            analysis_data = v.get("analysis", {}) or {}
            if isinstance(analysis_data, str):
                legacy_obs = analysis_data
                legacy_fix = "Ver estandares OWASP."
            else:
                legacy_obs = analysis_data.get("ai_observation", "")
                legacy_fix = analysis_data.get("recommended_fix", "")

            ai_razon = v.get("ai_razonamiento", "")
            ai_fix   = v.get("ai_remediacion", "")
            ai_nota  = v.get("ai_nota", "")

            observacion = ai_razon or legacy_obs or "Sin analisis disponible."
            remediacion = ai_fix   or legacy_fix or "Revisar documentacion OWASP API Security Top 10."


            evidence_display, trigger_payload = self._build_evidence(v)
            evidence_display = evidence_display.replace("<", "&lt;").replace(">", "&gt;")

            trigger_html = ""
            if trigger_payload:
                tp_safe = trigger_payload.replace("<", "&lt;").replace(">", "&gt;")[:80]
                trigger_html = f'<div class="trigger-label">Trigger: <code>{tp_safe}</code></div>'


            owasp_ref, cwe = self._get_owasp_ref(vtype)

            ai_tag      = '<span class="tag ai">&#x1F916; Analizado por IA</span>' if ai_razon else ""
            ai_nota_tag = (
                '<span class="tag" style="background:rgba(236,201,75,.15);color:#ecc94b;'
                'border:1px solid #ecc94b;"> Requiere revision manual</span>'
            ) if ai_nota else ""

            ai_nota_block = f"""
                <div class="info-block" style="margin-top:14px;border-left:3px solid #ecc94b;padding-left:10px;">
                    <label style="color:#ecc94b;">Nota de IA (FP sugerido)</label>
                    <p style="font-size:0.85rem;">{ai_nota}</p>
                </div>""" if ai_nota else ""

            html += f"""
    <div class="finding-card">
        <div class="finding-header">
            <span class="risk-badge badge-{risk}">{risk}</span>
            <div>
                <div class="finding-title">{vtype.upper()}</div>
                <div class="finding-url">{method} {endpoint}</div>
            </div>
        </div>
        <div class="finding-body">
            <div>
                <div class="info-block">
                    <label>Riesgo de negocio / Observacion</label>
                    <p>{observacion}</p>
                </div>
                <div class="info-block" style="margin-top:14px;">
                    <label>Evidencia</label>
                    <p class="evidence-box">{evidence_display}</p>
                    {trigger_html}
                </div>
                {ai_nota_block}
            </div>
            <div>
                <div class="info-block">
                    <label>Remediacion</label>
                    <p>{remediacion}</p>
                </div>
                <div class="info-block" style="margin-top:14px;">
                    <label>Confianza — {conf_pct}%</label>
                    <div class="conf-bar"><div class="conf-fill" style="width:{conf_pct}%;"></div></div>
                </div>
            </div>
        </div>
        <div class="tags">
            <span class="tag">{validated}</span>
            {'<span class="tag">' + val_method + '</span>' if val_method else ""}
            {'<span class="tag">' + owasp_ref + '</span>' if owasp_ref else ""}
            {'<span class="tag">CWE-' + cwe + '</span>' if cwe else ""}
            {ai_tag}
            {ai_nota_tag}
        </div>
    </div>"""


        html += """
    <h2 class="section-title" style="margin-top:48px;">Estado del Scanner (Transparencia)</h2>
    <table class="maturity-table">
        <thead><tr><th>Modulo</th><th>Estado</th><th>Notas</th></tr></thead>
        <tbody>
            <tr><td>M6 IDOR / BOLA</td><td> Produccion</td><td>Fingerprint cross-session + BOLA write (PUT/DELETE)</td></tr>
            <tr><td>PassiveRecon (API8+API9)</td><td> Produccion</td><td>Docs expuestas, CORS, headers de seguridad</td></tr>
            <tr><td>JWT Audit (API2)</td><td> Produccion</td><td>alg:none, firma vacia, claim escalation, weak secret</td></tr>
            <tr><td>BFLA Vertical (API5)</td><td> Produccion</td><td>Token normal contra endpoints admin</td></tr>
            <tr><td>API4 Resource Consumption</td><td> Produccion</td><td>Params de paginacion con valores extremos</td></tr>
            <tr><td>M9 Params</td><td> Produccion</td><td>Descubre parametros ocultos por delta de tamano</td></tr>
            <tr><td>Oracle Shannon</td><td> Produccion</td><td>Evita desperdiciar tiempo en endpoints saturados</td></tr>
            <tr><td>NetworkManager</td><td> Produccion</td><td>Session pool + circuit breaker + token health check</td></tr>
            <tr><td>M3 Classifier</td><td>✅ Produccion</td><td>Pattern matching + heuristica. Sin segunda opinion de IA (modulo independiente)</td></tr>
            <tr><td>M74P1 Recon</td><td> Funcional</td><td>Lee OpenAPI — no descubre endpoints fuera del spec</td></tr>

            <tr><td>M11 GraphQL</td><td> Sin validar</td><td>Existe en codigo — sin prueba real en target</td></tr>
            <tr><td>M8 Stress</td><td> Sin validar</td><td>Existe en codigo — sin prueba real en target</td></tr>
        </tbody>
    </table>

</div>

<footer>
    <p>Powered by <strong>LokiTrace VAA v4.0.0</strong> &nbsp;|&nbsp; Desarrollado por LokiTrace Security (n1000)</p>
    <p style="margin-top:4px;">Este reporte es confidencial. Uso exclusivo del equipo de seguridad.</p>
</footer>

</body>
</html>
"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[+] Reporte HTML ejecutivo generado: {filename}")
        return filename

    @staticmethod
    def _get_owasp_ref(vtype: str):
        """Devuelve (owasp_ref, cwe) basado en el tipo de vulnerabilidad."""
        vl = vtype.lower()
        if "idor" in vl or "bola" in vl:
            return "API1:2023 — BOLA", "639"
        if "bfla" in vl or "privilege escalation" in vl:
            return "API5:2023 — BFLA", "285"
        if "mass_assignment" in vl or "mass assignment" in vl:
            return "API3:2023 — Mass Assignment", "915"
        if "resource_consumption" in vl or "api4" in vl:
            return "API4:2023 — Resource Consumption", "400"
        if "otp_brute_force" in vl or "otp brute" in vl:
            return "API2:2023 — Broken Authentication (Brute Force)", "307"
        if "sqli" in vl or "sql injection" in vl:
            return "API8:2023 — Injection (SQLi)", "89"
        if "xss" in vl or "cross-site" in vl:
            return "API8:2023 — Injection (XSS)", "79"
        if "server_error" in vl:
            return "API8:2023 — Security Misconfiguration", "209"
        if "exploit confirmed" in vl:
            return "API1:2023 — BOLA / Exposicion de datos", "200"
        if "sensitive" in vl or "leakage" in vl:
            return "API2:2023 — Broken Authentication", "200"
        if "exposed_documentation" in vl:
            return "API9:2023 — Improper Inventory", "200"
        if "missing_security_headers" in vl or "cors" in vl:
            return "API8:2023 — Security Misconfiguration", "693"
        if "jwt" in vl or "broken_authentication" in vl:
            return "API2:2023 — Broken Authentication", "345"
        if "ssrf" in vl:
            return "API7:2023 — SSRF", "918"
        if "prompt_injection" in vl:
            return "OWASP LLM01 — Prompt Injection", "1357"
        if "dos" in vl or "denial" in vl:
            return "API4:2023 — Resource Exhaustion", "400"
        return "", ""
