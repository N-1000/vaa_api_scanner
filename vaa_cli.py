
import argparse
import asyncio
import sys
import os
import yaml  # pyre-ignore[21]
import re

sys.path.append(os.getcwd())
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

from app.core.engine import ScanOrchestrator  # pyre-ignore[21]
from app.config.settings import settings  # pyre-ignore[21]
from app.utils.logger import logger  # pyre-ignore[21]
from urllib.parse import urlparse

def load_config(path="scan.yaml"):
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                logger.info(f"Cargando configuracion desde {path}...")
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"Error leyendo {path}: {e}")
    return {}

def icon(val):
    return "ON" if val else "OFF"

def validate_target_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)
    except Exception:
        return False

def main():
    logger.info(f"""
    ██╗      ██████╗ ██╗  ██╗██╗████████╗██████╗  █████╗  ██████╗███████╗    █████╗ ██████╗ ██╗
    ██║     ██╔═══██╗██║ ██╔╝██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝   ██╔══██╗██╔══██╗██║
    ██║     ██║   ██║█████╔╝ ██║   ██║   ██████╔╝███████║██║     █████╗     ███████║██████╔╝██║
    ██║     ██║   ██║██╔═██╗ ██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝     ██╔══██║██╔═══╝ ██║
    ███████╗╚██████╔╝██║  ██╗██║   ██║   ██║  ██║██║  ██║╚██████╗███████╗██╗██║  ██║██║     ██║
    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝╚═╝  ╚═╝╚═╝     ╚═╝
     #MAY ALL YOUR DREAMS COME TRUE. AMEN
    {settings.APP_NAME} - v{settings.VERSION}
    Desarrollado por: {settings.AUTHOR} ({settings.COMPANY})
    """)


    yaml_config = load_config()
    

    defaults = {
        "target": yaml_config.get("target"),
        "modes": yaml_config.get("modes", {}),
        "evasion": yaml_config.get("evasion", {}),
        "advanced": yaml_config.get("advanced", {})
    }

    parser = argparse.ArgumentParser(description="Agente de Evaluacion de Vulnerabilidades (VAA)")
    

    parser.add_argument("PositionalTarget", nargs="?", help="URL Objetivo o Archivo Local (Sin flag --target)")
    parser.add_argument("--target", help="URL Objetivo (ej: https://api.example.com)")
    parser.add_argument("--target-endpoint", help="[QUIRURGICO] Endpoint especifico a auditar (ej: /api/v1/users/1)")
    parser.add_argument("--method", default="GET", help="[QUIRURGICO] Metodo HTTP para el endpoint especifico (default: GET)")
    parser.add_argument("--env", help="Archivo de Environment de Postman (.json)")
    parser.add_argument("--auth", help="Token de autenticacion (Bearer/API Key) para inyectar en todas las peticiones")
    parser.add_argument("--auth-refresh-cmd", help="Comando shell a ejecutar para renovar el token si expira (ej: 'curl ... | jq -r .token')")
    

    parser.add_argument("--recon", action="store_true", help="Activar Descubrimiento de Endpoints")
    parser.add_argument("--fuzz", action="store_true", help="Activar Ataques de Inyeccion")
    parser.add_argument("--logic", action="store_true", help="Activar Analisis de Logica (BOLA/IDOR)")
    

    parser.add_argument("--tor", action="store_true", help="Rutar todo el trafico via TOR (SOCKS5). Requiere TOR instalado y corriendo.")
    parser.add_argument("--ghost", action="store_true", help="Modo Sigilo: User-Agent aleatorio + delays variables (Implica Anonimato)")
    

    parser.add_argument("--optimize", action="store_true", help="Activar optimizacion M12 Vesta")
    parser.add_argument("--delay", type=float, default=0.0, help="Retraso base")
    

    parser.add_argument("--safe", action="store_true", help="Modo Seguro: Filtra payloads destructivos (DROP, DELETE, TRUNCATE)")
    parser.add_argument("--force-destructive", action="store_true", help="Permitir payloads destructivos (DROP TABLE, DELETE, etc). PELIGROSO en produccion")
    parser.add_argument("--no-ai", action="store_true", help="Desactivar AI")
    parser.add_argument("--no-rce", action="store_true", help="Desactivar RCE")
    parser.add_argument("--no-jwt-audit", action="store_true",
                        help="[v4.0.0] Desactivar la auditoria JWT (alg:none, claim escalation). Util si el token es de produccion y no se quiere modificar.")
    parser.add_argument("--mass-assign", action="store_true",
                        help="[v4.0.0] Activar Mass Assignment activo (API3). Envia campos extra en POST/PUT sin necesitar HAR.")
    parser.add_argument("--victim-email", dest="victim_email", default=None,
                        help="[v4.0.0] Email de la cuenta victima para OTP brute force (API2). Si se omite, usa el email del auto-registro.")
    parser.add_argument("--m1-classify-debug", action="store_true",
                        help="[v4.0.0] Loguear en DEBUG el tipo de endpoint asignado por M1 (auditar clasificacion antes de declarar exito de M1->M2)")
    parser.add_argument("--debug-pipeline", action="store_true",
                        help="[v4.0.0] Activar trazabilidad estructurada del pipeline de deteccion. Emite reports/pipeline_trace_<ts>.jsonl con el journey de cada hallazgo por capa (Shannon/M3/validate/report).")


    parser.add_argument("--no-memory", action="store_true", help="[v8.0] No cargar ni guardar memoria persistente para este scan.")
    parser.add_argument("--reset-memory", action="store_true", help="[v8.0] Ignorar exploits previos del dominio e iniciar con memoria limpia.")


    parser.add_argument("--report-threshold", type=float, default=0.6, help="Umbral minimo de confianza para reportar hallazgos (default: 0.6)")


    parser.add_argument("--har-a", help="HAR Usuario A")
    parser.add_argument("--har-b", help="HAR Usuario B")
    parser.add_argument("--auth-b", help="Token Bearer del usuario VICTIMA para IDOR cross-session (M6 Enfoque 1). Si se omite con --logic, el scanner intenta auto-registrar un usuario victima.")
    parser.add_argument("--headers", help="Cabeceras Custom")
    parser.add_argument("--proxy", help="Proxy URL")


    args = parser.parse_args()
    

    pos_arg = args.PositionalTarget
    input_src = None
    target = None
    
    if pos_arg:
        if os.path.exists(pos_arg):

             input_src = pos_arg
             logger.info(f"[*] Modo Archivo Detectado: {input_src}")
        else:

             if validate_target_url(pos_arg):
                 target = pos_arg
                 input_src = pos_arg
             else:

                 logger.error(f"Error: El argumento '{pos_arg}' no es un archivo existente ni una URL valida.")
                 sys.exit(1)
                 

    if args.target:
        if not validate_target_url(args.target):
             logger.error(f"Error: --target '{args.target}' no es una URL valida.")
             sys.exit(1)

        target = args.target

        if not input_src:
            input_src = args.target


    if not target and defaults.get("target"):
        target = defaults.get("target")
        if not input_src: input_src = target

    if not input_src:
        parser.print_help()
        sys.exit(1)
    

    if input_src and os.path.exists(str(input_src)) and not target:
         try:
            with open(str(input_src), 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(5000)
                extracted_url = None
                

                if '"openapi":' in content or '"swagger":' in content:
                    match = re.search(r'"servers":\s*\[\s*\{\s*"url":\s*"([^"]+)"', content)
                    if match:
                       extracted_url = match.group(1)
                    else:
                        host_match = re.search(r'"host":\s*"([^"]+)"', content)
                        scheme_match = re.search(r'"schemes":\s*\[\s*"([^"]+)"', content)
                        base_match = re.search(r'"basePath":\s*"([^"]+)"', content)
                            
                        if host_match:
                            host = host_match.group(1)
                            scheme = scheme_match.group(1) if scheme_match else "http"
                            base = base_match.group(1) if base_match else ""
                            extracted_url = f"{scheme}://{host}{base}"

                if extracted_url:
                    if extracted_url.startswith("http"):
                         logger.info(f"[*] Auto-Detecion de Target URL exitosa: {extracted_url}")
                         target = extracted_url 
                    else:
                         logger.warning(f"[!] URL Relativa detectada en archivo ({extracted_url}). Se requiere --target <URL_BASE>.")
                else:
                    logger.warning("[!] No se pudo extraer una URL base del archivo. Se requiere --target <URL_BASE>.")
         except Exception as e:
            logger.warning(f"Error en auto-deteccion de target: {e}")


    if not target:
         logger.error("Error: No se pudo determinar un Target URL. Usa --target o provee un archivo con URL base definida.")
         sys.exit(1)
    

    if args.safe and args.force_destructive:
        logger.error("Error: --safe y --force-destructive son mutuamente excluyentes")
        sys.exit(1)
        
    logger.info("INICIANDO VAAS")
    
    auto_pilot = not (args.recon or args.fuzz or args.logic)
    

    if auto_pilot:
        logger.warning("[AUTO-PILOT] No se especificaron flags de fase (--recon, --fuzz, --logic)")
        logger.warning("Ejecutando TODAS las fases disponibles automaticamente")
    
    mode_recon = True if auto_pilot else args.recon
    mode_fuzz = True if auto_pilot else args.fuzz
    mode_logic = True if auto_pilot else args.logic
    

    if mode_logic:
        has_hars = bool(args.har_a and args.har_b)
        has_tokens = bool(args.auth and args.auth_b)
        if not (has_hars or has_tokens):
            if auto_pilot:
                logger.info("[AUTO-PILOT] Sin HAR A/B ni Tokens A/B. Desactivando Logic (M6) por falta de sesiones.")
                mode_logic = False
            else:
                logger.error("[ERROR] Has solicitado la fase --logic pero faltan las sesiones.")
                logger.error("La fase logica (M6) es estricta y requiere material de dos usuarios distintos para detectar IDOR/BOLA.")
                logger.error("Provee --har-a y --har-b, o provee --auth y --auth-b.")
                sys.exit(1)
    
    enable_ai = not args.no_ai
    enable_rce = not args.no_rce
    
    options = {
        "crawl": mode_recon,
        "fuzz_mode": mode_fuzz,
        "logic_mode": mode_logic,
        "target_endpoint": args.target_endpoint,
        "target_method": args.method,
        "api_type": "rest",
        "input_source": input_src,
        "env_file": args.env,
        "delay": args.delay,
        "custom_headers": args.headers,
        "auth_token": args.auth,
        "auth_refresh_cmd": args.auth_refresh_cmd,
        "auth_b_token": args.auth_b,
        "proxy": args.proxy,
        "scan_ai": enable_ai and mode_fuzz,
        "scan_rce": enable_rce and mode_fuzz,
        "use_tor": args.tor,
        "use_ghost": args.ghost,
        "har_files": {"a": args.har_a, "b": args.har_b},
        "safe_mode": args.safe,
        "force_destructive": args.force_destructive,
        "optimize": args.optimize,
        "m1_classify_debug": args.m1_classify_debug, 
        "no_jwt_audit": args.no_jwt_audit,       
        "mass_assign": args.mass_assign,          
        "victim_email": args.victim_email,         
        "debug_pipeline": args.debug_pipeline,       
        "no_memory": args.no_memory,            
        "reset_memory": args.reset_memory,         
        "report_threshold": args.report_threshold,
    }

    # Auto-extrae tokens de los HARs si no se dieron explicitamente con --auth / --auth-b
    def _extract_token_from_har(har_path: str) -> str:
        """Lee el primer entry del HAR y extrae el valor del header Authorization."""
        try:
            import json as _json
            with open(har_path, 'r', encoding='utf-8', errors='ignore') as _f:
                _data = _json.load(_f)
            _entries = _data.get('log', {}).get('entries', [])
            for _entry in _entries:
                for _hdr in _entry.get('request', {}).get('headers', []):
                    if _hdr.get('name', '').lower() == 'authorization':
                        return _hdr.get('value', '')
        except Exception as _e:
            logger.debug(f"[CLI] No se pudo extraer token del HAR: {_e}")
        return ''

    if not options["auth_token"] and args.har_a and os.path.exists(args.har_a):
        _tok_a = _extract_token_from_har(args.har_a)
        if _tok_a:
            options["auth_token"] = _tok_a
            logger.info(f"[CLI] Token A auto-extraido del HAR: {_tok_a[:40]}...")

    if not options["auth_b_token"] and args.har_b and os.path.exists(args.har_b):
        _tok_b = _extract_token_from_har(args.har_b)
        if _tok_b:
            options["auth_b_token"] = _tok_b
            logger.info(f"[CLI] Token B auto-extraido del HAR: {_tok_b[:40]}...")

    logger.info(f"Configuracion Activa: Recon={icon(mode_recon)} Fuzz={icon(mode_fuzz)} Logic={icon(mode_logic)} Optimize={icon(args.optimize)}")
    
    try:
        orchestrator = ScanOrchestrator(target, options)
        asyncio.run(orchestrator.execute_mission())
    except KeyboardInterrupt:
        logger.warning("Mision abortada por el operador.")
        import traceback
        traceback.print_exc()
    except Exception as e:
        logger.critical(f"Error inesperado durante la ejecucion: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
