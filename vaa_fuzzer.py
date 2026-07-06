import argparse
import asyncio
import sys
import os
import time

sys.path.append(os.getcwd())
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')

from app.config.settings import settings
from app.utils.logger import logger
from app.core.network_manager import NetworkManager
from app.core.m1_grammar import M1GrammarModel
from app.core.m8_chronos import M8Chronos
from app.core.m3_classification import M3IntelligentClassifier
from app.core.m9_params import M9ParameterDiscovery
from app.core.m2_generation import M2AdaptiveGenerator
from app.core.engine.phases import fuzzer

def main():
    logger.info(f"""
    ███████╗██╗   ██╗███████╗███████╗███████╗██████╗ 
    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██╔════╝██╔══██╗
    █████╗  ██║   ██║  ███╔╝   ███╔╝ █████╗  ██████╔╝
    ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██╔══╝  ██╔══██╗
    ██║     ╚██████╔╝███████╗███████╗███████╗██║  ██║
    ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
    VAA FUZZER - Fuerza Bruta y Análisis Agresivo
    v{settings.VERSION}
    """)

    parser = argparse.ArgumentParser(description="VAA Fuzzer - Módulo de Fuzzing Agresivo (SQLi, XSS, SSRF, RCE)")
    
    parser.add_argument("target", help="URL base objetivo (ej: https://api.example.com)")
    parser.add_argument("--auth", help="Token de autorización (Bearer/API Key)")
    parser.add_argument("--auth-b", help="Token B para pruebas IDOR en fuzzing")
    parser.add_argument("--concurrency", type=int, default=5, help="Nivel de concurrencia (default: 5)")
    parser.add_argument("--proxy", help="URL del Proxy (ej: http://127.0.0.1:8080)")
    parser.add_argument("--tor", action="store_true", help="Usar proxy SOCKS5 Tor local")
    parser.add_argument("--ghost", action="store_true", help="Activar Ghost Protocol (M5) para evasión de WAF")
    parser.add_argument("--no-rce", action="store_true", help="Desactivar payloads de ejecución de comandos")
    parser.add_argument("--no-ai", action="store_true", help="Desactivar payloads de inyección de prompts/AI")

    args = parser.parse_args()

    options = {
        "auth_token": args.auth,
        "auth_b_token": args.auth_b,
        "concurrency": args.concurrency,
        "proxy": args.proxy,
        "use_tor": args.tor,
        "use_ghost": args.ghost,
        "scan_rce": not args.no_rce,
        "scan_ai": not args.no_ai
    }

    logger.info(f"[*] Objetivo: {args.target}")
    logger.info(f"[*] Concurrencia: {args.concurrency}")
    logger.info(f"[*] RCE activado: {not args.no_rce}")
    logger.info(f"[*] Ghost Protocol: {args.ghost}")

    try:
        asyncio.run(run_fuzzer(args.target, options))
    except KeyboardInterrupt:
        logger.warning("\n[!] Fuzzing interrumpido por el usuario.")
    except Exception as e:
        logger.critical(f"\n[!] Error crítico: {e}")
        import traceback
        traceback.print_exc()

async def run_fuzzer(target: str, options: dict):
    from app.core.engine.algorithms.shannon import ShannonOracle
    from app.core.engine.models import EndpointTarget

    # Simulando el descubrimiento de endpoints de recon (en la vida real lo sacaríamos de Swagger o M74P1)
    # Por ahora probamos con un par de endpoints estáticos para que el fuzzer arranque.
    dummy_endpoints = [
        EndpointTarget(url=f"{target}/api/v1/users/1", method="GET", confidence=1.0, tags=["user"]),
        EndpointTarget(url=f"{target}/api/v1/products/search", method="POST", confidence=1.0, tags=["search"])
    ]

    net_mgr = NetworkManager(target, options)
    oracle = ShannonOracle()
    sem = asyncio.Semaphore(options["concurrency"])
    
    m1 = M1GrammarModel()
    m2 = M2AdaptiveGenerator(options)
    m3 = M3IntelligentClassifier()
    m9 = M9ParameterDiscovery()
    
    validation_queue = asyncio.Queue()
    queue_dedup = set()
    abort_scan_ref = [False]
    stats = {"total_requests": 0, "429_count": 0, "401_count": 0}

    def dummy_record(finding: dict, via_queue=False):
        logger.info(f"[*] HALLAZGO: {finding.get('type')} en {finding.get('url')} | Payload: {finding.get('payload')}")

    def dummy_harvest(text: str, url: str):
        pass

    async def dummy_token_health(url: str):
        return True

    logger.info("[+] Iniciando motor de Fuzzing...")
    
    async with net_mgr.create_client():
        await fuzzer.run(
            endpoints=dummy_endpoints,
            network_manager=net_mgr,
            options=options,
            sem=sem,
            oracle=oracle,
            m1_grammar_context={},
            m1_classify=m1.classify_endpoint_type,
            m2_generate_suite=m2.generate_payload_suite,
            m2_prioritize=m2.prioritize_payloads_by_endpoint_type,
            m3_predict_risk=m3.predict_risk,
            m9_discover_params=m9.discover_params,
            harvest_from_response=dummy_harvest,
            record_finding=dummy_record,
            validation_queue=validation_queue,
            queue_dedup=queue_dedup,
            target=target,
            detected_stack=[],
            abort_scan_ref=abort_scan_ref,
            stats=stats,
            token_health_check=dummy_token_health
        )
    
    logger.info("[+] Fuzzing completado.")

if __name__ == "__main__":
    main()
