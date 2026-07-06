import asyncio
import httpx
import time
from typing import Dict, Any
from app.config.settings import settings
from app.utils.metrics import StatsCollector
from app.utils.logger import logger

class M8Chronos:
    """
    Modulo M8: Inteligencia de Rendimiento y Estres.
    Responsable de auditorias de disponibilidad (DoS Logico) y tiempos de respuesta.
    """
    
    def __init__(self):
        self.stats = StatsCollector()
        self.concurrency = settings.STRESS_CONCURRENCY
        self.duration = settings.STRESS_DURATION
        

        import platform
        if platform.system() == "Windows" and self.concurrency > settings.WINDOWS_MAX_THREADS:
            logger.warning(f"M8: Limitando threads de estres (Windows Policy). Solicitado: {self.concurrency}")
            self.concurrency = settings.WINDOWS_MAX_THREADS
        
    async def run_stress_test(self, target_url: str, custom_headers: Dict = None, concurrency: int = None, duration: int = None, verify: bool = None) -> Dict[str, Any]:
        """
        Ejecuta una prueba de carga contra el objetivo.
        Permite override dinamico de concurrencia, duracion y SSL verification.
        """
        verify_ssl = verify if verify is not None else settings.VERIFY_SSL

        active_concurrency = concurrency if concurrency else self.concurrency
        active_duration = duration if duration else self.duration
        

        import platform
        if platform.system() == "Windows" and active_concurrency > settings.WINDOWS_MAX_THREADS:
             logger.warning(f"M8: Limitando threads ({active_concurrency} -> {settings.WINDOWS_MAX_THREADS})")
             active_concurrency = settings.WINDOWS_MAX_THREADS

        logger.info(f"M8 Chronos: Iniciando prueba de estres contra {target_url}")
        logger.info(f"    - Concurrencia: {active_concurrency} threads")
        logger.info(f"    - Duracion: {active_duration} segundos")
        
        semaphore = asyncio.Semaphore(active_concurrency)
        start_time = time.time()
        
        async with httpx.AsyncClient(verify=verify_ssl, timeout=10.0, headers=custom_headers) as client:
            tasks = []
            active = True
            
            async def worker():
                while time.time() - start_time < active_duration:
                    async with semaphore:
                        try:

                            t0 = time.time()
                            r = await client.get(target_url)
                            t1 = time.time()
                            
                            latency = (t1 - t0) * 1000
                            self.stats.add_sample(latency, r.status_code)
                            
                        except Exception as e:

                            self.stats.errors += 1
                            

                    await asyncio.sleep(0.01)


            workers = [worker() for _ in range(active_concurrency)]
            await asyncio.gather(*workers)
            
        return self._analyze_results()

    def _analyze_results(self) -> Dict[str, Any]:
        """Analiza estadisticas y emite veredicto."""
        report = self.stats.calculate_stats()
        

        risk = "Low"
        verdict = "Stable Performance"
        
        if report.get("error_rate_percent", 0) > settings.M8_RISK_ERROR_RATE:
            risk = "High"
            verdict = f"Potential DoS Susceptibility (errors > {settings.M8_RISK_ERROR_RATE}%)"
        elif report.get("latency", {}).get("p95", 0) > settings.M8_RISK_LATENCY_MS:
            risk = "Medium"
            verdict = f"Performance Degradation Detected (p95 > {settings.M8_RISK_LATENCY_MS}ms)"
            
        report["risk"] = risk
        report["verdict"] = verdict
        return report

    async def check_performance_dos(self, target_url: str, verify: bool = None) -> Dict[str, Any]:
        """
        Verifica si el endpoint es susceptible a DoS Logico (Resource Exhaustion).
        Envia payloads pesados (ej. JSON anidado o Strings grandes) y mide degradacion.
        """
        logger.info(f"M8: Verificando DoS Logico en {target_url}...")
        verify_ssl = verify if verify is not None else settings.VERIFY_SSL
        

        async with httpx.AsyncClient(verify=verify_ssl, timeout=10.0) as client:

            t0 = time.time()
            try:
                await client.get(target_url)
            except Exception:
                pass
            baseline = (time.time() - t0) * 1000
            

            payload = "A" * 100000
            t1 = time.time()
            try:
                await client.post(target_url, data={"data": payload}, timeout=5.0)
            except httpx.ReadTimeout:
                return {"vulnerable": True, "reason": "Timeout con payload de 100KB", "factor": "Infinity"}
            except (httpx.TimeoutException, httpx.RequestError) as e:
                logger.debug(f"Error en payload DoS pesado: {e}")
            heavy_time = (time.time() - t1) * 1000
        
        factor = heavy_time / baseline if baseline > 0 else 0
        
        if factor > 10:
            return {
                "vulnerable": True,
                "reason": f"Degradacion Severa (10x) con payload pesado.",
                "evidence": {"baseline": baseline, "heavy": heavy_time, "factor": factor}
            }
            
        return {"vulnerable": False, "factor": factor}

    async def check_json_nesting_dos(self, target_url: str, verify: bool = None) -> Dict[str, Any]:
        """
        [NEW] Verifica DoS por anidamiento profundo de JSON (Stack Overflow / High CPU).
        Payload: {"a":{"a": ... {"a":1}...}}
        """
        logger.info(f"M8: Verificando JSON Nesting DoS en {target_url}...")
        verify_ssl = verify if verify is not None else settings.VERIFY_SSL
        
        depth = 2000
        payload = "{\"a\": " * depth + "1" + "}" * depth
        
        t0 = time.time()
        async with httpx.AsyncClient(verify=verify_ssl, timeout=10.0) as client:
            try:

                await client.post(target_url, content=payload, headers={"Content-Type": "application/json"})
            except httpx.ReadTimeout:
                logger.warning(f"M8: Timeout confirmado con JSON Depth {depth}")
                return {
                    "vulnerable": True, 
                    "type": "JSON_NESTING_DOS",
                    "evidence": f"Timeout (>10s) con profundidad {depth}",
                    "severity": "High"
                }
            except Exception as e:
                logger.debug(f"JSON Nesting Error: {e}")
                pass
                
        duration = (time.time() - t0) * 1000
        if duration > 5000:
             return {
                 "vulnerable": True,
                 "type": "JSON_NESTING_DOS",
                 "evidence": f"Latencia excesiva ({duration}ms) con profundidad {depth}",
                 "severity": "Medium"
             }
             
        return {"vulnerable": False}

    async def check_timing_attack(self, login_url: str, params: Dict) -> Dict:
        """
        Compara tiempos de respuesta entre usuario valido e invalido.
        [v4.0.0] Manejo optimizado de semáforos y delays.
        lo cual contaminaria el reporte de vulnerabilidades si alguna fase lo llama.
        Ahora lanza NotImplementedError para que el caller lo maneje explicitamente.
        """
        raise NotImplementedError(
            "check_timing_attack no esta implementado. "
            "Requiere usernames conocidos del target para comparar tiempos valido vs invalido."
        )
