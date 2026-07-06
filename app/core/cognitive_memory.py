import json
import asyncio
from typing import Optional, Dict, Any, List
import asyncpg
import uuid

from app.config.settings import settings  # pyre-ignore[21]
from app.utils.logger import logger  # pyre-ignore[21]

class CognitiveMemory:
    """
    Gestor de Memoria Distribuida (PostgreSQL).
    Asegura que el agente VAA retenga conocimientos sobre escaneos pasados:
    - Entiende gramatica para omitir fuzzing redundante.
    - Memoriza exploits efectivos con factor de decaimiento.
    - Mantiene tracking de misiones.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(CognitiveMemory, cls).__new__(cls)
            cls._instance.pool = None
            cls._instance.enabled = False
        return cls._instance

    async def init_pool(self):
        """Inicializa el pool asincrono PostgreSQL con backoff. Si no hay DB configurada
        o la conexion falla, opera en modo degradado (enabled=False) sin bloquear el scan."""
        db_url = settings.VAA_DB_URL
        if not db_url:
            logger.warning(
                "[MEMORY] VAA_DATABASE_URL no configurado — Memoria Cognitiva desactivada. "
                "El scanner opera sin persistencia entre sesiones. "
                "Para activarla, setear VAA_DATABASE_URL antes de ejecutar."
            )
            self.enabled = False
            return


        if hasattr(self, '_keepalive_task') and self._keepalive_task:
            self._keepalive_task.cancel()

        max_retries = 3
        base_delay = 3

        for attempt in range(1, max_retries + 1):
            try:
                if attempt == 1:
                    logger.info(f"[MEMORY] Conectando a Base de Datos Cognitiva (Timeout: {settings.DB_TIMEOUT}s)...")

                self.pool = await asyncpg.create_pool(
                    dsn=db_url,
                    min_size=1,
                    max_size=3,
                    max_inactive_connection_lifetime=55.0,
                    command_timeout=settings.DB_TIMEOUT,
                    server_settings={'application_name': 'vaa_scanner'}
                )


                async with self.pool.acquire() as conn:
                    await conn.execute("SELECT 1")

                self.enabled = True
                logger.info("[MEMORY] Memoria Cognitiva conectada y lista.")

                self._keepalive_task = asyncio.create_task(self._ping_keepalive())
                return

            except Exception as e:
                if attempt < max_retries:
                    delay = base_delay * attempt
                    logger.warning(f"[MEMORY] Intento {attempt}/{max_retries} fallido ({str(e)}). Reintentando en {delay}s...")
                    await asyncio.sleep(delay)
                else:
                    logger.warning(
                        f"[MEMORY] No se pudo conectar a PostgreSQL tras {max_retries} intentos: {str(e)}. "
                        "Continuando sin Memoria Cognitiva (modo degradado)."
                    )
                    self.enabled = False

    async def _ping_keepalive(self):
        """Mantiene la conexion TCP viva enviando un latido cada 45s."""
        self._consecutive_errors = 0
        while self.enabled and self.pool:
            try:
                await asyncio.sleep(45)
                async with self.pool.acquire() as conn:
                    await conn.execute("SELECT 1")
                    
                if self._consecutive_errors > 0:
                    logger.info(f"[MEMORY] Keep-Alive restaurado tras {self._consecutive_errors} error(es) consecutivo(s).")
                    self._consecutive_errors = 0
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self._consecutive_errors += 1
                logger.debug(f"[MEMORY] Keep-Alive error #{self._consecutive_errors}: {e}")

    async def close_pool(self):
        """Cierra el pool ordenadamente."""
        if hasattr(self, '_keepalive_task') and self._keepalive_task:
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
                
        if self.pool and self.enabled:
            await self.pool.close()
            logger.info("[MEMORY] Conexion de Memoria Cognitiva cerrada.")


    async def learn_grammar(self, path: str, param_name: str, param_data: Dict[str, Any]):
        """Memoriza que un parametro particular existe en una ruta (Upsert)."""
        if not self.enabled: return
        query = """
            INSERT INTO grammar_entries (path, param_name, param_data, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (path, param_name) DO UPDATE 
            SET param_data = EXCLUDED.param_data, updated_at = NOW();
        """
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query, path, param_name, json.dumps(param_data))
        except Exception as e:
            logger.debug(f"[MEMORY] Error en learn_grammar para {path}: {e}")

    async def recall_grammar(self, path: str) -> Dict[str, Any]:
        """Recupera la memoria estructural sobre una ruta conocida."""
        if not self.enabled: return {}
        query = "SELECT param_name, param_data FROM grammar_entries WHERE path = $1;"
        results = {}
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(query, path)
                for r in rows:
                    results[r['param_name']] = json.loads(r['param_data'])
        except Exception as e:
            logger.debug(f"[MEMORY] Error comprobando memoria de gramatica en {path}: {e}")
        return results


    async def memorize_exploit(self, domain: str, norm_path: str, vuln_type: str, payload: str, confidence: float):
        """Loguea un hallazgo solido en memoria."""
        if not self.enabled or confidence < 0.80: 
            return
            
        payload_truncated = payload[:200] if payload else ""
        
        query = """
            INSERT INTO exploit_memory (domain, norm_path, vuln_type, payload, confidence, scan_count, scan_date)
            VALUES ($1, $2, $3, $4, $5, 1, NOW())
            ON CONFLICT (domain, norm_path, vuln_type, payload) DO UPDATE
            SET confidence = EXCLUDED.confidence,
                scan_count = exploit_memory.scan_count + 1,
                scan_date  = NOW();
        """
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query, domain, norm_path, vuln_type, payload_truncated, float(confidence))
            logger.info(f"[MEMORY] Exploit memorizado [{vuln_type}] en {norm_path}")
        except Exception as e:
            logger.debug(f"[MEMORY] Error memorizando exploit: {e}")

    async def get_prior_exploits(self, domain: str) -> List[Dict[str, Any]]:
        """Recupera vulnerabilidades confirmadas previamente en el dominio."""
        if not self.enabled: return []
        query = "SELECT norm_path, vuln_type, payload, confidence FROM exploit_memory WHERE domain = $1 ORDER BY confidence DESC;"
        exploits = []
        try:
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(query, domain)
                for r in rows:
                    exploits.append(dict(r))
        except Exception as e:
             logger.debug(f"[MEMORY] Error recuperando prior_exploits: {e}")
        return exploits


    async def log_endpoint(self, domain: str, norm_path: str, method: str, requires_auth: bool, 
                           auth_scheme: Optional[str], last_status: int, param_schema: Dict[str, Any]):
        """Memoriza existencia y metadata de un Endpoint."""
        if not self.enabled: return
        query = """
            INSERT INTO endpoint_intel (domain, norm_path, method, requires_auth, auth_scheme, last_status, param_schema, last_seen)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            ON CONFLICT (domain, norm_path, method) DO UPDATE
            SET requires_auth = EXCLUDED.requires_auth,
                auth_scheme   = EXCLUDED.auth_scheme,
                last_status   = EXCLUDED.last_status,
                param_schema  = EXCLUDED.param_schema,
                last_seen     = NOW();
        """
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query, domain, norm_path, method, bool(requires_auth), 
                                   auth_scheme, last_status, json.dumps(param_schema))
        except Exception as e:
             logger.debug(f"[MEMORY] Error en log_endpoint {norm_path}: {e}")


    async def start_mission(self, domain: str) -> str:
        """Inicia una mision escaneao, devuelve UUID"""
        if not self.enabled: return str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        query = "INSERT INTO scan_history (domain, scan_id, status) VALUES ($1, $2, 'running');"
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query, domain, scan_id)
            return scan_id
        except Exception as e:
            logger.debug(f"[MEMORY] Error en start_mission: {e}")
            return scan_id

    async def end_mission(self, scan_id: str, total_findings: int):
        """Finaliza la mision"""
        if not self.enabled: return
        query = """
            UPDATE scan_history 
            SET status = 'done', finished_at = NOW(), total_findings = $1
            WHERE scan_id = $2;
        """
        try:
            async with self.pool.acquire() as conn:
                await conn.execute(query, total_findings, scan_id)
        except Exception as e:
             logger.debug(f"[MEMORY] Error en end_mission: {e}")


memory = CognitiveMemory()
