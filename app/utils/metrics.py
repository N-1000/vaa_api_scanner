import statistics
import time
from typing import List, Dict

class StatsCollector:
    """
    Recolector de metricas de rendimiento para M8 Chronos.
    Calcula latencias y tasas de error.
    """
    def __init__(self):
        self.response_times: List[float] = []
        self.status_codes: Dict[int, int] = {}
        self.start_time = time.time()
        self.errors = 0
        
    def add_sample(self, response_time_ms: float, status_code: int):
        """Registra una peticion completada."""
        self.response_times.append(response_time_ms)
        self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1
        if status_code >= 400:
            self.errors += 1
            
    def calculate_stats(self) -> Dict:
        """Genera el reporte estadistico."""
        total_reqs = len(self.response_times)
        if total_reqs == 0:
             return {"error": "No data"}
             
        duration = time.time() - self.start_time
        rps = total_reqs / duration if duration > 0 else 0
        

        sorted_times = sorted(self.response_times)
        avg_lat = statistics.mean(sorted_times)
        p95_lat = sorted_times[int(total_reqs * 0.95)] if total_reqs > 20 else max(sorted_times)
        max_lat = max(sorted_times)
        min_lat = min(sorted_times)
        

        error_rate = (self.errors / total_reqs) * 100
        
        return {
            "total_requests": total_reqs,
            "duration_sec": round(duration, 2),
            "rps": round(rps, 2),
            "latency": {
                "min": round(min_lat, 2),
                "avg": round(avg_lat, 2),
                "p95": round(p95_lat, 2),
                "max": round(max_lat, 2)
            },
            "error_rate_percent": round(error_rate, 2),
            "status_codes": self.status_codes
        }
