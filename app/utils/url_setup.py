
"""
Utilidad de Limpieza de URLs.
Evita bucles infinitos en el crawler eliminando parametros de rastreo
"""

from urllib.parse import urlparse, parse_qs
from app.config.settings import settings  # pyre-ignore[21]

def clean_tracking_params(url: str) -> str:
    """
    Elimina parametros de rastreo conocidos (rs, source, ref, etc.) de una URL.
    Retorna la URL limpia.
    Usado por M7 Crawler para prevenir bucles infinitos.
    """
    parsed = urlparse(url)
    if not parsed.query:
        return url
        
    qs = parse_qs(parsed.query)
    clean_query = []
    

    tracking_params = settings.TRACKING_PARAMS
    
    for k, v in qs.items():
        if k not in tracking_params:
            for val in v:
                clean_query.append(f"{k}={val}")
                
    final_path = parsed.path
    if clean_query:

        final_path += "?" + "&".join(clean_query)
    

    if parsed.scheme:
        return f"{parsed.scheme}://{parsed.netloc}{final_path}"
    
    return final_path
