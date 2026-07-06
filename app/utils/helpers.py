import re

def normalize_path_structure(path: str) -> str:
    """
    Normalizes a URL path by replacing dynamic segments like UUIDs and integers
    with structural placeholders ({UUID}, {ID}).
    
    This ensures consistent endpoint clustering and signature generation
    across the entire scanning engine (e.g., used by M6, M12).
    """

    sig = re.sub(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 
        '{UUID}', 
        path, 
        flags=re.IGNORECASE
    )
    

    sig = re.sub(r'/\d+/', '/{ID}/', sig)
    

    sig = re.sub(r'/\d+$', '/{ID}', sig)
    
    return sig
