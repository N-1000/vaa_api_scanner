

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


BASE_DIR = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
MODELS_DIR = os.path.join(BASE_DIR, "models")
LOGS_DIR = os.path.join(BASE_DIR, "logs")


for d in [REPORTS_DIR, MODELS_DIR, LOGS_DIR]:
    os.makedirs(d, exist_ok=True)

class Config:

    APP_NAME = "LokiTrace API Security Scanner"
    COMPANY = "LokiTrace Security"
    AUTHOR = "n1000"
    VERSION = "4.0.0"
    DEFAULT_USER_AGENT = "UA-BugBounty"
    H1_EMAIL = os.getenv("H1_EMAIL", "anonymous@example.com")
    

    BASE_DIR = BASE_DIR
    

    DEFAULT_TIMEOUT = 10.0
    DEFAULT_DELAY = 2.0
    MAX_CONCURRENCY = 2
    

    MODELS_DIR = MODELS_DIR
    REPORTS_DIR = REPORTS_DIR
    LOGS_DIR = LOGS_DIR


    IGNORED_EXTENSIONS = [
        ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".js", ".pdf", ".json", ".map", ".mp4", ".mp3", ".avi"
    ]
    
    TRACKING_PARAMS = [
        "rs", "source", "ref", "utm_source", "utm_medium", "utm_campaign",
        "rp", "fbclid", "gclid", "_ga", "yclid"
    ]


    BROWSER_HEADLESS = True
    BROWSER_ARGS = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-blink-features=AutomationControlled"
    ]
    

    IGNORED_DOMAINS = [
        "google-analytics.com", "googletagmanager.com", "facebook.com", 
        "doubleclick.net", "twitter.com", "linkedin.com", "fonts.googleapis.com",
        "stripe.com", "paypal.com", "nr-data.net", "typekit.net", "bam.nr-data.net"
    ]
    

    IGNORED_PATHS = [
        '/docs', '/documentation', '/swagger', '/api-docs', 
        '/node_modules', '/vendor', '/_next', '/static', '/assets',
        '/logout', '/signout'
    ]
    

    IMPORT_API_ONLY = True
    API_PATH_KEYWORDS = [
        '/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/json', '/v4.0.0/', '/v4.0.0/'
    ]
    API_MIME_TYPES = [
        'application/json', 'application/xml', 'text/xml', 'application/javascript'
    ]
    
    
    WAF_BLOCK_SIGNATURES = [
        "Just a moment...",
        "Attention Required! | Cloudflare",
        "Access Denied", 
        "Security Check",
        "WAF Blocked"
    ]
    

    POWER_KEYS = {
        "is_admin": True,
        "role": "admin",
        "admin": True,
        "superuser": True,
        "balance": 999999,
        "credit": 999999,
        "fee_waived": True,
        "commission_rate": 0,
        "bypass_kyc": True,
        "tier": "gold",
        "premium": True,
        "debug": True
    }


    MAX_ENDPOINTS = 100


    STRESS_CONCURRENCY = 50
    STRESS_DURATION = 30
    STRESS_RAMP_UP = 5
    M8_RISK_ERROR_RATE = 5.0
    M8_RISK_LATENCY_MS = 1000


    ASM_CONCURRENCY_FAST = 50
    ASM_CONCURRENCY_SAFE = 5
    ASM_JITTER_MIN = 0.5
    ASM_JITTER_MAX = 2.0
    

    WINDOWS_MAX_THREADS = 60


    USE_STEALTH_CLIENT = True


    RCE_CALLBACK_HOST = "10.0.0.1"
    RCE_CALLBACK_PORT = 4444


    MODEL_SHA256 = None


    VERIFY_SSL: bool = os.getenv("VAA_VERIFY_SSL", "true").lower() == "true"


    TOR_CONTROL_PORT = 9051
    TOR_SOCKS_PORT = 9050
    TOR_ROTATION_THRESHOLD = 50
    

    LOG_MAX_BYTES = 5 * 1024 * 1024
    LOG_BACKUP_COUNT = 3
    

    DEFAULT_REPORTS_DIR = REPORTS_DIR


    RETINA_VIEWPORT = {'width': 1920, 'height': 1080}
    RETINA_MOUSE_STEPS = (20, 50)


    SECRET_MINING_ENTROPY_MIN = 4.8
    SECRET_MINING_ENTROPY_HIGH = 5.3
    M7_API_MODE_TIMEOUT = 10.0


    VESTA_DEDUPLICATION_LEVEL = 1
    VESTA_MAX_PER_CLUSTER = 3


    VAA_DB_URL: str = os.getenv("VAA_DATABASE_URL", "")
    DB_TIMEOUT: float = float(os.getenv("VAA_DB_TIMEOUT", "3.0"))

    CREDENTIAL_SERVER: str = os.getenv("CREDENTIAL_SERVER", "$0ftw4r3.v44")
    

settings = Config()
