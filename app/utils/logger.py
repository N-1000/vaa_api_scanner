import logging
import sys
import os


if os.name == 'nt':
    os.system('')


class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

class VaaFormatter(logging.Formatter):
    """
    Custom Formatter for VAA that mimics the previous print style but adds structure.
    """
    
    FORMATS = {
        logging.DEBUG:    Colors.DIM + "[DEBUG] %(message)s" + Colors.RESET,
        logging.INFO:     Colors.CYAN + "[*] %(message)s" + Colors.RESET,
        logging.WARNING:  Colors.YELLOW + "[!] %(message)s" + Colors.RESET,
        logging.ERROR:    Colors.RED + "[-] %(message)s" + Colors.RESET,
        logging.CRITICAL: Colors.RED + Colors.BOLD + "[!] CRITICAL: %(message)s" + Colors.RESET
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, "%(message)s")
        formatter = logging.Formatter(log_fmt)
        

        msg = record.msg
        if isinstance(msg, str):
             if msg.strip().startswith("[+]"):

                 log_fmt = Colors.GREEN + "%(message)s" + Colors.RESET
                 formatter = logging.Formatter(log_fmt)
        
        return formatter.format(record)

from logging.handlers import RotatingFileHandler
from app.config.settings import settings  # pyre-ignore[21]

def setup_logger(name="VAA", level=logging.DEBUG):
    """
    Sets up the global logger configuration.
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)


    if logger.hasHandlers():
        return logger


    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(VaaFormatter())
    logger.addHandler(console_handler)


    log_file = os.path.join(settings.LOGS_DIR, "vaa.log")
    
    try:
        file_handler = RotatingFileHandler(
            log_file, 
            maxBytes=settings.LOG_MAX_BYTES,
            backupCount=settings.LOG_BACKUP_COUNT,
            encoding='utf-8'
        )

        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except Exception as e:

        print(f"[-] Warning: Failed to set up file logging: {e}")

    return logger


logger = setup_logger(level=logging.INFO)
