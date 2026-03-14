"""
Logging sistem za pyshield antivirus: Belezi se skeniranje, detekcije, greske.
"""

import logging
import os
from datetime import datetime

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "pyshield.log")

def setup_logger():
    """
        Podesava i vraca glavni logger za celu aplikaciju
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger("Pyshield")

    #provera da li log sadrzi handler, ako postoje funkcija odma vraca handler
    if logger.handlers:
        return logger
    
    logger.setLevel(logging.DEBUG)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    #povezivanje handlera sa loggerom, sada ce se logovi upisivati u fajl i prikazivati na konzoli
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

logger= setup_logger()
