"""Main entry point for KeenGuard server."""
import logging
import sys

# Suppress raw Scapy libpcap warnings on Windows (handled cleanly by KeenGuard logger)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

import uvicorn
from keenguard.config import settings

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    logger = logging.getLogger("keenguard")
    logger.info("==================================================")
    logger.info("KeenGuard: Network Security & Forensics for Keenetic")
    logger.info("Web Interface: http://%s:%d", settings.web_host if settings.web_host != "0.0.0.0" else "127.0.0.1", settings.web_port)
    logger.info("==================================================")

    uvicorn.run(
        "keenguard.web.app:app",
        host=settings.web_host,
        port=settings.web_port,
        log_level="info",
        access_log=True
    )

if __name__ == "__main__":
    main()
