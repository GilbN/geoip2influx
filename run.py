#!/usr/bin/env python3

import os
import logging
import signal
from geoip2influx import LogParser, configure_logging

from dotenv import load_dotenv
load_dotenv()

def handle_sigterm(signum, frame):
    logger = logging.getLogger("g2i")
    logger.info("Received SIGTERM. Exiting GeoIP2Influx.")
    logger.info("Parsed %d log line(s).", parser.parsed_lines)
    exit(0)

if __name__ == "__main__":
    try:
        configure_logging(os.getenv("GEOIP2INFLUX_LOG_LEVEL", "debug"))
        signal.signal(signal.SIGTERM, handle_sigterm)
        logger = logging.getLogger("g2i")
        logger.info("Starting GeoIP2Influx.")
        parser = LogParser()
        parser.run()
    except KeyboardInterrupt:
        logger.info("Exiting GeoIP2Influx.")
        logger.info("Parsed %d log line(s).", parser.parsed_lines)
        exit(0)
    except Exception:
        logger.exception("Error running parser.")
        exit(1)
