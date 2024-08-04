#!/usr/bin/env python3

from geoip2influx.logger import configure_logging
import os
import logging

from geoip2influx.logparser import LogParser

from dotenv import load_dotenv
load_dotenv()

if __name__ == "__main__":
    try:
        configure_logging(os.environ.get("GEOIP2INFLUX_LOG_LEVEL", "debug"))
        logger = logging.getLogger("g2i")
        logger.info("Starting GeoIP2Influx.")
        parser = LogParser()
        parser.run()
    except KeyboardInterrupt:
        logger.info("Exiting GeoIP2Influx.")
        exit(0)
    except Exception:
        logger.exception("Error running parser.")
        exit(1)
