#!/usr/bin/env python3

import re
import os
import time
import logging
from functools import wraps
import socket
from datetime import datetime

import geoip2
from geohash2 import encode
import geoip2.database
from geoip2.models import City

from IPy import IP

from .constants import ipv4_pattern, ipv6_pattern, MONITORED_IP_TYPES, ipv4, ipv6
from .influx import InfluxClient

logger = logging.getLogger(__name__)

def wait(timeout_seconds=60):
    """Factory Decorator to wait for a function to return True for a given amount of time.

    Args:
        timeout_seconds (int, optional): Defaults to 60.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs) -> bool:
            timeout: float = time.time() + timeout_seconds
            while time.time() < timeout:
                if func(*args, **kwargs):
                    return True
                time.sleep(1)
            logger.error(f"Timeout of {timeout_seconds} seconds reached on {func.__name__} function.")
            return False
        return wrapper
    return decorator

class LogParser:
    def __init__(self) -> None:
        self.log_path: str = os.getenv("NGINX_LOG_PATH", "/config/log/nginx/access.log")
        self.geoip_path: str = os.getenv("GEOIP_DB_PATH", "/config/geoip2db/GeoLite2-City.mmdb")
        self.geo_measurement = os.getenv("GEO_MEASUREMENT", "geoip2influx")
        self.log_measurement = os.getenv("LOG_MEASUREMENT", "nginx_access_logs")
        self.send_logs: bool = os.getenv("SEND_NGINX_LOGS", "true").lower() == "true"
       
        self.hostname: str = socket.gethostname()
        self.client = InfluxClient()
        self.geoip_reader = geoip2.database.Reader(self.geoip_path)
        self.current_log_inode: int|None = None
        self.parsed_lines: int = 0
        
        self.logger = logging.getLogger("LogParser")
        self.logger.debug("Log file path: %s", self.log_path)
        self.logger.debug("GeoIP database path: %s", self.geoip_path)
        self.logger.debug("GeoIP measurement name: %s", self.geo_measurement)
        self.logger.debug("NGINX log measurement name: %s", self.log_measurement)
        self.logger.debug("Send NGINX logs: %s", self.send_logs)
        self.logger.debug("Hostname: %s", self.hostname)
    
    def validate_log_line(self, log_line: str) -> re.Match[str] | None:
        """Validate the log line against the IPv4 and IPv6 patterns."""
        if self.send_logs:
            return ipv4_pattern().match(log_line) or ipv6_pattern().match(log_line)
        # If we are not sending logs but only geo data to influx, only validate the IP address
        self.send_logs = False
        return ipv4().match(log_line) or ipv6().match(log_line)

    @wait(timeout_seconds=60)
    def validate_log_format(self) -> bool: # regex tester
        """Try for 60 seconds and validate that the log format is correct by checking the last 3 lines."""
        LAST_LINE_COUNT = 3
        POSITION = LAST_LINE_COUNT + 1
        log_lines_capture  = []
        lines = []
        with open(self.log_path, "r", encoding="utf-8") as f:
            while len(log_lines_capture) <= LAST_LINE_COUNT:
                try:
                    f.seek(-POSITION, os.SEEK_END) # Move to the last line
                except (IOError, OSError):
                    f.seek(os.SEEK_SET) # Start of file
                    break
                finally:
                    log_lines_capture = list(f) # Read all lines from the current position
                POSITION *= 2 # Double the position to read more lines
        lines: list = log_lines_capture[-LAST_LINE_COUNT:] # Get the last 3 lines
        for line in lines:
            if self.validate_log_line(line):
                self.logger.success("Log file format is valid!")
                return True
        self.logger.debug("Testing log format")
        return False

    @wait(timeout_seconds=60)
    def log_file_exists(self) -> bool:
        """Try for 60 seconds to check if the log file exists."""
        self.logger.debug(f"Checking if log file {self.log_path} exists.")
        if not os.path.exists(self.log_path):
            self.logger.warning(f"Log file {self.log_path} does not exist.")
            return False
        self.logger.info(f"Log file {self.log_path} exists.")
        self.current_log_inode: int = os.stat(self.log_path).st_ino
        return True

    @wait(timeout_seconds=60)
    def geoip_file_exists(self) -> bool:
        """Try for 60 seconds to check if the GeoIP file exists."""
        self.logger.debug(f"Checking if GeoIP file {self.geoip_path} exists.")
        if not os.path.exists(self.geoip_path):
            self.logger.warning(f"GeoIP file {self.geoip_path} does not exist.")
            return False
        self.logger.info(f"GeoIP file {self.geoip_path} exists.")
        return True
    
    def tail_logs(self, skip_validation: bool = False) -> None:
        """Continiously tail the log file and parse the logs.
        
        If the log file has been rotated, reopen the file and continue tailing.
        
        Writes the geo data to InfluxDB and optionally the log data.
        """
        
        if not skip_validation:
            self.logger.debug("Trying to validate the log file format.")
            if not self.validate_log_format():
                self.send_logs = False
                self.logger.warning("Log file format is invalid. Only sending geo data to Influx.")

        self.logger.debug("Opening log file.")
        with open(self.log_path, "r", encoding="utf-8") as file:
            stat_results: os.stat_result = os.stat(self.log_path)
            st_size: int = stat_results.st_size
            file.seek(st_size) # Move to the end of the file
            self.logger.info("Tailing log file.")
            while True:
                if self.is_rotated(stat_results):
                    return self.tail_logs(skip_validation=True) # Reopen the file and continue tailing
                where = file.tell() # Get the current position in the file
                line = file.readline() # Read the next line
                if not line: # If the line is empty, wait for 1 second
                    time.sleep(1)
                    file.seek(where) # Move to the current position
                    continue
                matched: re.Match[str] | None = self.validate_log_line(line)
                if not matched:
                    self.logger.warning('Failed to match regex that previously matched!? Skipping this line!\n'
                                    'If you think the regex should have mathed the line, please share the log line below on https://discord.gg/HSPa4cz or Github: https://github.com/gilbN/geoip2influx\n' 
                                    f'Line: "{line}"')
                    continue
                ip: str = matched.group(1)
                geo_metrics: list[dict] = self.create_geo_metrics(ip)
                self.client.write_to_influx(geo_metrics)
                
                if self.send_logs:
                    log_metrics: list[dict] = self.create_log_metrics(matched, ip)
                    self.client.write_to_influx(log_metrics)
                self.parsed_lines += 1

    def run(self) -> None:
        """Tail the log file and write the data to InfluxDB."""
        while all([self.log_file_exists(), self.geoip_file_exists()]):
            self.tail_logs()
    
    def is_rotated(self, stat_result:os.stat_result) -> bool:
        """Check if log file has been rotated/truncated.
        
        Update the current inode if it has changed.
        """
        new_stat_results: os.stat_result = os.stat(self.log_path)
        new_st_size: int = new_stat_results.st_size
        new_inode = new_stat_results.st_ino
        if stat_result.st_size > new_st_size:
            self.logger.info("Log file has been truncated/rotated.")
            return True
        if new_inode != self.current_log_inode:
            self.logger.info("Log file inode %s has changed. New inode is %s.", self.current_log_inode, new_inode)
            self.current_log_inode = new_inode
            return True
        return False
    
    def get_ip_type(self, ip:str) -> str:
        """Get the IP type of the given IP address."""
        if not isinstance(ip, str):
            self.logger.error("IP address must be a string.")
            return ""
        try:
            ip_type = IP(ip).iptype()
            return ip_type
        except ValueError:
            self.logger.error("Invalid IP address %s.", ip)
            return ""
    
    def create_geo_metrics(self, ip:str) -> list[dict]:
        """Create the geo metrics for the given IP address.

        Args:
            ip (str): The IP address to create the metrics for.

        Returns:
            list[dict]: A list of geo metrics for the given IP address or an empty list if no data was found.
        """
        if not isinstance(ip, str):
            self.logger.error("IP address must be a string.")
            return []

        geo_metrics: list[dict] = []
        geohash_fields: dict = {}
        geohash_tags: dict = {}
        
        if self.get_ip_type(ip) not in MONITORED_IP_TYPES:
            self.logger.debug("IP %s is not a monitored IP type.", ip)
            return []
        
        ip_data: City = self.geoip_reader.city(ip)
        if not ip_data:
            self.logger.debug("No data found for IP %s.", ip)
            return []
        geohash = encode(ip_data.location.latitude, ip_data.location.longitude)
        geohash_fields["count"] = 1
        geohash_tags["geohash"] = geohash
        geohash_tags['ip'] = ip
        geohash_tags['host'] = self.hostname
        geohash_tags['country_code'] = ip_data.country.iso_code
        geohash_tags['country_name'] = ip_data.country.name
        geohash_tags['state'] = ip_data.subdivisions.most_specific.name or "-"
        geohash_tags['state_code'] = ip_data.subdivisions.most_specific.iso_code or "-"
        geohash_tags['city'] = ip_data.city.name or "-"
        geohash_tags['postal_code'] = ip_data.postal.code or "-"
        geohash_tags['latitude'] = ip_data.location.latitude or "-"
        geohash_tags['longitude'] = ip_data.location.longitude or "-" 
        geo_metrics.append(
            {
                "tags": geohash_tags, 
                "fields": geohash_fields,
                "measurement": self.geo_measurement
            })
        self.logger.debug("GeoIP metrics: %s", geo_metrics)
        return geo_metrics
   
    def create_log_metrics(self, log_data:re.Match[str], ip:str) -> list[dict]:
        """Create the log metrics for the given log data.

        Args:
            log_data (re.Match[str]): The log data to create the metrics for.

        Returns:
            list[dict]: A list of log metrics for the given log data or an empty list if no data was found.
        """
        log_metrics: list[dict] = []
        log_data_tags: dict = {}
        log_data_fields: dict = {}
        
        if not log_data:
            self.logger.error("Log data must be a valid log data.")
            return []
        
        if self.get_ip_type(ip) not in MONITORED_IP_TYPES:
            self.logger.debug("IP %s is not a monitored IP type.", ip)
            return []
        ip_data: City = self.geoip_reader.city(ip)
        if not ip_data:
            self.logger.debug("No data found for IP %s.", ip)
            return []
        
        datadict: dict = log_data.groupdict()

        log_data_fields['count'] = 1
        log_data_fields['bytes_sent'] = int(datadict['bytes_sent'])
        log_data_fields['request_time'] = float(datadict['request_time'])
        
        try:
            log_data_fields['connect_time'] = float(datadict['connect_time']) if datadict['connect_time'] != '-' else 0.0
        except ValueError:
            log_data_fields['connect_time'] = str(datadict['connect_time'])
        log_data_tags['ip'] = datadict['ipaddress']
        log_data_tags['datetime'] = datetime.strptime(datadict['dateandtime'], '%d/%b/%Y:%H:%M:%S %z')
        log_data_tags['remote_user'] = datadict['remote_user']
        log_data_tags['method'] = datadict['method']
        log_data_tags['referrer'] = datadict['referrer']
        log_data_tags['host'] = datadict['host']
        log_data_tags['http_version'] = datadict['http_version']
        log_data_tags['status_code'] = datadict['status_code']
        log_data_tags['bytes_sent'] = datadict['bytes_sent']
        log_data_tags['url'] = datadict['url']
        log_data_tags['user_agent'] = datadict['user_agent']
        log_data_tags['request_time'] = datadict['request_time']
        log_data_tags['connect_time'] = datadict['connect_time']
        log_data_tags['city'] = datadict['city']
        log_data_tags['country_code'] = datadict['country_code']
        log_data_tags['country_name'] = ip_data.country.name
        log_metrics.append(
            {
                "tags": log_data_tags,
                "fields": log_data_fields,
                "measurement": self.log_measurement
            })
        self.logger.debug("NGINX log metrics: %s", log_metrics)
        return log_metrics
