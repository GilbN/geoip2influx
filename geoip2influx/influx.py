#!/usr/bin/env python3

import os
import logging
from logging import Logger

from influxdb import InfluxDBClient
from requests.exceptions import ConnectionError
from influxdb.exceptions import InfluxDBServerError, InfluxDBClientError

logger: Logger = logging.getLogger(__name__)

class InfluxClient:
    def __init__(self, **kwargs) -> None:
        """Initialize the InfluxDB client.
        
        If no arguments are provided, the client will attempt to use the following environment variables:
        - INFLUX_HOST
        - INFLUX_HOST_PORT
        - INFLUX_USER
        - INFLUX_PASS
        - INFLUX_DATABASE
        - INFLUX_RETENTION
        - INFLUX_SHARD
        
        Args:
            host (str, optional): The InfluxDB host. Defaults to None.
            port (int, optional): The InfluxDB port. Defaults to None.
            username (str, optional): The InfluxDB username. Defaults to None.
            password (str, optional): The InfluxDB password. Defaults to None.
            database (str, optional): The InfluxDB database. Defaults to None.
            retention (str, optional): The InfluxDB retention policy. Defaults to None.
            shard (str, optional): The InfluxDB shard duration. Defaults to None.
        
        Raises:
            ValueError: If the InfluxDB client is not properly configured.
        """
        self.host = kwargs.pop("host", None) or os.getenv("INFLUX_HOST", "localhost")
        self.port = kwargs.pop("port", None) or os.getenv("INFLUX_HOST_PORT", 8086)
        self.username = kwargs.pop("username", None) or os.getenv("INFLUX_USER", "root")
        self.password = kwargs.pop("password", None) or os.getenv("INFLUX_PASS", "root")
        self.database = kwargs.pop("database", None) or os.getenv("INFLUX_DATABASE", "geoip2influx")
        self.retention = kwargs.pop("retention", None) or os.getenv("INFLUX_RETENTION", "7d")
        self.shard = kwargs.pop("shard", None) or os.getenv("INFLUX_SHARD", "1d")
        self.version: str|None = None
        self.retention_policy = f"{self.database} {self.retention}-{self.shard}"
        
        self.logger = logging.getLogger("InfluxClient")
        self.logger.debug("InfluxDB host: %s", self.host)
        self.logger.debug("InfluxDB port: %s", self.port)
        self.logger.debug("InfluxDB username: %s", self.username)
        self.logger.debug("InfluxDB password: %s", self.password)
        self.logger.debug("InfluxDB database: %s", self.database)
    
        self.influx: InfluxDBClient | None = self.create_influx_client(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            database=self.database,
            **kwargs
        )
        
        self.setup() # Setup the database and retention policy

    def setup(self):
        """Setup the database and retention policy, and validate the setup."""
        self.test_connection()
        self.create_database()
        self.create_retention_policy()
        self.validate()
        self.logger.success("InfluxDB client setup complete.")
        
    def create_influx_client(self, **kwargs) -> InfluxDBClient | None:
        try:
            return InfluxDBClient(**kwargs)
        except Exception:
            self.logger.exception("Error creating InfluxDB client.")
            
    def test_connection(self):
        try:
            self.version: str = self.influx.ping()
            self.logger.debug("InfluxDB version: %s", self.version)
        except Exception:
            self.logger.exception("Error testing connection to InfluxDB. Please check your url/hostname.")
            raise
    
    def write_to_influx(self, data: list[dict]) -> None:
        """Write the data to InfluxDB.

        Args:
            data (list[dict]): The data to write to InfluxDB.
        """
        
        try:
            if not data:
                self.logger.debug("No data to write to InfluxDB.")
                return
            if self.influx.write_points(data):
                measurement = data[0]["measurement"]
                self.logger.debug("'%s' data written to InfluxDB.", measurement)
                return
            self.logger.error("Error writing data to InfluxDB!")
        except (InfluxDBServerError, InfluxDBClientError, ConnectionError):
            self.logger.exception("Error writing data to InfluxDB! Check your database!")
    
    def create_database(self) -> None:
        """Create the database if it does not exist."""
        try:
            if self.check_database():
                return
            self.logger.info("Creating database.")
            self.influx.create_database(self.database)
            if self.check_database():
                self.logger.info("Database %s created.", self.database)
        except Exception:
            self.logger.exception("Error creating database %s.", self.database)
    
    def check_database(self) -> bool:
        """Check if the database exists."""
        try:
            databases: list[dict] = self.influx.get_list_database()
            if self.database in [db["name"] for db in databases]:
                self.logger.debug("Database %s exists.", self.database)
                return True
            self.logger.debug("Database %s does not exist.", self.database)
            return False
        except Exception:
            self.logger.exception("Error checking database %s.", self.database)
            return False
    
    def create_retention_policy(self) -> None:
        """Create the retention policy if it does not exist."""
        
        if self.check_retention_policy():
            return
        self.logger.info("Creating retention policy %s.", self.retention_policy)
        self.influx.create_retention_policy(
            name=self.retention_policy,
            duration=self.retention,
            replication=1,
            database=self.database,
            default=True,
            shard_duration=self.shard
        )
    
    def check_retention_policy(self) -> bool:
        policies: list[dict] = self.influx.get_list_retention_policies(self.database)
        retention_policies: list = [policy['name'] for policy in policies]
        if self.retention_policy in retention_policies:
            self.logger.debug(f"Retention policy {self.retention} exists.")
            return True
        self.logger.debug(f"Retention policy {self.retention} does not exist.")
        return False
    
    
    def validate(self) -> None:
        """Validate that everything is properly configured.
        
        Raises:
            ValueError: If the InfluxDB client is not properly configured.
            ValueError: If the InfluxDB database does not exist.
            ValueError: If the InfluxDB retention policy does not exist.
        """
        if not self.influx:
            raise ValueError("InfluxDB client is not properly configured.")
        if not self.check_database():
            raise ValueError("InfluxDB database does not exist.")
        if not self.check_retention_policy():
            raise ValueError("InfluxDB retention policy does not exist.")
        self.logger.info("InfluxDB client validated.")