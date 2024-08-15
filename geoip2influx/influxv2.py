#!/usr/bin/env python3

import os
import logging
from logging import Logger

from influxdb_client import InfluxDBClient, WriteApi, Point, BucketRetentionRules
from influxdb_client.client.bucket_api import BucketsApi
from influxdb_client.client.organizations_api import OrganizationsApi
from requests.exceptions import ConnectionError
from influxdb_client.client.exceptions import InfluxDBError
from influxdb_client.client.write_api import SYNCHRONOUS, WriteOptions

from .influx_base import InfluxBase

logger: Logger = logging.getLogger(__name__)

class BatchingCallback:

    def success(self, conf: tuple[str, str, str], data: str) -> None:
        logger.debug("Written batch: %s, data: %s", conf, data)

    def error(self, conf: tuple[str, str, str], data: str, exception: InfluxDBError) -> None:
        logger.error("Cannot write batch: %s, data: %s due: %s", conf, data, exception)

    def retry(self, conf: tuple[str, str, str], data: str, exception: InfluxDBError) -> None:
        logger.warning("Retryable error occured for batch: %s, data: %s retry: %s", conf, data, exception)

class InfluxClient(InfluxBase):
    def __init__(self, auto_init: bool = True) -> None:
        """Initialize the InfluxDBClient.
        
        Supported InfluxDBClient environment properties:
            - INFLUXDB_V2_URL
            - INFLUXDB_V2_ORG
            - INFLUXDB_V2_TOKEN
            - INFLUXDB_V2_TIMEOUT
            - INFLUXDB_V2_VERIFY_SSL
            - INFLUXDB_V2_SSL_CA_CERT
            - INFLUXDB_V2_CERT_FILE
            - INFLUXDB_V2_CERT_KEY_FILE
            - INFLUXDB_V2_CERT_KEY_PASSWORD
            - INFLUXDB_V2_CONNECTION_POOL_MAXSIZE
            - INFLUXDB_V2_AUTH_BASIC
            - INFLUXDB_V2_PROFILERS
            
        Used by this class:
            - INFLUXDB_V2_BUCKET
            - INFLUX_V2_RETENTION
            - INFLUXDB_V2_DEBUG
            - INFLUXDB_V2_BATCHING
            - INFLUXDB_V2_BATCH_SIZE
            - INFLUXDB_V2_FLUSH_INTERVAL
        
        Args:
            auto_init (bool, optional): Whether to automatically setup the InfluxDB client. Defaults to True.
        
        Raises:
            ValueError: If the InfluxDB client is not properly configured.
        """
        
        self.bucket: str = os.getenv("INFLUXDB_V2_BUCKET", "geoip2influx")
        self.retention: str = int(os.getenv("INFLUX_V2_RETENTION", "604800"))
        self.debug: bool = os.getenv("INFLUXDB_V2_DEBUG", "false").lower() == "true"
        self.org: str = os.getenv("INFLUXDB_V2_ORG", "geoip2influx")
        self.version: str|None = None
        self._setup_complete: bool = False
        batching: bool = os.getenv("INFLUXDB_V2_BATCHING", "false").lower() == "true"
        batch_size: int = int(os.getenv("INFLUXDB_V2_BATCH_SIZE", "10"))
        flush_interval: int = int(os.getenv("INFLUXDB_V2_FLUSH_INTERVAL", "15000"))
        
        self.influx: InfluxDBClient | None = self.create_influx_client(debug=self.debug)
        
        self.logger: Logger = logging.getLogger("InfluxClient")
        self.logger.debug("InfluxDB url: %s", self.influx.url)
        self.logger.debug("InfluxDB org: %s", self.org)
        self.logger.debug("InfluxDB token: %s", self.influx.token)
        self.logger.debug("InfluxDB bucket: %s", self.bucket)
        self.logger.debug("InfluxDB bucket retention seconds: %s", self.retention)
        self.logger.debug("InfluxDB batching enabled: %s", batching)

        if batching:
            self.logger.debug("InfluxDB batch size: %s", batch_size)
            self.logger.debug("InfluxDB flush interval: %s", flush_interval)
            callback = BatchingCallback()
            write_options: WriteOptions = WriteOptions(batch_size=batch_size, flush_interval=flush_interval)
            self.write_api: WriteApi = self.influx.write_api(
                write_options=write_options,
                success_callback=callback.success,
                error_callback=callback.error,
                retry_callback=callback.retry
                )
        else:
            write_options = SYNCHRONOUS
            self.write_api: WriteApi = self.influx.write_api(write_options=write_options)
        self.bucket_api: BucketsApi = self.influx.buckets_api()
        self.org_api: OrganizationsApi = self.influx.organizations_api()

        if auto_init:
            self.setup()

    @property
    def setup_complete(self) -> bool:
        return self._setup_complete

    @setup_complete.setter
    def setup_complete(self, value: bool) -> None:
        self._setup_complete = value

    def setup(self) -> None:
        """Setup the bucket and retention policy, and validate the setup."""
        self.test_connection()
        self.create_org()
        self.create_bucket()
        self.logger.success("InfluxDB client setup complete.")
        self.setup_complete = True

    def create_influx_client(self, debug = True, enable_gzip:bool = False, **kwargs) -> InfluxDBClient | None:
        try:
            return InfluxDBClient.from_env_properties(debug, enable_gzip, **kwargs)
        except Exception:
            self.logger.exception("Error creating InfluxDB client.")
            raise

    def test_connection(self) -> None:
        try:
            if not self.influx.ping():
                raise
            self.version: str = self.influx.version()
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
            records: list[Point] = [Point.from_dict(point) for point in data]
            self.write_api.write(self.bucket, self.org, records)
            measurement = data[0]["measurement"]
            self.logger.debug("'%s' data written to InfluxDB.", measurement)
        except (InfluxDBError, ConnectionError):
            self.logger.exception("Error writing data to InfluxDB! Check your database!")
    
    def create_bucket(self) -> None:
        """Create the bucket and retention policy if it does not exist."""
        try:
            if self.bucket_exists():
                return
            self.logger.info("Creating bucket.")
            bucket_description: str = f"Bucket for storing GeoIP data for {self.bucket}"
            bucket_retention = BucketRetentionRules(type="expire",every_seconds=self.retention)
            self.bucket_api.create_bucket(bucket_name=self.bucket, org=self.org, description=bucket_description, retention_rules=bucket_retention)
            if self.bucket_exists():
                self.logger.info("Bucket %s created.", self.bucket)
        except Exception:
            self.logger.exception("Error creating bucket %s.", self.bucket)
            raise
    
    def bucket_exists(self) -> bool:
        """Check if the bucket exists."""
        try:
            buckets = self.bucket_api.find_buckets_iter(org=self.org)
            if buckets and self.bucket in [bucket.name for bucket in buckets]:
                self.logger.debug("Bucket %s exists.", self.bucket)
                return True
            self.logger.debug("Bucket %s does not exist.", self.bucket)
            return False
        except Exception:
            self.logger.exception("Error checking bucket %s.", self.bucket)
            raise
    
    def create_org(self) -> None:
        """Create the organization if it does not exist."""
        if self.org_exists():
            return
        try:
            self.logger.info("Creating organization.")
            self.org_api.create_organization(name=self.org)
            if self.org_exists():
                self.logger.info("Organization %s created.", self.org)
        except Exception:
            self.logger.exception("Error creating organization %s.", self.org)
            raise
        
    def org_exists(self) -> bool:
        """Check if the organization exists."""
        try:
            orgs = self.org_api.find_organizations(org=self.org)
            if orgs and self.org in [org.name for org in orgs]:
                self.logger.debug("Organization %s exists.", self.org)
                return True
            self.logger.debug("Organization %s does not exist.", self.org)
            return False
        except Exception:
            self.logger.exception("Error checking organization %s.", self.org)
            raise
