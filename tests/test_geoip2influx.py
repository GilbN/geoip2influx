import re
import pytest
import datetime

from geoip2.database import Reader
from geoip2influx.constants import ipv4_pattern, ipv6_pattern, Rgx
from geoip2influx import LogParser

VALID_LOG_PATH = "tests/valid_ipv4_log.txt"
INVALID_LOG_PATH = "tests/invalid_logs.txt"
TEST_IPV6 = "2607:f0d0:1002:51::4"

test_geo_metrics: list[dict] = [{'tags': {'geohash': '9ydqy025w0qn', 'ip': '2607:f0d0:1002:51::4', 'host': 'localhost', 'country_code': 'US', 'country_name': 'United States', 'state': '-', 'state_code': '-', 'city': '-', 'postal_code': '-', 'latitude': 37.751, 'longitude': -97.822}, 'fields': {'count': 1}, 'measurement': 'geoip2influx'}]
test_log_metrics: list[dict] = [{'tags': {'ip': '2607:f0d0:1002:51::4', 'datetime': datetime.datetime(2024, 8, 3, 13, 14, 23, tzinfo=datetime.timezone(datetime.timedelta(seconds=7200))), 'remote_user': '-', 'method': 'GET', 'referrer': '/wp-includes/Text/about.php', 'host': ' yourdomain.com ', 'http_version': 'HTTP/2.0', 'status_code': '404', 'bytes_sent': '36', 'url': '-', 'user_agent': '-', 'request_time': '0.002', 'connect_time': '0.000', 'city': 'Hong Kong', 'country_code': 'HK', 'country_name': 'United States'}, 'fields': {'count': 1, 'bytes_sent': 36, 'request_time': 0.002, 'connect_time': 0.0}, 'measurement': 'nginx_access_logs'}]

@pytest.fixture
def load_valid_ipv4_log() -> list[str]:
    """Load the contents of the valid IPv4 log file.""" 
    with open('tests/valid_ipv4_log.txt', "r", encoding="utf-8") as f:
        return f.readlines()

@pytest.fixture
def load_valid_ipv6_log() -> list[str]:
    """Load the contents of the valid IPv6 log file.""" 
    with open('tests/valid_ipv6_log.txt', "r", encoding="utf-8") as f:
        return f.readlines()

@pytest.fixture
def load_invalid_logs() -> list[str]:
    """Load the contents of the invalid log file.""" 
    with open('tests/invalid_logs.txt', "r", encoding="utf-8") as f:
        return f.readlines()

@pytest.fixture
def ipv4_log_pattern() -> re.Pattern[str]:
    """Return the regular expression pattern for an IPv4 log line."""
    return ipv4_pattern()

@pytest.fixture
def ipv6_log_pattern() -> re.Pattern[str]:
    """Return the regular expression pattern for an IPv6 log line."""
    return ipv6_pattern()

@pytest.fixture
def log_parser() -> LogParser:
    """Return an instance of the LogParser class."""
    parser = LogParser(auto_init=False)
    parser.hostname = "localhost"
    parser.geoip_reader = Reader("tests/GeoLite2-City.mmdb")
    return parser

def test_regex_tester_ipv4(load_valid_ipv4_log: list[str], ipv4_log_pattern: re.Pattern[str]) -> None:
    """Test the regex tester for IPv4 log lines."""
    for line in load_valid_ipv4_log:
        assert bool(ipv4_log_pattern.match(line)) is True

def test_regex_tester_ipv6(load_valid_ipv6_log: list[str], ipv6_log_pattern: re.Pattern[str]) -> None:
    """Test the regex tester for IPv6 log lines."""
    for line in load_valid_ipv6_log:
        assert bool(ipv6_log_pattern.match(line)) is True

def test_regex_tester_invalid(load_invalid_logs: list[str], ipv4_log_pattern: re.Pattern[str], ipv6_log_pattern: re.Pattern[str]) -> None:
    """Test the regex tester for invalid log lines."""
    for line in load_invalid_logs:
        assert bool(ipv4_log_pattern.match(line)) is False
        assert bool(ipv6_log_pattern.match(line)) is False

def test_get_ip_type(log_parser: LogParser) -> None:
    """Test the get_ip_type function."""
    private_ip = "10.10.10.1"
    public_ip = "52.53.54.55"
    assert log_parser.get_ip_type(private_ip) == "PRIVATE"
    assert log_parser.get_ip_type(public_ip) == "PUBLIC"

def test_get_ip_type_invalid(log_parser: LogParser) -> None:
    """Test the get_ip_type function with an invalid IP address."""
    invalid_ip = "10.10.10.256"
    assert log_parser.get_ip_type(invalid_ip) == ""
    
def test_create_geo_metrics(log_parser: LogParser) -> None:
    """Test the create_geo_metrics function."""
    assert log_parser.create_geo_metrics(TEST_IPV6) == test_geo_metrics

def test_create_log_metrics(log_parser: LogParser, load_valid_ipv6_log: list[str]):
    """Test the create_log_metrics function."""
    test_line: str = load_valid_ipv6_log[0]
    matched: re.Match[str] | None = log_parser.validate_log_line(test_line)
    log_metrics: list[dict] = log_parser.create_log_metrics(matched, TEST_IPV6)
    assert log_metrics[0]["tags"]["ip"] == TEST_IPV6
    assert log_metrics[0]["tags"]["city"] == "Hong Kong"
    assert log_metrics[0]["tags"]["country_code"] == "HK"
    assert log_metrics[0]["tags"]["status_code"] == "404"
    assert log_metrics[0]["measurement"] == "nginx_access_logs"
    