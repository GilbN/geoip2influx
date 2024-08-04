import re
import pytest

from geoip2influx.constants import ipv4_pattern, ipv6_pattern

VALID_LOG_PATH = "tests/valid_ipv4_log.txt"
INVALID_LOG_PATH = "tests/invalid_logs.txt"

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