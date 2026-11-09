"""Test data used by several test modules."""

from pathlib import Path

from log_analyzer.models import LogRecord

# Real logs from Squid 6.13, Apache 2.4 and nginx 1.31, recorded in a Docker lab.
FIXTURES = Path(__file__).parent / "fixtures"

# Three requests, two from 10.0.0.1 and one from 10.0.0.2, 500 bytes in total.
LINES = [
    "1157689324.156   1372 10.0.0.1 TCP_MISS/200 399 GET http://a.com/ - DIRECT/1.2.3.4 text/html",
    "1157689324.900    100 10.0.0.2 TCP_MISS/200 100 GET http://b.com/ - DIRECT/1.2.3.4 text/html",
    "1157689325.500    100 10.0.0.1 TCP_MISS/200 1 GET http://c.com/ - DIRECT/1.2.3.4 text/html",
]


def record(
    ip: str = "10.0.0.1", timestamp: float = 0.0, response_size: int | None = 0
) -> LogRecord:
    """A LogRecord with only the fields that tests care about set."""
    return LogRecord(
        timestamp=timestamp,
        elapsed_ms=0,
        client_ip=ip,
        result_code="TCP_MISS/200",
        response_size=response_size,
        method="GET",
        url="http://example.com/",
        user="-",
        hierarchy="DIRECT/1.2.3.4",
        content_type="text/html",
    )
