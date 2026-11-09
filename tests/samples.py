"""Test data used by several test modules."""

from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from typing import Any

from log_analyzer.analyzers import Analyzer
from log_analyzer.models import LogRecord

# Real logs from Squid 6.13, Apache 2.4 and nginx 1.31, recorded in a Docker lab.
FIXTURES = Path(__file__).parent / "fixtures"

# Three requests, two from 10.0.0.1 and one from 10.0.0.2, 500 bytes in total.
LINES = [
    "1157689324.156   1372 10.0.0.1 TCP_MISS/200 399 GET http://a.com/ - DIRECT/1.2.3.4 text/html",
    "1157689324.900    100 10.0.0.2 TCP_MISS/200 100 GET http://b.com/ - DIRECT/1.2.3.4 text/html",
    "1157689325.500    100 10.0.0.1 TCP_MISS/200 1 GET http://c.com/ - DIRECT/1.2.3.4 text/html",
]


_DEFAULT = LogRecord(
    timestamp=0.0,
    elapsed_ms=0,
    client_ip="10.0.0.1",
    result_code="TCP_MISS/200",
    response_size=0,
    method="GET",
    url="http://example.com/",
    user="-",
    hierarchy="DIRECT/1.2.3.4",
    content_type="text/html",
)


def record(**fields: Any) -> LogRecord:
    """A LogRecord with defaults, overriding any field by name, e.g. record(client_ip="::1")."""
    return replace(_DEFAULT, **fields)


def records(field: str, values: Iterable[Any]) -> list[LogRecord]:
    """One record per value, each with `field` set to it."""
    return [record(**{field: value}) for value in values]


def feed(analyzer: Analyzer, records: Iterable[LogRecord]) -> object:
    """Run `analyzer` over `records` and return its result."""
    for r in records:
        analyzer.update(r)
    return analyzer.result()
