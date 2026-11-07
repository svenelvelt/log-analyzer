from collections.abc import Iterable

from log_analyzer.analyzers import Analyzer, MostFrequentIp
from log_analyzer.models import LogRecord


def record(ip: str) -> LogRecord:
    return LogRecord(
        timestamp=0.0,
        elapsed_ms=0,
        client_ip=ip,
        result_code="TCP_MISS/200",
        response_size=0,
        method="GET",
        url="http://example.com/",
        user="-",
        hierarchy="DIRECT/1.2.3.4",
        content_type="text/html",
    )


def run(analyzer: Analyzer, ips: Iterable[str]) -> object:
    for ip in ips:
        analyzer.update(record(ip))
    return analyzer.result()


def test_mfip_name() -> None:
    assert MostFrequentIp().name == "mfip"


def test_mfip() -> None:
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.2", "10.0.0.3"]
    assert run(MostFrequentIp(), ips) == {"ips": ["10.0.0.2"], "count": 2}


def test_mfip_returns_all_ties_sorted_by_address() -> None:
    ips = ["10.0.0.10", "10.0.0.2", "10.0.0.10", "10.0.0.2", "10.0.0.1"]
    assert run(MostFrequentIp(), ips) == {"ips": ["10.0.0.2", "10.0.0.10"], "count": 2}


def test_mfip_sorts_ipv4_then_ipv6_then_other() -> None:
    ips = ["proxy.local", "::1", "10.0.0.1"]
    assert run(MostFrequentIp(), ips) == {"ips": ["10.0.0.1", "::1", "proxy.local"], "count": 1}


def test_mfip_no_records() -> None:
    assert run(MostFrequentIp(), []) == {"ips": [], "count": 0}
