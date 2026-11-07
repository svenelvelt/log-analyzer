from collections.abc import Iterable

import pytest

from log_analyzer.analyzers import Analyzer, EventsPerSecond, LeastFrequentIp, MostFrequentIp
from log_analyzer.models import LogRecord


def record(ip: str = "10.0.0.1", timestamp: float = 0.0) -> LogRecord:
    return LogRecord(
        timestamp=timestamp,
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


def run_at(analyzer: Analyzer, timestamps: Iterable[float]) -> object:
    for ts in timestamps:
        analyzer.update(record(timestamp=ts))
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


def test_lfip_name() -> None:
    assert LeastFrequentIp().name == "lfip"


def test_lfip() -> None:
    ips = ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.3"]
    assert run(LeastFrequentIp(), ips) == {"ips": ["10.0.0.2"], "count": 1}


def test_lfip_returns_all_ties_sorted_by_address() -> None:
    ips = ["10.0.0.10", "10.0.0.2", "10.0.0.1", "10.0.0.1"]
    assert run(LeastFrequentIp(), ips) == {"ips": ["10.0.0.2", "10.0.0.10"], "count": 1}


def test_lfip_no_records() -> None:
    assert run(LeastFrequentIp(), []) == {"ips": [], "count": 0}


def test_eps_name() -> None:
    assert EventsPerSecond().name == "eps"


def test_eps() -> None:
    # seconds 100 to 104 inclusive = 5 s, 4 events; second 100 has 2
    result = run_at(EventsPerSecond(), [100.0, 100.5, 101.2, 104.9])
    assert result == {"average": pytest.approx(0.8), "peak": 2}


def test_eps_single_event() -> None:
    assert run_at(EventsPerSecond(), [100.3]) == {"average": 1.0, "peak": 1}


def test_eps_all_in_one_second() -> None:
    assert run_at(EventsPerSecond(), [100.1, 100.2, 100.9]) == {"average": 3.0, "peak": 3}


def test_eps_average_uses_earliest_and_latest_not_first_and_last_seen() -> None:
    # rotated logs passed newest first: seconds 100 to 201 = 102 s
    result = run_at(EventsPerSecond(), [200.0, 201.0, 100.0])
    assert result == {"average": pytest.approx(3 / 102), "peak": 1}


def test_eps_peak_assumes_time_order() -> None:
    # Squid writes lines in time order. If a second's events are split up,
    # each run is counted separately, so the peak can only come out too low.
    result = run_at(EventsPerSecond(), [5.0, 5.1, 6.0, 5.2])
    assert result == {"average": pytest.approx(2.0), "peak": 2}


def test_eps_no_records() -> None:
    assert run_at(EventsPerSecond(), []) == {"average": 0.0, "peak": 0}
