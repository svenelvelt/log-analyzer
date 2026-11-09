import pytest

from log_analyzer.analyzers import (
    EventsPerSecond,
    LeastFrequentIp,
    MostFrequentIp,
    TotalBytes,
)
from samples import feed, records


def test_mfip_name() -> None:
    assert MostFrequentIp().name == "mfip"


def test_mfip() -> None:
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.2", "10.0.0.3"]
    assert feed(MostFrequentIp(), records("client_ip", ips)) == {"ips": ["10.0.0.2"], "count": 2}


def test_mfip_returns_all_ties_sorted_by_address() -> None:
    ips = ["10.0.0.10", "10.0.0.2", "10.0.0.10", "10.0.0.2", "10.0.0.1"]
    assert feed(MostFrequentIp(), records("client_ip", ips)) == {
        "ips": ["10.0.0.2", "10.0.0.10"],
        "count": 2,
    }


def test_mfip_sorts_ipv4_then_ipv6_then_other() -> None:
    ips = ["proxy.local", "::1", "10.0.0.1"]
    assert feed(MostFrequentIp(), records("client_ip", ips)) == {
        "ips": ["10.0.0.1", "::1", "proxy.local"],
        "count": 1,
    }


def test_mfip_no_records() -> None:
    assert feed(MostFrequentIp(), []) == {"ips": [], "count": 0}


def test_lfip_name() -> None:
    assert LeastFrequentIp().name == "lfip"


def test_lfip() -> None:
    ips = ["10.0.0.1", "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.3"]
    assert feed(LeastFrequentIp(), records("client_ip", ips)) == {"ips": ["10.0.0.2"], "count": 1}


def test_lfip_returns_all_ties_sorted_by_address() -> None:
    ips = ["10.0.0.10", "10.0.0.2", "10.0.0.1", "10.0.0.1"]
    assert feed(LeastFrequentIp(), records("client_ip", ips)) == {
        "ips": ["10.0.0.2", "10.0.0.10"],
        "count": 1,
    }


def test_lfip_no_records() -> None:
    assert feed(LeastFrequentIp(), []) == {"ips": [], "count": 0}


def test_eps_name() -> None:
    assert EventsPerSecond().name == "eps"


def test_eps() -> None:
    # seconds 100 to 104 inclusive = 5 s, 4 events; second 100 has 2
    result = feed(EventsPerSecond(), records("timestamp", [100.0, 100.5, 101.2, 104.9]))
    assert result == {"average": pytest.approx(0.8), "peak": 2}


def test_eps_single_event() -> None:
    assert feed(EventsPerSecond(), records("timestamp", [100.3])) == {"average": 1.0, "peak": 1}


def test_eps_all_in_one_second() -> None:
    assert feed(EventsPerSecond(), records("timestamp", [100.1, 100.2, 100.9])) == {
        "average": 3.0,
        "peak": 3,
    }


def test_eps_average_uses_earliest_and_latest_not_first_and_last_seen() -> None:
    # rotated logs passed newest first: seconds 100 to 201 = 102 s
    result = feed(EventsPerSecond(), records("timestamp", [200.0, 201.0, 100.0]))
    assert result == {"average": pytest.approx(3 / 102), "peak": 1}


def test_eps_peak_assumes_time_order() -> None:
    # Squid writes lines in time order. If a second's events are split up,
    # each run is counted separately, so the peak can only come out too low.
    result = feed(EventsPerSecond(), records("timestamp", [5.0, 5.1, 6.0, 5.2]))
    assert result == {"average": pytest.approx(2.0), "peak": 2}


def test_eps_no_records() -> None:
    assert feed(EventsPerSecond(), records("timestamp", [])) == {"average": 0.0, "peak": 0}


def test_bytes_name() -> None:
    assert TotalBytes().name == "bytes"


def test_bytes() -> None:
    assert feed(TotalBytes(), records("response_size", [399, 0, 19763])) == {
        "total": 20162,
        "unknown": 0,
    }


def test_bytes_counts_unknown_sizes_separately() -> None:
    assert feed(TotalBytes(), records("response_size", [399, None, None])) == {
        "total": 399,
        "unknown": 2,
    }


def test_bytes_no_records() -> None:
    assert feed(TotalBytes(), records("response_size", [])) == {"total": 0, "unknown": 0}
