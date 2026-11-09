import pytest

from log_analyzer.analyzers import (
    EventsPerSecond,
    LeastFrequentIp,
    MostFrequentIp,
    TotalBytes,
    parameter,
)
from samples import feed, records


def ips(counts: dict[str, int]) -> list[str]:
    """One client IP per request, e.g. {"a": 2, "b": 1} -> ["a", "a", "b"]."""
    return [ip for ip, n in counts.items() for _ in range(n)]


def ranking(*rows: tuple[str, int], n: int = 1) -> dict[str, object]:
    return {"n": n, "clients": [{"ip": ip, "count": count} for ip, count in rows]}


SAMPLE_IPS = ips({"10.0.0.9": 1, "10.0.0.10": 3, "10.0.0.2": 1, "10.0.0.3": 2})


def test_names() -> None:
    assert (MostFrequentIp.name, LeastFrequentIp.name) == ("mfip", "lfip")


def test_mfip() -> None:
    assert feed(MostFrequentIp(), records("client_ip", SAMPLE_IPS)) == ranking(("10.0.0.10", 3))


def test_mfip_n() -> None:
    assert feed(MostFrequentIp(2), records("client_ip", SAMPLE_IPS)) == ranking(
        ("10.0.0.10", 3), ("10.0.0.3", 2), n=2
    )


def test_lfip_rarest_first_ties_sorted_by_address() -> None:
    # 10.0.0.2 and 10.0.0.9 tie for the fewest; 10.0.0.2 sorts first by address
    assert feed(LeastFrequentIp(), records("client_ip", SAMPLE_IPS)) == ranking(
        ("10.0.0.2", 1), ("10.0.0.9", 1)
    )


def test_lfip_n() -> None:
    assert feed(LeastFrequentIp(3), records("client_ip", SAMPLE_IPS)) == ranking(
        ("10.0.0.2", 1), ("10.0.0.9", 1), ("10.0.0.3", 2), n=3
    )


def test_ties_at_the_cutoff_are_included() -> None:
    sample = ips({"10.0.0.1": 3, "10.0.0.2": 2, "10.0.0.3": 2, "10.0.0.4": 1})

    assert feed(MostFrequentIp(2), records("client_ip", sample)) == ranking(
        ("10.0.0.1", 3), ("10.0.0.2", 2), ("10.0.0.3", 2), n=2
    )


def test_sorts_ipv4_then_ipv6_then_other() -> None:
    sample = ["proxy.local", "::1", "10.0.0.1"]

    assert feed(MostFrequentIp(), records("client_ip", sample)) == ranking(
        ("10.0.0.1", 1), ("::1", 1), ("proxy.local", 1)
    )


def test_fewer_clients_than_n() -> None:
    assert feed(MostFrequentIp(5), records("client_ip", ["10.0.0.1"])) == ranking(
        ("10.0.0.1", 1), n=5
    )


def test_no_records() -> None:
    assert feed(MostFrequentIp(), []) == ranking()
    assert feed(LeastFrequentIp(), []) == ranking()


def test_n_below_one() -> None:
    with pytest.raises(ValueError, match="n must be at least 1, got 0"):
        LeastFrequentIp(0)


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


def test_an_operation_takes_the_value_its_constructor_accepts() -> None:
    mfip = parameter(MostFrequentIp)

    assert mfip is not None
    assert (mfip.name, mfip.type, mfip.default) == ("n", int, 1)
    assert parameter(TotalBytes) is None
