import logging
from pathlib import Path

import pytest

from log_analyzer.models import LogRecord
from log_analyzer.parsers.squid import parse_line
from log_analyzer.reader import ReadStats, read_records


def squid_line(ip: str = "10.0.0.1", url: str = "http://example.com/") -> str:
    return f"1157689324.156   1372 {ip} TCP_MISS/200 399 GET {url} - DIRECT/1.2.3.4 text/html"


def read_all(path: Path) -> tuple[list[LogRecord], ReadStats]:
    stats = ReadStats()
    records = list(read_records(path, parse_line, stats))
    return records, stats


def test_reads_plain_file(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text(f"{squid_line('10.0.0.1')}\n{squid_line('10.0.0.2')}\n")

    records, stats = read_all(path)

    assert [r.client_ip for r in records] == ["10.0.0.1", "10.0.0.2"]
    assert stats == ReadStats(lines=2, records=2)


def test_last_line_without_newline(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text(f"{squid_line('10.0.0.1')}\n{squid_line('10.0.0.2')}")

    records, _ = read_all(path)

    assert len(records) == 2


def test_crlf_line_endings(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(f"{squid_line()}\r\n".encode())

    records, _ = read_all(path)

    assert records[0].content_type == "text/html"


def test_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(b"")

    records, stats = read_all(path)

    assert records == []
    assert stats == ReadStats()


def test_skips_and_counts_malformed_lines(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text(f"\n{squid_line()}\ngarbage\n{squid_line()}\n")

    records, stats = read_all(path)

    assert len(records) == 2
    assert stats == ReadStats(lines=4, records=2, skipped=2)


def test_logs_details_at_debug_and_summary_at_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "access.log"
    path.write_text(f"{squid_line()}\ngarbage\n")

    with caplog.at_level(logging.DEBUG, logger="log_analyzer"):
        read_all(path)

    debug = [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert debug == [f"{path}:2: expected 10 fields, got 1"]
    assert warnings == [f"{path}: skipped 1 of 2 lines"]


def test_no_warning_when_nothing_skipped(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "access.log"
    path.write_text(f"{squid_line()}\n")

    with caplog.at_level(logging.WARNING, logger="log_analyzer"):
        read_all(path)

    assert caplog.records == []
