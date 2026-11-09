import gzip
import io
import logging
import re
from pathlib import Path

import pytest

from log_analyzer.errors import InputError
from log_analyzer.models import LogRecord
from log_analyzer.parsers.squid import parse_line
from log_analyzer.reader import (
    MAX_LINE_BYTES,
    MAX_TIMESTAMP,
    ReadStats,
    read_records,
    read_stream,
)
from samples import record


def squid_line(ip: str = "10.0.0.1", url: str = "http://example.com/") -> str:
    return f"1157689324.156   1372 {ip} TCP_MISS/200 399 GET {url} - DIRECT/1.2.3.4 text/html"


def read_all(path: Path, max_line_bytes: int = MAX_LINE_BYTES) -> tuple[list[LogRecord], ReadStats]:
    stats = ReadStats()
    records = list(read_records(path, parse_line, stats, max_line_bytes))
    return records, stats


def test_reads_plain_file(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text(f"{squid_line('10.0.0.1')}\n{squid_line('10.0.0.2')}\n")

    records, stats = read_all(path)

    assert [r.client_ip for r in records] == ["10.0.0.1", "10.0.0.2"]
    assert stats == ReadStats(lines=2, records=2)


def test_detects_gzip_by_content_not_name(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(
        gzip.compress(f"{squid_line('10.0.0.1')}\n{squid_line('10.0.0.2')}\n".encode())
    )

    records, stats = read_all(path)

    assert [r.client_ip for r in records] == ["10.0.0.1", "10.0.0.2"]
    assert stats == ReadStats(lines=2, records=2)


def test_plain_text_named_gz_is_read_as_text(tmp_path: Path) -> None:
    path = tmp_path / "access.log.gz"
    path.write_text(f"{squid_line()}\n")

    records, _ = read_all(path)

    assert len(records) == 1


def test_invalid_utf8_is_replaced(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_bytes(squid_line(url="http://example.com/caf\xe9").encode("latin-1") + b"\n")

    records, _ = read_all(path)

    assert records[0].url == "http://example.com/caf\ufffd"


def test_invalid_utf8_in_gzip_is_replaced(tmp_path: Path) -> None:
    path = tmp_path / "access.log.gz"
    line = squid_line(url="http://example.com/caf\xe9").encode("latin-1") + b"\n"
    path.write_bytes(gzip.compress(line))

    records, _ = read_all(path)

    assert records[0].url == "http://example.com/caf\ufffd"


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


def test_skips_overlong_line_and_continues(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "access.log"
    huge = squid_line(url="http://example.com/" + "a" * 1000)
    path.write_text(f"{squid_line('10.0.0.1')}\n{huge}\n{squid_line('10.0.0.2')}\n")

    with caplog.at_level(logging.DEBUG, logger="log_analyzer"):
        records, stats = read_all(path, max_line_bytes=200)

    assert [r.client_ip for r in records] == ["10.0.0.1", "10.0.0.2"]
    assert stats == ReadStats(lines=3, records=2, skipped=1)
    assert f"{path}:2: line longer than 200 bytes" in caplog.messages


def test_line_at_exact_limit_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    line = f"{squid_line()}\n".encode()
    path.write_bytes(line)

    records, _ = read_all(path, max_line_bytes=len(line))

    assert len(records) == 1


def test_overlong_last_line_without_newline(tmp_path: Path) -> None:
    path = tmp_path / "access.log"
    path.write_text(f"{squid_line()}\n" + "a" * 1000)

    records, stats = read_all(path, max_line_bytes=200)

    assert len(records) == 1
    assert stats == ReadStats(lines=2, records=1, skipped=1)


def test_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "nope.log"

    with pytest.raises(InputError, match=re.escape(str(path))):
        read_all(path)


def test_directory(tmp_path: Path) -> None:
    with pytest.raises(InputError, match=re.escape(str(tmp_path))):
        read_all(tmp_path)


def test_truncated_gzip(tmp_path: Path) -> None:
    path = tmp_path / "access.log.gz"
    data = gzip.compress(f"{squid_line()}\n".encode() * 1000)
    path.write_bytes(data[: len(data) // 2])

    with pytest.raises(InputError, match=re.escape(str(path))):
        read_all(path)


def test_corrupt_gzip_header(tmp_path: Path) -> None:
    path = tmp_path / "access.log.gz"
    path.write_bytes(b"\x1f\x8b" + b"not really gzip")

    with pytest.raises(InputError, match=re.escape(str(path))):
        read_all(path)


def test_corrupt_gzip_data(tmp_path: Path) -> None:
    path = tmp_path / "access.log.gz"
    data = bytearray(gzip.compress(f"{squid_line()}\n".encode() * 1000))
    data[30:60] = b"\xff" * 30
    path.write_bytes(data)

    with pytest.raises(InputError, match=re.escape(str(path))):
        read_all(path)


def test_skips_timestamps_outside_1970_to_9999_for_any_parser(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # a stand-in parser: each line is just a timestamp
    path = tmp_path / "times.log"
    path.write_text(f"0\n1157689324.5\n{MAX_TIMESTAMP}\n1e20\n-1\n")
    stats = ReadStats()

    with caplog.at_level(logging.DEBUG, logger="log_analyzer"):
        records = list(read_records(path, lambda line: record(timestamp=float(line)), stats))

    assert [r.timestamp for r in records] == [0, 1157689324.5, MAX_TIMESTAMP]
    assert stats == ReadStats(lines=5, records=3, skipped=2)
    assert f"{path}:4: timestamp 1e+20 out of range" in caplog.messages


def stream_of(data: bytes) -> io.BufferedReader:
    # like sys.stdin.buffer: buffered, and not seekable once wrapped around a pipe
    return io.BufferedReader(io.BytesIO(data))


def test_reads_stream(caplog: pytest.LogCaptureFixture) -> None:
    stream = stream_of(f"{squid_line('10.0.0.1')}\ngarbage\n".encode())
    stats = ReadStats()

    with caplog.at_level(logging.WARNING, logger="log_analyzer"):
        records = list(read_stream(stream, "<stdin>", parse_line, stats))

    assert [r.client_ip for r in records] == ["10.0.0.1"]
    assert stats == ReadStats(lines=2, records=1, skipped=1)
    assert caplog.messages == ["<stdin>: skipped 1 of 2 lines"]


def test_reads_gzip_stream() -> None:
    stream = stream_of(gzip.compress(f"{squid_line()}\n".encode()))

    assert len(list(read_stream(stream, "<stdin>", parse_line, ReadStats()))) == 1


def test_leaves_stream_open() -> None:
    stream = stream_of(f"{squid_line()}\n".encode())

    list(read_stream(stream, "<stdin>", parse_line, ReadStats()))

    assert not stream.closed


def test_corrupt_gzip_stream() -> None:
    stream = stream_of(b"\x1f\x8bnot really gzip")

    with pytest.raises(InputError, match="<stdin>"):
        list(read_stream(stream, "<stdin>", parse_line, ReadStats()))
