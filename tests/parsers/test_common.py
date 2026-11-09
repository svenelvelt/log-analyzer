from datetime import UTC, datetime
from pathlib import Path

import pytest

from log_analyzer.errors import ParseError
from log_analyzer.parsers.common import parse_line

# Real logs from Squid 6.13 (logformat common/combined), nginx 1.31 and Apache 2.4.
FIXTURES = Path(__file__).parent.parent / "fixtures"
FILES = [
    "squid-6.13-common.log",
    "squid-6.13-combined.log",
    "nginx-1.31-combined.log",
    "apache-2.4-common.log",
]
LOGGED_AT = datetime(2026, 11, 9, 14, 9, 50, tzinfo=UTC).timestamp()


def lines(name: str) -> list[str]:
    return (FIXTURES / name).read_text().splitlines()


@pytest.mark.parametrize("name", FILES)
def test_every_real_line_parses(name: str) -> None:
    for line in lines(name):
        parse_line(line)


def test_squid_common() -> None:
    record = parse_line(lines("squid-6.13-common.log")[0])

    assert record.timestamp == LOGGED_AT
    assert record.client_ip == "172.23.0.4"
    assert (record.method, record.url) == ("GET", "http://origin/ok.txt")
    assert record.result_code == "TCP_MISS/200"
    assert record.hierarchy == "HIER_DIRECT"
    assert record.response_size == 313
    assert (record.user, record.elapsed_ms, record.content_type) == ("-", None, "-")


def test_squid_combined_with_unescaped_quotes_in_user_agent() -> None:
    # Squid logs the agent `odd "quoted" agent` without escaping the quotes
    record = parse_line(lines("squid-6.13-combined.log")[2])

    assert (record.url, record.result_code) == ("http://origin/index.html", "TCP_MISS/200")


def test_nginx_combined_with_extra_field() -> None:
    # nginx's default format adds X-Forwarded-For after the user agent
    record = parse_line(lines("nginx-1.31-combined.log")[0])

    assert (record.client_ip, record.url) == ("172.23.0.3", "/ok.txt")
    assert (record.result_code, record.hierarchy) == ("200", "-")
    assert record.response_size == 3


def test_apache_dash_size_means_no_bytes() -> None:
    # Apache's %b writes "-" instead of 0, here for a HEAD request
    record = parse_line(lines("apache-2.4-common.log")[1])

    assert (record.method, record.response_size) == ("HEAD", 0)


def test_time_zone_offset() -> None:
    line = '10.0.0.1 - - [09/Nov/2026:16:09:50 +0200] "GET /a HTTP/1.1" 200 1'

    assert parse_line(line).timestamp == LOGGED_AT


def test_authenticated_user() -> None:
    line = '10.0.0.1 - alice [09/Nov/2026:14:09:50 +0000] "GET /a HTTP/1.1" 200 1'

    assert parse_line(line).user == "alice"


BASE = '10.0.0.1 - - [09/Nov/2026:14:09:50 +0000] "GET /a HTTP/1.1" 200 1'


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        pytest.param("", "not in common log format", id="empty"),
        pytest.param(BASE.replace("[", ""), "not in common log format", id="no-brackets"),
        pytest.param(BASE.replace("200 1", "200 1_000"), "not in common log format", id="size"),
        pytest.param(BASE.replace(" 200 ", " OK "), "not in common log format", id="status"),
        pytest.param(BASE.replace("09/Nov", "31/Feb"), "invalid time", id="bad-date"),
        pytest.param(BASE.replace("Nov", "Foo"), "invalid time", id="bad-month"),
        pytest.param(BASE.replace("+0000", "UTC"), "invalid time", id="bad-zone"),
        # nginx logs "-" for connections that never sent a request
        pytest.param(BASE.replace('"GET /a HTTP/1.1"', '"-"'), "invalid request", id="no-request"),
    ],
)
def test_rejects_malformed_lines(line: str, reason: str) -> None:
    with pytest.raises(ParseError, match=reason):
        parse_line(line)
