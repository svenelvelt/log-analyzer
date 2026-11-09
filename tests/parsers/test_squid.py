from pathlib import Path

import pytest

from log_analyzer.errors import ParseError
from log_analyzer.models import LogRecord
from log_analyzer.parsers.squid import parse_line

SAMPLE = (
    "1157689324.156   1372 10.105.21.199 TCP_MISS/200 399 GET "
    "http://www.google-analytics.com/__utm.gif? badeyek DIRECT/66.102.9.147 image/gif"
)


def test_parses_all_ten_fields() -> None:
    assert parse_line(SAMPLE) == LogRecord(
        timestamp=1157689324.156,
        elapsed_ms=1372,
        client_ip="10.105.21.199",
        result_code="TCP_MISS/200",
        response_size=399,
        method="GET",
        url="http://www.google-analytics.com/__utm.gif?",
        user="badeyek",
        hierarchy="DIRECT/66.102.9.147",
        content_type="image/gif",
    )


def test_ignores_surrounding_whitespace_and_newline() -> None:
    assert parse_line(f"  {SAMPLE}  \n") == parse_line(SAMPLE)


def test_keeps_dash_placeholders_verbatim() -> None:
    line = (
        "1157689312.049   5006 10.105.21.199 TCP_MISS/200 19763 CONNECT "
        "login.yahoo.com:443 badeyek DIRECT/209.73.177.115 -"
    )
    assert parse_line(line).content_type == "-"


def test_minus_one_size_means_unknown() -> None:
    # from the sample data
    line = (
        "1335542309     35 127.0.0.1 TCP_MISS/303 -1 GET "
        "http://gadm.geovocab.org/id/1_3214_geometry_1km - NONE/- text/html"
    )
    record = parse_line(line)
    assert record.response_size is None
    assert record.timestamp == 1335542309.0


def test_minus_one_elapsed_means_unknown() -> None:
    assert parse_line(SAMPLE.replace(" 1372 ", " -1 ")).elapsed_ms is None


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        pytest.param("", "expected 10 fields", id="empty"),
        pytest.param("   \n", "expected 10 fields", id="blank"),
        pytest.param(SAMPLE.rsplit(" ", 1)[0], "expected 10 fields", id="too-few-fields"),
        # line 82948 of the sample data, two records on one line
        pytest.param(
            "1157703559.984    221 10.105.41.222 TCP_HIT/200 238266 GET "
            "http://www.vanguardngr.com/images/adverts/vanguard.swf doyedele "
            "NONE/-1335542309 164 127.0.0.1 TCP_MISS/404 291 GET "
            "http://gadm.geovocab.org/robots.txt - NONE/- text/html",
            "expected 10 fields",
            id="two-records-one-line",
        ),
        pytest.param(SAMPLE.replace("1157689324.156", "yesterday"), "timestamp", id="bad-ts"),
        pytest.param(SAMPLE.replace("1157689324.156", "nan"), "timestamp", id="nan-ts"),
        pytest.param(SAMPLE.replace("1157689324.156", "-5.0"), "timestamp", id="negative-ts"),
        pytest.param(
            SAMPLE.replace("1157689324.156", "1_157_689_324.156"), "timestamp", id="underscore-ts"
        ),
        pytest.param(SAMPLE.replace("1157689324.156", "1.157689e9"), "timestamp", id="exponent-ts"),
        pytest.param(
            SAMPLE.replace(" 1372 ", " \u0661\u0663\u0667\u0662 "), "elapsed", id="arabic-digits"
        ),
        pytest.param(SAMPLE.replace(" 399 ", " +399 "), "response size", id="plus-size"),
        pytest.param(SAMPLE.replace(" 399 ", " 1_000 "), "response size", id="underscore-size"),
        pytest.param(
            SAMPLE.replace(" 399 ", " " + "9" * 19 + " "), "response size", id="huge-size"
        ),
        pytest.param(SAMPLE.replace(" 1372 ", " fast "), "elapsed", id="bad-elapsed"),
        pytest.param(SAMPLE.replace(" 1372 ", " -3 "), "elapsed", id="negative-elapsed"),
        pytest.param(SAMPLE.replace(" 399 ", " big "), "response size", id="bad-size"),
        pytest.param(SAMPLE.replace(" 399 ", " -2 "), "response size", id="negative-size"),
    ],
)
def test_rejects_malformed_lines(line: str, reason: str) -> None:
    with pytest.raises(ParseError, match=reason):
        parse_line(line)


# Real lines from Squid 6.13 (ubuntu/squid image) with log_mime_hdrs on, see
# tests/fixtures. The second line of each file is a request for "/my file.txt".
FIXTURES = Path(__file__).parent.parent / "fixtures"
MIME_LINES = (FIXTURES / "squid-6.13-log_mime_hdrs.log").read_text().splitlines()


def test_mime_headers_are_split_off() -> None:
    record = parse_line(MIME_LINES[0])

    assert (record.url, record.content_type) == ("http://origin:8000/ok.txt", "text/plain")
    assert record.request_headers == r"Host: origin:8000\r\nUser-Agent: test-client/1.0\r\n"
    assert record.reply_headers is not None
    assert record.reply_headers.startswith(r"HTTP/1.1 200 OK\r\nServer: SimpleHTTP/0.6")


def test_brackets_inside_headers_are_escaped_by_squid() -> None:
    # sent as "User-Agent: odd] agent [x"
    record = parse_line(MIME_LINES[2])

    assert record.request_headers == r"Host: origin:8000\r\nUser-Agent: odd%5d agent %5bx\r\n"


def test_default_uri_whitespace_strips_spaces() -> None:
    assert parse_line(MIME_LINES[1]).url == "http://origin:8000/myfile.txt"


def test_empty_header_columns() -> None:
    record = parse_line(f"{SAMPLE} [] []")

    assert (record.request_headers, record.reply_headers) == ("", "")


def test_no_headers_without_log_mime_hdrs() -> None:
    record = parse_line(SAMPLE)

    assert (record.request_headers, record.reply_headers) == (None, None)


def test_url_with_space_is_rejected() -> None:
    # Only logged with the non-default `uri_whitespace allow`. It can't be told
    # apart from a corrupt line, like the two records glued together above.
    line = (FIXTURES / "squid-6.13-uri_whitespace_allow.log").read_text().strip()

    with pytest.raises(ParseError, match="expected 10 fields, got 11"):
        parse_line(line)


def test_single_bracket_column_is_rejected() -> None:
    with pytest.raises(ParseError, match="expected 10 fields"):
        parse_line(f"{SAMPLE} [Host: a.example]")
