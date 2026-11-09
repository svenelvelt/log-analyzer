"""Parser for Squid's native access.log format."""

import re

from log_analyzer.errors import ParseError
from log_analyzer.models import LogRecord

FIELD_COUNT = 10
UNKNOWN = "-1"

# What Squid writes: plain ASCII digits. int() and float() would also take "1_000",
# "+5", "1e9", "nan" or digits from other scripts. Sizes are capped at 18 digits,
# an exabyte, far beyond any real response.
_TIMESTAMP = re.compile(r"[0-9]+(?:\.[0-9]+)?")
_SIZE = re.compile(r"[0-9]{1,18}")

# log_mime_hdrs adds two columns, [request headers] [reply headers], which contain
# spaces. Squid writes brackets inside them as %5b and %5d, so a raw bracket only
# ever delimits a column.
_MIME_HEADERS = re.compile(r"\s\[([^\[\]]*)\]\s+\[([^\[\]]*)\]\s*$")


def parse_line(line: str) -> LogRecord:
    """Parse one access.log line. Raises ParseError if the line is malformed.

    Lines with more than 10 fields are rejected, which includes URLs with spaces:
    Squid only logs those with the non-default `uri_whitespace allow`, and they
    can't be told apart from a corrupt line.
    """
    request_headers = reply_headers = None
    if line.rstrip().endswith("]") and (headers := _MIME_HEADERS.search(line)):
        request_headers, reply_headers = headers.groups()
        line = line[: headers.start()]

    # Squid pads columns with spaces, so split on any whitespace.
    fields = line.split()
    if len(fields) != FIELD_COUNT:
        raise ParseError(f"expected {FIELD_COUNT} fields, got {len(fields)}")

    ts, elapsed, ip, code, size, method, url, user, hierarchy, ctype = fields
    return LogRecord(
        timestamp=_parse_timestamp(ts),
        elapsed_ms=_parse_size(elapsed, "elapsed"),
        client_ip=ip,
        result_code=code,
        response_size=_parse_size(size, "response size"),
        method=method,
        url=url,
        user=user,
        hierarchy=hierarchy,
        content_type=ctype,
        request_headers=request_headers,
        reply_headers=reply_headers,
    )


def _parse_timestamp(raw: str) -> float:
    if not _TIMESTAMP.fullmatch(raw):
        raise ParseError(f"invalid timestamp {raw!r}")
    return float(raw)


def _parse_size(raw: str, name: str) -> int | None:
    if raw == UNKNOWN:
        return None
    if not _SIZE.fullmatch(raw):
        raise ParseError(f"invalid {name} {raw!r}")
    return int(raw)
