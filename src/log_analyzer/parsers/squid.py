"""Parser for Squid's native access.log format."""

import re
from datetime import UTC, datetime

from log_analyzer.errors import ParseError
from log_analyzer.models import LogRecord

FIELD_COUNT = 10
UNKNOWN = "-1"
# Anything later can't be turned into a date, which the report needs for its time range.
MAX_TIMESTAMP = datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC).timestamp()

# What Squid writes: plain ASCII digits. int() and float() would also take "1_000",
# "+5", "1e9", "nan" or digits from other scripts. Sizes are capped at 18 digits,
# an exabyte, far beyond any real response.
_TIMESTAMP = re.compile(r"[0-9]+(?:\.[0-9]+)?")
_SIZE = re.compile(r"[0-9]{1,18}")


def parse_line(line: str) -> LogRecord:
    """Parse one access.log line. Raises ParseError if the line is malformed."""
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
    )


def _parse_timestamp(raw: str) -> float:
    if not _TIMESTAMP.fullmatch(raw) or float(raw) > MAX_TIMESTAMP:
        raise ParseError(f"invalid timestamp {raw!r}")
    return float(raw)


def _parse_size(raw: str, name: str) -> int | None:
    if raw == UNKNOWN:
        return None
    if not _SIZE.fullmatch(raw):
        raise ParseError(f"invalid {name} {raw!r}")
    return int(raw)
