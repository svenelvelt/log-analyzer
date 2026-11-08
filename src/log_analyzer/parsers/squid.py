"""Parser for Squid's native access.log format."""

import math
from datetime import UTC, datetime

from log_analyzer.errors import ParseError
from log_analyzer.models import LogRecord

FIELD_COUNT = 10
UNKNOWN = "-1"
# Anything later can't be turned into a date, which the report needs for its time range.
MAX_TIMESTAMP = datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC).timestamp()


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
    try:
        value = float(raw)
    except ValueError:
        raise ParseError(f"invalid timestamp {raw!r}") from None
    if not math.isfinite(value) or not 0 <= value <= MAX_TIMESTAMP:
        raise ParseError(f"invalid timestamp {raw!r}")
    return value


def _parse_size(raw: str, name: str) -> int | None:
    if raw == UNKNOWN:
        return None
    try:
        value = int(raw)
    except ValueError:
        raise ParseError(f"invalid {name} {raw!r}") from None
    if value < 0:
        raise ParseError(f"invalid {name} {raw!r}")
    return value
