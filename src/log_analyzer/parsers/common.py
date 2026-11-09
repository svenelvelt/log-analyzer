"""Parser for the Common Log Format and its combined variant.

Squid writes it with `logformat common` or `combined`, and Apache and nginx use it
for their access logs. Only the first seven fields are standard:

    host ident user [time] "request" status size [more fields...]

What follows differs by producer: referrer and user agent, Squid's cache status,
nginx's X-Forwarded-For. Squid doesn't even escape quotes in them, so they are
ignored, except for Squid's status (e.g. TCP_MISS:HIER_DIRECT) at the very end.
"""

import re
from datetime import datetime, timedelta, timezone

from log_analyzer.errors import ParseError
from log_analyzer.models import LogRecord

_LINE = re.compile(
    r"(?P<host>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]*)\] "
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>[0-9]{3}) (?P<size>[0-9]{1,18}|-)'
    r"(?P<rest>\s.*)?"
)
# e.g. 09/Nov/2026:14:09:50 +0000
_TIME = re.compile(
    r"([0-9]{2})/([A-Z][a-z]{2})/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r" ([+-])([0-9]{2})([0-9]{2})"
)
# Matched by hand: strptime's %b depends on the locale.
_MONTHS = {
    name: number
    for number, name in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}
_SQUID_STATUS = re.compile(r"\s([A-Z_]+):(\S+)\s*$")


def parse_line(line: str) -> LogRecord:
    """Parse one access log line. Raises ParseError if the line is malformed."""
    match = _LINE.fullmatch(line.strip())
    if not match:
        raise ParseError("not in common log format")

    request = match["request"].split(" ")
    if len(request) != 3:
        raise ParseError(f"invalid request {match['request']!r}")
    method, url, _protocol = request

    status = match["status"]
    squid = _SQUID_STATUS.search(match["rest"] or "")
    return LogRecord(
        timestamp=_parse_time(match["time"]),
        elapsed_ms=None,
        client_ip=match["host"],
        result_code=f"{squid[1]}/{status}" if squid else status,
        # Apache's %b writes "-" when no bytes were sent
        response_size=0 if match["size"] == "-" else int(match["size"]),
        method=method,
        url=url,
        user=match["user"],
        hierarchy=squid[2] if squid else "-",
        content_type="-",
    )


def _parse_time(raw: str) -> float:
    """Turn e.g. 09/Nov/2026:14:09:50 +0000 into a Unix timestamp."""
    parts = _TIME.fullmatch(raw)
    if not parts or parts[2] not in _MONTHS:
        raise ParseError(f"invalid time {raw!r}")
    day, month, year, hour, minute, second, sign, tz_hours, tz_minutes = parts.groups()
    try:
        offset = timedelta(hours=int(tz_hours), minutes=int(tz_minutes))
        zone = timezone(-offset if sign == "-" else offset)
        when = datetime(
            int(year), _MONTHS[month], int(day), int(hour), int(minute), int(second), tzinfo=zone
        )
    except ValueError:
        raise ParseError(f"invalid time {raw!r}") from None
    return when.timestamp()
