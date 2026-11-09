from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LogRecord:
    """A single access log entry. Numeric fields are None when Squid logged -1."""

    timestamp: float  # unix epoch seconds
    elapsed_ms: int | None
    client_ip: str
    result_code: str  # e.g. TCP_MISS/200
    response_size: int | None  # bytes
    method: str
    url: str
    user: str
    hierarchy: str  # e.g. DIRECT/66.102.9.147
    content_type: str
    # Only logged with Squid's log_mime_hdrs, raw as written (CR/LF appear as \r\n).
    request_headers: str | None = None
    reply_headers: str | None = None
