# log-analyzer

CLI for analyzing log files. Currently supports Squid access logs.

## Development

Requires [uv](https://docs.astral.sh/uv/).

```sh
uv sync                 # create .venv, install package and dev tools
uv run pytest
uv run ruff check .
uv run ruff format .
uv run mypy
```

## Assumptions

### Input format

Squid native `access.log`, 10 fields per line.

- The spec calls the format CSV, but the fields are whitespace-separated and Squid pads the
  second column, so lines are split on any run of whitespace.
- The spec describes field 2 as the response header size. In Squid's native format it's the
  request duration in milliseconds, so it's stored as `elapsed_ms`.
- Squid logs `-1` when a size or duration is unknown. About 61% of the sample lines have
  `-1` as response size, so these are parsed as `None` instead of rejecting the line. Other
  negative values are treated as malformed.
- Malformed lines (wrong field count, bad timestamp or number) are skipped and counted.
  The sample file has two: an empty first line, and line 82948 where two records ended up
  on the same line.
- `-` placeholders (no user, no content type) are kept as is.
