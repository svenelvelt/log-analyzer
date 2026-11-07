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

### Reading files

- Files are read line by line, so memory use doesn't grow with file size.
- Gzip is detected by the magic bytes at the start of the file, not by the `.gz` extension.
- Input is decoded as UTF-8. Invalid bytes are replaced with U+FFFD instead of failing,
  since they can only show up in the URL or user field.
- Lines longer than 64 KiB are skipped as malformed. The longest line in the sample file is
  about 4 KiB, so this leaves plenty of room for long URLs while keeping a corrupt file
  without newlines from being read into memory in one go.
- Each skipped line is logged at DEBUG with file and line number, and each file with
  skipped lines gets one WARNING with the total. Only the reason is logged, not the line
  itself, since log lines contain usernames and URLs.
- A missing, unreadable, truncated or corrupt file raises an error naming the file. With a
  truncated gzip, the records read before the error are still counted.
