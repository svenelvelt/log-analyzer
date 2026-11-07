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
  request duration in milliseconds
  ([Squid docs](https://wiki.squid-cache.org/Features/LogFormat#squid-native-accesslog-format-in-detail)),
  so it's stored as `elapsed_ms`.
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

### Operations

With several input files, results are aggregated over all of them, e.g. rotated
`access.log.1`, `access.log.2`, ... give one answer per operation.

#### Most and least frequent IP (`--mfip`, `--lfip`)

- The spec asks for "the" most and least frequent IP, but ties are common: in the sample
  file 30 IPs share the lowest count of 1 request. Picking one of them would depend on input
  order or an arbitrary tie-break and hide the rest, so all tied IPs are returned together
  with the shared count. The result has the same shape with or without a tie, like
  `statistics.multimode` in the standard library:

  ```json
  {"ips": ["127.0.0.1"], "count": 1422267}
  ```

- Tied IPs are sorted by address (`10.0.0.2` before `10.0.0.10`), IPv4 before IPv6. The
  client field is counted as is, so if Squid logs hostnames (`log_fqdn on`) those are
  counted too and sorted after the addresses.
- With no valid records the result is `{"ips": [], "count": 0}`.

#### Events per second (`--eps`)

The sample file isn't one continuous log. It has four periods with years between them:

| Period (UTC)             | Events    | Duration | Rate    |
|--------------------------|-----------|----------|---------|
| 2002-10-19 to 2002-10-23 | 138,305   | 3.6 days | 0.45/s  |
| 2006-09-08               | 82,946    | 4 h      | 5.8/s   |
| 2012-04-23               | 199,247   | 5 h      | 10.7/s  |
| 2012-04-27 to 2012-05-02 | 1,223,020 | 4.5 days | 3.2/s   |

So a single "events per second" number depends heavily on the definition. Events divided
by the time from first to last event gives 0.0055, because the gaps dominate. Dividing by
only the seconds that have events gives 3.56, but that ignores quiet seconds and overstates
the rate. Splitting into periods needs an arbitrary gap threshold.

SIEM sizing usually looks at average and peak EPS, so the result has both:

```json
{"average": 0.0055, "peak": 7952}
```

- `average` is the number of events divided by the whole seconds from the earliest to the
  latest event, inclusive. That's the plain reading of the spec, and the +1 means a single
  event gives 1.0 instead of a division by zero. Earliest and latest are the minimum and
  maximum timestamps, so the order the files are given in doesn't matter.
- `peak` is the most events in any one second. It's computed by counting consecutive
  events with the same second, which keeps memory constant instead of storing a count per
  second (461k seconds, about 34 MiB, for the sample). This relies on each file being in
  time order, which is how Squid writes it: the sample only goes back in time twice, both
  at the jumps between periods. If events from one second are split up, for example two
  proxies' logs covering the same time, the peak can come out too low but never too high.
- With no valid records the result is `{"average": 0.0, "peak": 0}`.

#### Total bytes (`--bytes`)

```json
{"total": 2216979451, "unknown": 1001183}
```

- `total` is the sum of field 5. Squid's
  [log format docs](https://wiki.squid-cache.org/Features/LogFormat#squid-native-accesslog-format-in-detail)
  describe it as "the amount of data delivered to the client", and note that "headers are
  also counted". In the [`logformat`](https://www.squid-cache.org/Doc/config/logformat/)
  definition of the native format it's `%<st`, "Total size of reply sent to client".
- That's the only byte count in the native format. Squid can log the full traffic in both
  directions with `%st` ("Total size of request + reply traffic with client"), but only
  with a custom `logformat`, so "bytes exchanged" here means bytes delivered to clients.
- Field 2 isn't added, even though the spec calls it the header size. It's `%tr`, the
  response time in milliseconds, and the headers are already part of field 5.
- `unknown` counts events where Squid logged `-1` as the size. In the sample that's 61% of
  all events, including about 348,000 `TCP_MISS/200` responses that did send content, so
  the total is a lower bound.
- With no valid records the result is `{"total": 0, "unknown": 0}`.
