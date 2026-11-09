# Assumptions and decisions

Where the specification was unclear, or didn't match the real data, these are the
choices made and the evidence behind them. The [README](../README.md#assumptions) has a
one-line summary of each.

## Input formats

`--input-format` picks one format for all inputs. With `auto`, the format is detected for
each input separately: the first line that one of the parsers accepts decides, and the rest
of that input is read in the same format. Lines before that are skipped as malformed. The
detected format is in `meta.files`, or `null` if no line matched. `squid` stays the default
because it's the format the assignment is about, and an explicit format never guesses.

### Squid native (`--input-format squid`, the default)

Squid's own `access.log` format, 10 fields per line.

- The spec calls the format CSV, but the fields are whitespace-separated and Squid pads the
  second column, so lines are split on any run of whitespace.
- The spec describes field 2 as the response header size. In Squid's native format it's the
  request duration in milliseconds
  ([Squid docs](https://wiki.squid-cache.org/Features/LogFormat#squid-native-accesslog-format-in-detail)),
  so it's stored as `elapsed_ms`.
- Squid logs `-1` when a size or duration is unknown. About 61% of the sample lines have
  `-1` as response size, so these are parsed as `None` instead of rejecting the line. Other
  negative values are treated as malformed.
- Numbers must be plain ASCII digits, as Squid writes them. Python's `int()` and `float()`
  would also accept forms like `1_000`, `+5`, `1e9` or `nan`, so the parser checks the
  format first.
- Malformed lines (wrong field count, bad timestamp or number) are skipped and counted.
  The sample file has two: an empty first line, and line 82948 where two records ended up
  on the same line.
- `-` placeholders (no user, no content type) are kept as is.
- With Squid's `log_mime_hdrs` option, two more columns follow: the request and the reply
  headers, each in `[...]`. They are split off and kept as `request_headers` and
  `reply_headers` on each record. Squid writes brackets inside headers as `%5b` and `%5d`,
  so the columns can be found reliably. This was checked against real Squid 6.13 logs,
  which are in [tests/fixtures](../tests/fixtures).
- The [Squid docs](https://wiki.squid-cache.org/Features/LogFormat#squid-native-accesslog-format-in-detail)
  warn that spaces in URLs are not escaped. In practice they only appear with
  `uri_whitespace allow`; with the default `strip` Squid removes them, and `encode` escapes
  them. A line with a space in the URL has more than 10 fields and is skipped like any
  malformed line, because it looks exactly like a corrupt one: line 82948 of the sample,
  two records written onto one line, would otherwise be read as a single request with
  half of the second record in its URL.

### Common Log Format (`--input-format common`)

The format Squid writes with `logformat common` or `combined`, and the one Apache and
nginx use for their access logs. It was checked against real logs from Squid 6.13,
Apache 2.4 and nginx 1.31, which are in [tests/fixtures](../tests/fixtures).

- Only the first seven fields are standard: `host ident user [time] "request" status size`.
  Everything after them differs by producer (referrer and user agent in `combined`,
  Squid's cache status, nginx's `X-Forwarded-For`), and Squid doesn't escape quotes in
  them, so they are ignored. The exception is Squid's status at the end, such as
  `TCP_MISS:HIER_DIRECT`, which fills the result code and hierarchy.
- Times have a precision of one second and include a time zone.
- A size of `-` means no bytes were sent, as Apache writes it.
- Bytes mean what the producer logs: Squid counts the headers, Apache's `%b` and nginx's
  `$body_bytes_sent` only the body.
- Web servers log the request path (`/index.html`) rather than the full URL. There's no
  duration or content type, so those fields are empty.
- A line whose request isn't `METHOD URL PROTOCOL` is malformed, for example the `"-"`
  nginx logs for connections that never sent a request.

## Reading files

- Files are read line by line, so memory use doesn't grow with file size.
- Gzip is detected by the magic bytes at the start of the file, not by the `.gz` extension.
- Input is decoded as UTF-8. Invalid bytes are replaced with U+FFFD instead of failing,
  since they can only show up in the URL or user field.
- Records with a timestamp before 1970 or after 9999 are skipped as malformed, whatever
  the input format, because the report turns timestamps into dates.
- Lines longer than 64 KiB are skipped as malformed. The longest line in the sample file is
  about 4 KiB, so this leaves plenty of room for long URLs while keeping a corrupt file
  without newlines from being read into memory in one go.
- Each skipped line is logged at DEBUG with file and line number, and each file with
  skipped lines gets one WARNING with the total. Only the reason is logged, not the line
  itself, since log lines contain usernames and URLs.
- A missing, unreadable, truncated or corrupt file raises an error naming the file. With a
  truncated gzip, the records read before the error are still counted.

## Operations

With several input files, results are aggregated over all of them, e.g. rotated
`access.log.1`, `access.log.2`, ... give one answer per operation.

### Most and least frequent IP (`--mfip`, `--lfip`)

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

### Events per second (`--eps`)

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
  time order. Squid writes entries "after the reply finished being sent", according to
  its docs, and the sample only goes back in time twice, both at the jumps between
  periods. If events from one second are split up, for example two
  proxies' logs covering the same time, the peak can come out too low but never too high.
- With no valid records the result is `{"average": 0.0, "peak": 0}`.

### Total bytes (`--bytes`)

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
  Splunk's [Squid add-on](https://docs.splunk.com/Documentation/AddOns/released/Squid/Setup)
  makes the same choice: its recommended log format records `%<st` as `bytes_out` and
  needs the custom `%>st` for `bytes_in`.
- Field 2 isn't added, even though the spec calls it the header size. It's `%tr`, the
  response time in milliseconds, and the headers are already part of field 5.
- `unknown` counts events where Squid logged `-1` as the size. In the sample that's 61% of
  all events, including about 348,000 `TCP_MISS/200` responses that did send content, so
  the total is a lower bound.
- With no valid records the result is `{"total": 0, "unknown": 0}`.
