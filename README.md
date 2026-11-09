# log-analyzer

A command-line tool, and a small Python API, for analyzing log files.

## At a glance

- Reads Squid's native access log, or the Common Log Format that Squid, Apache and nginx
  can write, plain or gzipped, from files or stdin. Input is streamed: the
  1.6 million lines of the sample take about 5 seconds and under 40 MiB of memory.
- Fault tolerant: malformed lines are skipped and counted, an unreadable input is reported
  while the others are still analyzed, and the report is written atomically. See
  [Exit status](#exit-status).
- Where the spec and the real data disagree, the data wins, and each decision is
  documented under [Assumptions](#assumptions): the "CSV" is whitespace-separated, field 2
  is a duration rather than a size, `-1` means unknown, tied IPs are all returned, and
  events per second is reported as average and peak.
- Built to be extended: operations, input formats and output formats each have a registry,
  and the CLI is a thin layer over a Python function. See [Design](#design).
- No runtime dependencies, a distroless non-root container, and CI with pinned actions and
  dependency, secret and image scanning. See [Docker](#docker) and
  [CI and supply chain](#ci-and-supply-chain).

## Install

Requires Python 3.11 or newer. No third-party runtime dependencies.

```sh
pip install .            # or: uv tool install .
log-analyzer --version
```

## Usage

```
log-analyzer [--input-format FORMAT] [--output-format FORMAT] [-v | -q]
             [--mfip] [--lfip] [--eps] [--bytes] INPUT [INPUT ...] OUTPUT
```

| Option            | Result                                                |
|-------------------|-------------------------------------------------------|
| `--mfip`          | most frequent client IP(s)                            |
| `--lfip`          | least frequent client IP(s)                           |
| `--eps`           | average and peak events per second                    |
| `--bytes`         | total bytes delivered to clients                      |
| `--input-format`  | `squid` (default), `common` or `auto`, see [Input formats](#input-formats) |
| `--output-format` | `json` (default) or `text`, see [Output](#output)      |
| `-v`, `--verbose` | also log every skipped line                           |
| `-q`, `--quiet`   | only log errors                                       |

Without any operation flag all of them run. Several inputs are analyzed together, and
flags can go anywhere on the command line. An `INPUT` of `-` reads stdin, plain or gzipped.
`OUTPUT` is the file for the report, or `-` for stdout
(use `./-` for a file actually named `-`). It can't be one of the inputs, so a mixed-up
command line can't overwrite a log. Messages go to stderr, so stdout stays valid JSON.

```sh
curl -O https://www.secrepo.com/squid/access.log.gz

log-analyzer access.log.gz report.json
log-analyzer access.log.gz - --mfip --eps | jq .results
log-analyzer access.log access.log.1 access.log.2.gz report.json --bytes
ssh proxy cat /var/log/squid/access.log | log-analyzer - report.json
```

### Output

For the sample file (the `lfip` list is shortened here, it has 30 entries):

```json
{
  "meta": {
    "tool": "log-analyzer 0.1.0",
    "files": [
      {"path": "access.log.gz", "format": "squid", "lines": 1643520, "events": 1643518,
       "skipped": 2, "error": null}
    ],
    "lines": 1643520,
    "events": 1643518,
    "skipped": 2,
    "first": "2002-10-19T20:30:37.745Z",
    "last": "2012-05-02T03:18:57.000Z"
  },
  "results": {
    "mfip": {"ips": ["127.0.0.1"], "count": 1422267},
    "lfip": {"ips": ["10.105.21.138", "10.105.21.178", "..."], "count": 1},
    "eps": {"average": 0.005462564623700176, "peak": 7952},
    "bytes": {"total": 2216979451, "unknown": 1001183}
  }
}
```

- `meta.files` lists every input with the format it was read in. A file that couldn't be
  read has its `error` set, and keeps the counts from before the failure.
- `first` and `last` are the earliest and latest event in UTC.
- Results always come in the order mfip, lfip, eps, bytes. Why they look the way they do
  is explained under [Assumptions](#assumptions).

JSON is the default and the complete report. `--output-format text` prints a short summary
for reading in a terminal instead, with long IP lists cut after five entries:

```
$ log-analyzer access.log.gz - --output-format text
log-analyzer 0.1.0
access.log.gz (squid): 1,643,518 events, 2 lines skipped
Period: 2002-10-19T20:30:37.745Z to 2012-05-02T03:18:57.000Z

Most frequent IP    127.0.0.1 (1,422,267 requests)
Least frequent IP   10.105.21.138, 10.105.21.178, 10.105.41.121, 10.105.47.186, 10.105.53.146 and 25 more (1 request each)
Events per second   0.005463 on average, 7,952 at peak
Bytes               2,216,979,451 (size unknown for 1,001,183 events)
```

### Exit status

| Code | Meaning                                                                  |
|------|--------------------------------------------------------------------------|
| 0    | all inputs read and the output written                                   |
| 1    | an input couldn't be read, or the output couldn't be written             |
| 2    | invalid command line                                                     |
| 130  | interrupted with Ctrl-C                                                  |
| 143  | stopped with SIGTERM, e.g. by `docker stop` or Kubernetes                |
| 141  | stdout was closed early, e.g. piped into `head`; no message is printed   |

If an input fails, the other inputs are still analyzed and the output is still written,
so a caller gets the partial result together with the reason.

The output file is written to a temporary file next to it and then renamed, so an existing
report is never left half-written. Whether the output location is usable is checked before
any input is read, so a typo in the path doesn't cost a long run over large logs.

### From Python

The CLI is a thin layer over one function, which returns the same report as a dictionary.
That makes it usable from an automation, for example a SOAR playbook, without going
through files or a subprocess:

```python
import io
from log_analyzer import analyze

report = analyze(["access.log", "access.log.1.gz"])
report = analyze(["access.log"], ["mfip", "eps"])

# data that never touches the disk, e.g. fetched from an API
report = analyze([io.BufferedReader(io.BytesIO(data))], ["bytes"])
print(report["results"]["bytes"]["total"])
```

Sources can be paths, binary streams (plain or gzipped) or `"-"` for stdin. Unreadable
sources end up in `report["meta"]["files"]` with their error, as with the CLI; an unknown
operation raises `ValueError`.

## Docker

```sh
docker build -t log-analyzer .
```

The image is a multi-stage build on
[distroless](https://github.com/GoogleContainerTools/distroless) Python (Debian 13,
Python 3.13): no shell, no package manager, about 90 MB, running as the unprivileged user
65532. Base images are pinned by digest, and the build backend is installed from
[build-requirements.txt](build-requirements.txt) with hash checking. Only the package
itself ends up in the runtime image.

The simplest way to run it is with the logs mounted read-only and the report on stdout:

```sh
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --network none \
  -v "$PWD:/data:ro" log-analyzer access.log.gz - > report.json
```

The extra flags aren't needed for it to work, but it doesn't need any more than that: no
network, no capabilities, nothing written inside the container. With `-i` it can read the
log from stdin instead, without any mount:

```sh
docker run --rm -i --read-only --cap-drop ALL --security-opt no-new-privileges \
  --network none log-analyzer - - < access.log.gz > report.json
```

To write the report into a mounted directory instead, run as your own user so the
container can write there and the file belongs to you:

```sh
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --network none \
  --user "$(id -u):$(id -g)" -v "$PWD/logs:/logs:ro" -v "$PWD/reports:/data" \
  log-analyzer /logs/access.log.gz report.json
```

### Docker Compose

[compose.yaml](compose.yaml) has the same settings, plus memory and process limits. It
analyzes `./data/access.log.gz` into `./reports/report.json`:

```sh
mkdir -p reports
HOST_UID=$(id -u) HOST_GID=$(id -g) docker compose run --rm log-analyzer
```

### Kubernetes

The tool is a batch job, so as a service it runs on a schedule.
[deploy/k8s/cronjob.yaml](deploy/k8s/cronjob.yaml) is a CronJob that analyzes the proxy's
current and rotated log every night at 00:15 UTC and writes the report to a volume. It
runs non-root with a read-only root filesystem, no capabilities, the default seccomp
profile, no service account token and a NetworkPolicy that blocks all traffic. A run over
the 1.6 million lines of the sample peaks at about 35 MiB, so the limits are 128 MiB and
one CPU.

```sh
kubectl apply -n <namespace> -f deploy/k8s/cronjob.yaml
kubectl create job -n <namespace> --from=cronjob/log-analyzer log-analyzer-now   # run once now
```

It expects the PersistentVolumeClaims `squid-logs` and `log-analyzer-reports`. The
`image:` in the manifest is a placeholder: build the image, push it to a registry the
cluster can pull from, and put that reference there.

## Design

Every input is read once. The reader turns bytes into lines, the parser turns each line
into a `LogRecord`, and each selected analyzer sees every record. The result is a plain
dictionary, which a formatter turns into text.

| Module          | Responsibility                                                   |
|-----------------|------------------------------------------------------------------|
| `cli.py`        | arguments, where the output goes, exit codes, logging            |
| `analysis.py`   | `analyze()`: reads each source once and feeds the analyzers      |
| `reader.py`     | files and streams, gzip, decoding, line limits, malformed lines  |
| `parsers/`      | one module per input format, registered in `PARSERS`             |
| `analyzers.py`  | one class per operation, registered in `ANALYZERS`               |
| `formatters.py` | output formats, registered in `FORMATTERS`                       |
| `models.py`     | `LogRecord`, what every parser produces                          |
| `errors.py`     | `ParseError` for a bad line, `InputError` for an unreadable source |

### Adding an operation

Write a class with a `name`, an `update(record)` method that is called once per log
record, and a `result()` method that returns something JSON-serializable. Then add it to
`_ALL` in `analyzers.py`. The CLI flag `--<name>` and its help text (the first paragraph
of the docstring) are generated from that list.

### Adding an input format

Write a function that turns one line into a `LogRecord` or raises `ParseError`, and add it
to `PARSERS` in `parsers/__init__.py`. Reading, gzip, encoding, the timestamp range check
and error handling are shared, and `--input-format` offers every registered parser.

### Adding an output format

Write a function that takes the report (the `meta` and `results` dictionary shown under
[Output](#output)) and returns the text to write, and add it to `FORMATTERS` in
`formatters.py`. Writing to a file or stdout, including the atomic replace, stays in the
CLI, and `--output-format` offers every registered format. A result the `text` format
doesn't know yet, from a newly added operation, is shown as JSON there until it gets a
readable line of its own.

## Assumptions

### Input formats

`--input-format` picks one format for all inputs. With `auto`, the format is detected for
each input separately: the first line that one of the parsers accepts decides, and the rest
of that input is read in the same format. Lines before that are skipped as malformed. The
detected format is in `meta.files`, or `null` if no line matched. `squid` stays the default
because it's the format the assignment is about, and an explicit format never guesses.

#### Squid native (`--input-format squid`, the default)

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
  which are in [tests/fixtures](tests/fixtures).
- The [Squid docs](https://wiki.squid-cache.org/Features/LogFormat#squid-native-accesslog-format-in-detail)
  warn that spaces in URLs are not escaped. In practice they only appear with
  `uri_whitespace allow`; with the default `strip` Squid removes them, and `encode` escapes
  them. A line with a space in the URL has more than 10 fields and is skipped like any
  malformed line, because it looks exactly like a corrupt one: line 82948 of the sample,
  two records written onto one line, would otherwise be read as a single request with
  half of the second record in its URL.

#### Common Log Format (`--input-format common`)

The format Squid writes with `logformat common` or `combined`, and the one Apache and
nginx use for their access logs. It was checked against real logs from Squid 6.13,
Apache 2.4 and nginx 1.31, which are in [tests/fixtures](tests/fixtures).

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

### Reading files

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
  time order. Squid writes entries "after the reply finished being sent", according to
  its docs, and the sample only goes back in time twice, both at the jumps between
  periods. If events from one second are split up, for example two
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

## Development

Requires [uv](https://docs.astral.sh/uv/).

```sh
uv sync                 # create .venv, install package and dev tools
uv run pytest --cov     # fails below 100% coverage
uv run ruff check .     # includes the flake8-bandit (S) security rules
uv run ruff format .
uv run mypy
```

The same checks run as git hooks, using the tool versions from `uv.lock`:

```sh
uv run pre-commit install --hook-type pre-commit --hook-type pre-push
```

Before each commit this runs ruff, mypy, gitleaks, zizmor on workflow changes and some
basic file checks. The tests run before each push.

The image scans from CI can be run locally with the Trivy container. The image is handed
over as a tar file, so Trivy doesn't need access to the Docker socket:

```sh
docker build -t log-analyzer . && docker save log-analyzer -o /tmp/log-analyzer.tar
docker run --rm -v /tmp/log-analyzer.tar:/image.tar:ro aquasec/trivy:0.76.1 \
  image --input /image.tar --severity HIGH,CRITICAL --ignore-unfixed
docker run --rm -v "$PWD:/repo:ro" aquasec/trivy:0.76.1 \
  config --severity HIGH,CRITICAL --skip-dirs /repo/.venv /repo
```

### CI and supply chain

[ci.yml](.github/workflows/ci.yml) runs on every push and pull request:

| Job | What it checks |
|---|---|
| lint | ruff, formatting, mypy (strict) |
| test | pytest on Python 3.11, 3.12, 3.13 and 3.14, 100% coverage required |
| dependency audit | `pip-audit` on the locked dependencies, with hashes |
| secret scan | gitleaks over the full git history |
| workflow audit | [zizmor](https://docs.zizmor.sh/) on the workflows, including a check that every pinned commit really belongs to the action's repository |
| image | builds the image, runs it on a small log with the hardening flags, then Trivy: fails on fixable HIGH or CRITICAL vulnerabilities in the image, and on HIGH or CRITICAL misconfigurations in the Dockerfile and Kubernetes manifests |

[codeql.yml](.github/workflows/codeql.yml) runs GitHub's CodeQL analysis. It's skipped
while the repository is private, since code scanning is only free for public repositories.

No image is published for this assignment, but
[release.yml](.github/workflows/release.yml) shows how a release would work. On a version
tag such as `v0.1.0` it runs the whole CI again, checks that the tag matches the package
version, then pushes the image to the GitHub Container Registry with an SBOM and signed
build provenance, which anyone can check with `gh attestation verify`.

All GitHub Actions are pinned to full commit SHAs, workflows get read-only permissions
unless a job needs more, and checkouts don't keep the token. Dependabot opens weekly
update PRs for the actions, the uv lockfile and the base image digests, but only for
releases at least two weeks old, which leaves time for a compromised release to be caught
before it lands here. The same two-week rule was used for every version pinned by hand.

## Sample data

The sample log is from [SecRepo](https://www.secrepo.com/), published under the
[Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/) license.
It isn't included in this repository.

## License

MIT, see [LICENSE](LICENSE).
