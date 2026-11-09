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
  [CI and supply chain](docs/development.md#ci-and-supply-chain).

## Install

Requires Python 3.11 or newer. No third-party runtime dependencies.

```sh
pip install .            # or: uv tool install .
log-analyzer --version
```

## Usage

```
log-analyzer [--input-format FORMAT] [--output-format FORMAT] [-v | -q]
             [--mfip [N]] [--lfip [N]] [--eps] [--bytes] INPUT [INPUT ...] OUTPUT
```

| Option            | Result                                                |
|-------------------|-------------------------------------------------------|
| `--mfip [N]`      | the N most frequent client IPs, 1 by default          |
| `--lfip [N]`      | the N least frequent client IPs, 1 by default         |
| `--eps`           | average and peak events per second                    |
| `--bytes`         | total bytes delivered to clients                      |
| `--input-format`  | `squid` (default), `common` or `auto`, see [Input formats](docs/decisions.md#input-formats) |
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

For the sample file (the `lfip` list is shortened here, 30 IPs tie):

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
    "mfip": {"n": 1, "clients": [{"ip": "127.0.0.1", "count": 1422267}]},
    "lfip": {"n": 1, "clients": [{"ip": "10.105.21.138", "count": 1},
                                 {"ip": "10.105.21.178", "count": 1}, "..."]},
    "eps": {"average": 0.005462564623700176, "peak": 7952},
    "bytes": {"total": 2216979451, "unknown": 1001183}
  }
}
```

- `meta.files` lists every input with the format it was read in. A file that couldn't be
  read has its `error` set, and keeps the counts from before the failure.
- `first` and `last` are the earliest and latest event in UTC.
- Results always come in the order mfip, lfip, eps, bytes. Why they look the way they do
  is explained in [docs/decisions.md](docs/decisions.md#operations).

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

If the operation takes a value, like the N in `--mfip [N]`, give its constructor one
argument with a type hint and a default, as the shared base of `MostFrequentIp` and
`LeastFrequentIp` does with `n: int = 1`. That's all: the CLI derives `--mfip [N]` from
it, converts the value with the type, and reports a `ValueError` from the constructor,
such as `--mfip 0`, as a usage error before reading any input. `analyze()` accepts
`{"mfip": 5}`.

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

Where the specification was unclear or didn't match the real data, these choices were made.
The reasoning and the evidence for each are in [docs/decisions.md](docs/decisions.md).

- The "CSV" is whitespace-separated: fields are split on any run of spaces.
- Field 2 is the request duration in milliseconds, not a header size, as Squid documents it.
- `-1` means unknown (61% of the sample's sizes), not a malformed line.
- Numbers must be plain ASCII digits; timestamps must lie between 1970 and 9999.
- Malformed lines are skipped and counted, never fatal. A URL with a space makes a line
  malformed: Squid only writes those with `uri_whitespace allow`, and they look exactly
  like corrupt lines.
- With `log_mime_hdrs`, the two header columns are split off and kept on the record.
- Several inputs are analyzed together, as one set of logs.
- `--mfip` and `--lfip` take an optional N, 1 by default, like Splunk's `top` and `rare`.
  IPs tied with the Nth are all returned, so the list can be longer than N.
- Events per second is the average over the whole time covered, plus the busiest second.
- Bytes are the sum of field 5, the reply size including headers. Sizes logged as `-1`
  are counted separately, so the total is a lower bound.
- In the Common Log Format only the seven standard fields are used, and bytes mean
  whatever the producer logs.

## Development

Requires [uv](https://docs.astral.sh/uv/).

```sh
uv sync                 # create .venv, install package and dev tools
uv run pytest --cov     # fails below 100% coverage
uv run ruff check .     # includes the flake8-bandit (S) security rules
uv run ruff format .
uv run mypy
```

Git hooks, running the image scans locally, and what CI checks are described in
[docs/development.md](docs/development.md).

## Sample data

The sample log is from [SecRepo](https://www.secrepo.com/), published under the
[Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/) license.
It isn't included in this repository.

## License

MIT, see [LICENSE](LICENSE).
