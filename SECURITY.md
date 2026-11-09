# Security policy

Please report vulnerabilities privately through
[Security → Report a vulnerability](https://github.com/svenelvelt/log-analyzer/security/advisories/new),
not in a public issue. Only the latest version on `main` is maintained.

log-analyzer reads log files that may come from untrusted sources, so anything a crafted
log can cause is in scope: a crash, unbounded memory use, a wrong result without a
warning, or a file written outside the given output path. So are problems in the
container image and the CI pipeline.
