# Development

Setup and the basic commands (tests, lint, format, type check) are in the
[README](../README.md#development).

## Git hooks

The same checks run as git hooks, using the tool versions from `uv.lock`:

```sh
uv run pre-commit install --hook-type pre-commit --hook-type pre-push
```

Before each commit this runs ruff, mypy, gitleaks, zizmor on workflow changes and some
basic file checks. The tests run before each push.

## Image scans

The image scans from CI can be run locally with the Trivy container. The image is handed
over as a tar file, so Trivy doesn't need access to the Docker socket:

```sh
docker build -t log-analyzer . && docker save log-analyzer -o /tmp/log-analyzer.tar
docker run --rm -v /tmp/log-analyzer.tar:/image.tar:ro aquasec/trivy:0.76.1 \
  image --input /image.tar --severity HIGH,CRITICAL --ignore-unfixed
docker run --rm -v "$PWD:/repo:ro" aquasec/trivy:0.76.1 \
  config --severity HIGH,CRITICAL --skip-dirs /repo/.venv /repo
```

## CI and supply chain

[ci.yml](../.github/workflows/ci.yml) runs on every push and pull request:

| Job | What it checks |
|---|---|
| lint | ruff, formatting, mypy (strict) |
| test | pytest on Python 3.11, 3.12, 3.13 and 3.14, 100% coverage required |
| dependency audit | `pip-audit` on the locked dependencies, with hashes |
| secret scan | gitleaks over the full git history |
| workflow audit | [zizmor](https://docs.zizmor.sh/) on the workflows, including a check that every pinned commit really belongs to the action's repository |
| image | builds the image, runs it on a small log with the hardening flags, then Trivy: fails on fixable HIGH or CRITICAL vulnerabilities in the image, and on HIGH or CRITICAL misconfigurations in the Dockerfile and Kubernetes manifests |

[codeql.yml](../.github/workflows/codeql.yml) runs GitHub's CodeQL analysis. It's skipped
while the repository is private, since code scanning is only free for public repositories.

No image is published for this assignment, but
[release.yml](../.github/workflows/release.yml) shows how a release would work. On a version
tag such as `v0.1.0` it runs the whole CI again, checks that the tag matches the package
version, then pushes the image to the GitHub Container Registry with an SBOM and signed
build provenance, which anyone can check with `gh attestation verify`.

All GitHub Actions are pinned to full commit SHAs, workflows get read-only permissions
unless a job needs more, and checkouts don't keep the token. Dependabot opens weekly
update PRs for the actions, the uv lockfile and the base image digests, but only for
releases at least two weeks old, which leaves time for a compromised release to be caught
before it lands here. The same two-week rule was used for every version pinned by hand.
