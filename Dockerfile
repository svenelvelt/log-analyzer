# syntax=docker/dockerfile:1

# Base images are pinned by digest. Builder and runtime share Python 3.13 so the
# bytecode compiled in the build stage is valid at runtime.
ARG BUILD_IMAGE=python:3.13-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
ARG RUNTIME_IMAGE=gcr.io/distroless/python3-debian13:nonroot@sha256:1c32c3720dc4c7f0c7dbe998737f32c200add6511eca7cec705008be488b87d6

FROM ${BUILD_IMAGE} AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /src
COPY build-requirements.txt ./
RUN pip install --require-hashes --no-deps -r build-requirements.txt

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
# The package has no runtime dependencies, so --no-deps installs just its own files.
RUN pip install --no-build-isolation --no-deps --target /app .


# Distroless: Python and its runtime libraries only, no shell or package manager.
FROM ${RUNTIME_IMAGE}

LABEL org.opencontainers.image.title="log-analyzer" \
      org.opencontainers.image.description="Analyze Squid access logs" \
      org.opencontainers.image.source="https://github.com/svenelvelt/log-analyzer" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /app /app

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# The nonroot base already runs as 65532; stating it keeps it visible to scanners and reviewers.
USER 65532:65532
WORKDIR /data

# A batch job that exits when done, so there's no HEALTHCHECK.
ENTRYPOINT ["/usr/bin/python3", "-m", "log_analyzer"]
