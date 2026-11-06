FROM cgr.dev/chainguard/python@sha256:31dd69d84fe5235fe18f8ceb5b76620e6f44a0ce1f9b0d3a46c491576f8b453b

# File: release/fixtures/task013-canary/oci/Dockerfile
# Purpose: Build the minimal private Task013 canary with an immutable,
#          review-only Chainguard Python OCI base and no package manager.
# Related: release/executable_oci.py, release/tests/test_executable_canary.py,
#          release/vulnerability_policy.py and release/README.md.
# The first FROM statement is mandatory for the original executable OCI
# regression; the scanner must independently PASS before any release.

ARG RELEASE_VERSION
ARG SOURCE_SHA
ARG OCI_REPOSITORY

LABEL org.opencontainers.image.title="$OCI_REPOSITORY" \
      org.opencontainers.image.version="$RELEASE_VERSION" \
      org.opencontainers.image.revision="$SOURCE_SHA" \
      ai.omnilyzer.canary="true" \
      ai.omnilyzer.base.digest="sha256:31dd69d84fe5235fe18f8ceb5b76620e6f44a0ce1f9b0d3a46c491576f8b453b"

ENV CANARY_RELEASE_VERSION="$RELEASE_VERSION" \
    CANARY_SOURCE_SHA="$SOURCE_SHA" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY --chown=10001:10001 canary_runtime.py migration.py migration-definition.json /app/

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/bin/python", "/app/canary_runtime.py"]
CMD []
