FROM ghcr.io/astral-sh/uv@sha256:df6ea28f3caf5eb77ebae34d38e9b177b41a4e58ee963b1cbc5c8c1c92710238

# File: release/fixtures/task013-canary/oci/Dockerfile
# Purpose: Build the Task013 non-root Python Canary without vulnerable
#          SQLite components and without glibc, preserving installed
#          Alpine package metadata so SBOM/Grype still inventories all
#          actual remaining OS packages.
# Related: release/executable_oci.py, release/tests/test_executable_canary.py,
#          .github/workflows/task013-canary-security-review.yml, and
#          deployment/docker_runtime.py.
#
# Section 1: Remove unused SQLite binary/extension and its actual APK package.
# This is not a vulnerability-policy waiver or an SBOM exclusion. The package
# database is retained and scanned. Network is disabled for Docker RUN.
# Existing Task014 requires /usr/bin/python; keep that exact entrypoint path.
RUN set -eu; \
    test -x /usr/local/bin/python; \
    apk info -e sqlite-libs; \
    apk info -e .python-rundeps; \
    apk del --no-network .python-rundeps sqlite-libs; \
    find /usr/local/lib/python3.14 -iname '*sqlite*' -exec rm -rf {} +; \
    test -z "$(find /usr/local/lib /usr/lib -iname '*sqlite*' -print -quit)"; \
    test -e /lib/ld-musl-x86_64.so.1; \
    ln -s /usr/local/bin/python /usr/bin/python; \
    /usr/bin/python -c 'import fcntl,hashlib,http.server,json,socket,threading'; \
    rm -f /sbin/apk /bin/sh /bin/busybox

# Section 2: Retain the original immutable Task013/Task014 runtime contract.
ARG RELEASE_VERSION
ARG SOURCE_SHA
ARG OCI_REPOSITORY

LABEL org.opencontainers.image.title="$OCI_REPOSITORY" \
      org.opencontainers.image.version="$RELEASE_VERSION" \
      org.opencontainers.image.revision="$SOURCE_SHA" \
      ai.omnilyzer.canary="true" \
      ai.omnilyzer.base.digest="sha256:df6ea28f3caf5eb77ebae34d38e9b177b41a4e58ee963b1cbc5c8c1c92710238"

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
