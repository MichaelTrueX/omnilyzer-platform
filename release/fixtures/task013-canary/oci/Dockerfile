FROM ghcr.io/astral-sh/uv@sha256:df6ea28f3caf5eb77ebae34d38e9b177b41a4e58ee963b1cbc5c8c1c92710238

# File: release/fixtures/task013-canary/oci/Dockerfile
# Purpose: Build the Task013 non-root Python Canary without unused vulnerable
#          SQLite and zlib APK packages or their Python optional extensions.
#          Preserve the actual Alpine package database for full Syft/Grype SBOM
#          scanning of every remaining component, with zero policy exceptions.
# Related: release/executable_oci.py, release/tests/test_executable_canary.py,
#          .github/workflows/task013-canary-security-review.yml, and
#          deployment/docker_runtime.py.
#
# Section 1: Remove unused SQLite, zlib and APK tooling + Python extensions.
# CVE-2026-4738 is CRITICAL in Alpine zlib 1.3.2-r1. The original offline
# apk del zlib alone leaves zlib installed because apk-tools depends on it.
# The Canary needs NONE of zlib/SQLite/apk-tools after build. Remove their
# actual package contents and optional Python extensions, NOT SBOM entries.
# Keep the genuine installed APK database for complete Syft/Grype scanning.
# Existing Task014 requires /usr/bin/python; keep that exact entrypoint path.
RUN set -eu; \
    test -x /usr/local/bin/python; \
    apk info -e sqlite-libs; \
    apk info -e .python-rundeps; \
    apk info -e zlib; \
    apk info -e apk-tools; \
    apk del --no-network .python-rundeps sqlite-libs zlib apk-tools; \
    test -s /lib/apk/db/installed; \
    if grep -qx 'P:sqlite-libs' /lib/apk/db/installed; then exit 1; fi; \
    if grep -qx 'P:zlib' /lib/apk/db/installed; then exit 1; fi; \
    if grep -qx 'P:apk-tools' /lib/apk/db/installed; then exit 1; fi; \
    find /usr/local/lib/python3.14 \( -iname '*sqlite*' -o -iname '*zlib*' \) -exec rm -rf {} +; \
    test -z "$(find /usr/local/lib /usr/lib \( -iname '*sqlite*' -o -iname '*zlib*' \) -print -quit)"; \
    test -e /lib/ld-musl-x86_64.so.1; \
    ln -s /usr/local/bin/python /usr/bin/python; \
    /usr/bin/python -c 'import fcntl,hashlib,http.server,json,socket,threading; import importlib.util; assert importlib.util.find_spec("zlib") is None'; \
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
