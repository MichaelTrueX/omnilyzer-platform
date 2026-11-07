FROM ghcr.io/astral-sh/uv@sha256:df6ea28f3caf5eb77ebae34d38e9b177b41a4e58ee963b1cbc5c8c1c92710238

# File: release/fixtures/task013-canary/oci/Dockerfile
# Purpose: Build the immutable Task013 nonroot Python Canary with patched
#          Alpine zlib 1.4-r0 instead of the pinned base's Critical 1.3.2-r1.
#          Retain actual installed package data for unchanged Syft/Grype checks.
# Related: release/executable_oci.py, release/tests/test_executable_canary.py,
#          .github/workflows/task013-canary-security-review.yml,
#          deployment/docker_runtime.py and Alpine v3.23 signed APK repository.
#
# Section 1: Import the reviewed, sha256-pinned upstream signed Alpine package.
# This build INPUT is checksum-locked before use. Unlike Docker RUN, BuildKit
# may fetch this exact HTTPS URL; its bytes must match the review-time digest.
# Alpine apk itself additionally verifies the vendor's normal signing keys.
# The original Astral base digest and upstream GHCR attestation are unchanged.
ADD --checksum=sha256:22ff5ae6b704ac1786d6565dcb3f5dde489e44a5038297a565382b76f656ee08 \
    https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/zlib-1.4-r0.apk \
    /tmp/zlib-1.4-r0.apk

# Section 2: Offline verified APK upgrade; remove genuinely unused SQLite.
# CRITICAL CVE-2026-4738 affects zlib 1.3.2-r1. zlib cannot be deleted: the
# CPython binascii extension needed by http.server links to libz.so.1.
# Upgrade to the vendor-signed, ABI-compatible fixed 1.4-r0 for Alpine 3.23.
# Never remove/alter APK package metadata to hide a Grype finding.
RUN set -eu; \
    test -x /usr/local/bin/python; \
    apk info -e sqlite-libs; \
    apk info -e .python-rundeps; \
    apk info -e zlib; \
    apk add --no-network /tmp/zlib-1.4-r0.apk; \
    apk del --no-network .python-rundeps sqlite-libs; \
    test -s /lib/apk/db/installed; \
    if grep -qx 'P:sqlite-libs' /lib/apk/db/installed; then exit 1; fi; \
    test "$(grep -xc 'P:zlib' /lib/apk/db/installed)" = 1; \
    grep -A1 -x 'P:zlib' /lib/apk/db/installed | grep -qx 'V:1.4-r0'; \
    find /usr/local/lib/python3.14 -iname '*sqlite*' -exec rm -rf {} +; \
    test -z "$(find /usr/local/lib /usr/lib -iname '*sqlite*' -print -quit)"; \
    test -e /lib/ld-musl-x86_64.so.1; \
    ln -s /usr/local/bin/python /usr/bin/python; \
    /usr/bin/python -c 'import fcntl,binascii,hashlib,http.server,json,socket,threading,zlib; assert zlib.ZLIB_RUNTIME_VERSION.startswith("1.4")'; \
    rm -f /tmp/zlib-1.4-r0.apk /sbin/apk /bin/sh /bin/busybox

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
