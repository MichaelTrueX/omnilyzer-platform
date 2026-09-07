FROM cgr.dev/chainguard/python@sha256:bbdc4d1e20995d9bb9f9935188844c824b40969de4bb1f0eaadacda4c8d4121e

ARG RELEASE_VERSION
ARG SOURCE_SHA
ARG OCI_REPOSITORY

LABEL org.opencontainers.image.title="$OCI_REPOSITORY" \
      org.opencontainers.image.version="$RELEASE_VERSION" \
      org.opencontainers.image.revision="$SOURCE_SHA" \
      ai.omnilyzer.canary="true" \
      ai.omnilyzer.base.digest="sha256:bbdc4d1e20995d9bb9f9935188844c824b40969de4bb1f0eaadacda4c8d4121e"

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
