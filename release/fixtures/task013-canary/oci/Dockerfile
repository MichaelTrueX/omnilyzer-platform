FROM cgr.dev/chainguard/python@sha256:549f3ba5e588ebab80dcf5a5a3536aa7f4b5c384bc6955c0347d372414197386

ARG RELEASE_VERSION
ARG SOURCE_SHA
ARG OCI_REPOSITORY

LABEL org.opencontainers.image.title="$OCI_REPOSITORY" \
      org.opencontainers.image.version="$RELEASE_VERSION" \
      org.opencontainers.image.revision="$SOURCE_SHA" \
      ai.omnilyzer.canary="true" \
      ai.omnilyzer.base.digest="sha256:549f3ba5e588ebab80dcf5a5a3536aa7f4b5c384bc6955c0347d372414197386"

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
