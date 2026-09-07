FROM docker.io/library/python:3.12-slim@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217

ARG RELEASE_VERSION
ARG SOURCE_SHA
ARG OCI_REPOSITORY

RUN test -n "$RELEASE_VERSION" \
    && test -n "$SOURCE_SHA" \
    && test -n "$OCI_REPOSITORY"

LABEL org.opencontainers.image.title="$OCI_REPOSITORY" \
      org.opencontainers.image.version="$RELEASE_VERSION" \
      org.opencontainers.image.revision="$SOURCE_SHA" \
      ai.omnilyzer.canary="true" \
      ai.omnilyzer.base.digest="sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217"

ENV CANARY_RELEASE_VERSION="$RELEASE_VERSION" \
    CANARY_SOURCE_SHA="$SOURCE_SHA" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY --chown=10001:10001 canary_runtime.py migration.py migration-definition.json /app/

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["python3", "/app/canary_runtime.py"]
CMD []
