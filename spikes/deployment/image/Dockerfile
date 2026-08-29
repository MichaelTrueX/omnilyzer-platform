ARG PYTHON_IMAGE=docker.io/library/python:3.12-slim@sha256:09f7da3bc104798d0afb40bc08d23ab2da20a76130cec1f2ef170848f5d85217
FROM ${PYTHON_IMAGE}
ARG RELEASE
ARG SOURCE_REVISION
LABEL org.opencontainers.image.title="Omnilyzer deployment fixture" \
      org.opencontainers.image.version="${RELEASE}" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid 10001 --no-create-home app
COPY image/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --requirement /app/requirements.txt
COPY image/server.py image/migrate.py /app/
COPY releases/${RELEASE}/release.json /app/release.json
COPY releases/${RELEASE}/migrations/ /app/migrations/
RUN python -c "from pathlib import Path; p=Path('/app/release.json'); p.write_text(p.read_text().replace('SOURCE_REVISION', '${SOURCE_REVISION}'))"
RUN chown -R 10001:10001 /app
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=2s --retries=12 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/livez', timeout=1)"]
ENTRYPOINT ["python", "/app/server.py"]
