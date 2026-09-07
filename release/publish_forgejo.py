#!/usr/bin/env python3
"""Publish prebuilt Python/npm artifacts and signed evidence to Forgejo."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

try:
    from .verify_handoff import verify
    from .vulnerability_policy import canonical_bytes
except ImportError:
    from verify_handoff import verify
    from vulnerability_policy import canonical_bytes


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise RuntimeError("Forgejo redirect refused")


def _token(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError("OIDC token file must be a regular mode-0600 file")
    try:
        value = path.read_text(encoding="utf-8")
    finally:
        path.unlink(missing_ok=True)
    if value.count(".") != 2 or "\n" in value:
        raise ValueError("OIDC token is malformed")
    return value


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            for key, value in attrs:
                if key.lower() == "href" and value is not None:
                    self.hrefs.append(value)


def _validated_pypi_download_url(origin: str, advertised_url: str, owner: str,
                                  package: str, version: str, wheel_filename: str,
                                  expected_sha256: str) -> str:
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ValueError("expected PyPI wheel SHA-256 is malformed")
    parsed = urllib.parse.urlsplit(advertised_url)
    expected_origin = urllib.parse.urlsplit(origin)
    try:
        unexpected_port = parsed.port != expected_origin.port
    except ValueError as exc:
        raise ValueError("PyPI wheel link has an invalid port") from exc
    expected_path = (
        f"/api/packages/{urllib.parse.quote(owner, safe='')}/pypi/files/"
        f"{urllib.parse.quote(package, safe='-')}/{urllib.parse.quote(version, safe='')}/"
        f"{urllib.parse.quote(wheel_filename, safe='')}"
    )
    if (parsed.scheme != "https" or parsed.netloc != expected_origin.netloc
            or parsed.username or parsed.password or unexpected_port or parsed.query
            or "\\" in advertised_url or "\x00" in urllib.parse.unquote(parsed.path)
            or parsed.path != expected_path):
        raise ValueError("PyPI wheel link escaped the expected Forgejo route")
    if parsed.fragment != f"sha256={expected_sha256}":
        raise ValueError("PyPI wheel link has an invalid SHA-256 fragment")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _request(origin: str, token: str, method: str, path_or_url: str, body: bytes = b"",
             content_type: str | None = None) -> tuple[int, bytes]:
    url = path_or_url if path_or_url.startswith("https://") else origin.rstrip("/") + path_or_url
    parsed = urllib.parse.urlsplit(url)
    expected = urllib.parse.urlsplit(origin)
    if (parsed.scheme != "https" or parsed.netloc != expected.netloc or parsed.username
            or parsed.password or parsed.fragment or "\\" in url
            or "\x00" in urllib.parse.unquote(parsed.path)):
        raise ValueError("Forgejo request escaped the reviewed origin")
    headers = {"Authorization": f"Bearer {token}"}
    if content_type is not None:
        headers.update({"Content-Type": content_type, "Content-Length": str(len(body))})
    req = urllib.request.Request(
        url, data=body if method in {"POST", "PUT"} else None, method=method, headers=headers,
    )
    try:
        with urllib.request.build_opener(NoRedirect).open(req, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read(512).decode("utf-8", "replace").replace(token, "[REDACTED]")
        safe_target = parsed.path.replace(token, "[REDACTED]")[:256]
        raise RuntimeError(
            f"Forgejo {method} {safe_target} returned HTTP {exc.code}: {detail}"
        ) from exc


def _multipart(filename: str, payload: bytes, fields: dict[str, str]) -> tuple[bytes, str]:
    boundary = "omnilyzer-task013-fixed-boundary"
    parts = []
    for key, value in sorted(fields.items()):
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n".encode()
        )
    parts.append((
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"content\"; "
        f"filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
    ).encode() + payload + f"\r\n--{boundary}--\r\n".encode())
    body = b"".join(parts)
    return body, f"multipart/form-data; boundary={boundary}"


def _pypi_multipart(filename: str, payload: bytes, name: str, version: str) -> tuple[bytes, str]:
    return _multipart(filename, payload, {
        ":action": "file_upload", "protocol_version": "1", "metadata_version": "2.3",
        "name": name, "version": version, "filetype": "bdist_wheel", "pyversion": "py3",
        "sha256_digest": hashlib.sha256(payload).hexdigest(),
    })


def _evidence_archive(handoff: Path, evidence: Path, plan: dict) -> bytes:
    allowed = {
        "release-manifest.json", "release-provenance.json",
        "release-manifest.sigstore.json", "release-provenance.sigstore.json",
    }
    if {path.name for path in evidence.iterdir()} != allowed:
        raise ValueError("release evidence file set differs from its exact allowlist")
    distributables = {
        plan["artifacts"]["python_wheel"], plan["artifacts"]["npm_tarball"],
        plan["artifacts"]["oci_archive"],
    }
    paths = [path for path in handoff.iterdir() if path.name not in distributables]
    paths.extend(evidence / name for name in sorted(allowed))
    if any(not path.is_file() or path.is_symlink() for path in paths):
        raise ValueError("signed release evidence is incomplete")
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(paths, key=lambda item: item.name):
            data = path.read_bytes()
            info = tarfile.TarInfo(path.name)
            info.size, info.mode, info.mtime = len(data), 0o600, 946684800
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=compressed, mode="wb", mtime=0) as stream:
        stream.write(raw.getvalue())
    return compressed.getvalue()


def publish(handoff: Path, evidence: Path, token_file: Path, repository: Path,
            version: str, source_sha: str) -> None:
    checked = verify(handoff, repository, version, source_sha, require_production_evidence=True)
    plan = checked["plan"]
    origin = plan["registries"]["forgejo_origin"]
    token = _token(token_file)
    owner = urllib.parse.quote(plan["packages"]["python"]["owner"], safe="")

    wheel_path = handoff / plan["artifacts"]["python_wheel"]
    wheel_bytes = wheel_path.read_bytes()
    body, content_type = _pypi_multipart(
        wheel_path.name, wheel_bytes, plan["packages"]["python"]["name"], version,
    )
    if _request(origin, token, "POST", f"/api/packages/{owner}/pypi", body, content_type)[0] != 201:
        raise RuntimeError("Forgejo PyPI publication did not return HTTP 201")
    normalized_python = plan["packages"]["python"]["name"].lower().replace("_", "-")
    simple_path = f"/api/packages/{owner}/pypi/simple/{urllib.parse.quote(normalized_python, safe='-')}/"
    status, simple_body = _request(origin, token, "GET", simple_path)
    if status != 200:
        raise RuntimeError("Forgejo PyPI Simple API did not return HTTP 200")
    parser = _Links()
    parser.feed(simple_body.decode("utf-8", "strict"))
    wheel_urls = [urllib.parse.urljoin(origin + simple_path, href) for href in parser.hrefs
                  if Path(urllib.parse.urlsplit(href).path).name == wheel_path.name]
    if len(wheel_urls) != 1:
        raise RuntimeError("Forgejo PyPI Simple API did not expose exactly one built wheel")
    expected_wheel_sha256 = hashlib.sha256(wheel_bytes).hexdigest()
    wheel_download_url = _validated_pypi_download_url(
        origin, wheel_urls[0], plan["packages"]["python"]["owner"], normalized_python,
        version, wheel_path.name, expected_wheel_sha256,
    )
    status, downloaded_wheel = _request(origin, token, "GET", wheel_download_url)
    if (status != 200 or downloaded_wheel != wheel_bytes
            or hashlib.sha256(downloaded_wheel).hexdigest() != expected_wheel_sha256):
        raise RuntimeError("Forgejo PyPI round-trip bytes differ from the immutable handoff")

    npm_path = handoff / plan["artifacts"]["npm_tarball"]
    npm_raw = npm_path.read_bytes()
    npm_name = plan["packages"]["npm"]["name"]
    npm_document = {
        "_id": npm_name, "name": npm_name,
        "dist-tags": {"latest": version},
        "versions": {version: {"name": npm_name, "version": version,
                               "dist": {
                                   "shasum": hashlib.sha1(npm_raw).hexdigest(),
                                   "integrity": "sha512-" + base64.b64encode(
                                       hashlib.sha512(npm_raw).digest()).decode(),
                               }}},
        "_attachments": {npm_path.name: {"content_type": "application/octet-stream",
                                         "data": base64.b64encode(npm_raw).decode(),
                                         "length": len(npm_raw)}},
    }
    npm_package = urllib.parse.quote(npm_name, safe="")
    npm_endpoint = f"/api/packages/{owner}/npm/{npm_package}"
    if _request(origin, token, "PUT", npm_endpoint,
                canonical_bytes(npm_document), "application/json")[0] != 201:
        raise RuntimeError("Forgejo npm publication did not return HTTP 201")
    status, metadata_raw = _request(origin, token, "GET", npm_endpoint)
    if status != 200:
        raise RuntimeError("Forgejo npm metadata retrieval did not return HTTP 200")
    metadata = json.loads(metadata_raw)
    tarball_url = metadata.get("versions", {}).get(version, {}).get("dist", {}).get("tarball")
    if not isinstance(tarball_url, str):
        raise RuntimeError("Forgejo npm metadata lacks the exact version tarball URL")
    parsed_tarball = urllib.parse.urlsplit(tarball_url)
    if not parsed_tarball.path.startswith(f"/api/packages/{owner}/npm/"):
        raise RuntimeError("Forgejo npm tarball escaped the reviewed package API path")
    status, downloaded_npm = _request(origin, token, "GET", tarball_url)
    if status != 200 or downloaded_npm != npm_raw:
        raise RuntimeError("Forgejo npm round-trip bytes differ from the immutable handoff")

    archive = _evidence_archive(handoff, evidence, plan)
    evidence_package = urllib.parse.quote(plan["packages"]["evidence"]["name"], safe="")
    generic_path = f"/api/packages/{owner}/generic/{evidence_package}/{version}/release-evidence.tar.gz"
    if _request(origin, token, "PUT", generic_path, archive, "application/gzip")[0] != 201:
        raise RuntimeError("Forgejo Generic evidence publication did not return HTTP 201")
    status, downloaded_evidence = _request(origin, token, "GET", generic_path)
    if status != 200 or downloaded_evidence != archive:
        raise RuntimeError("Forgejo Generic evidence round-trip bytes differ from publication")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    publish(args.handoff, args.evidence, args.token_file, args.repository, args.version, args.source_sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
