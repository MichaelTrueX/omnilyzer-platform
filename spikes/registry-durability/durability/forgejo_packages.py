"""Deterministic Generic, PyPI, and npm fixtures and Forgejo API client."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import gzip
from html.parser import HTMLParser
import hashlib
import io
import json
import tarfile
from urllib.error import HTTPError
from urllib.parse import quote, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import zipfile


OWNER = "task012b"
GENERIC_NAME = "durability-generic"
VERSION = "1.0.0"
WHEEL_NAME = "task012b_fixture-1.0.0-py3-none-any.whl"
PYPI_NAME = "task012b-fixture"
NPM_NAME = "@task012b/fixture"


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class PackageFixtures:
    generic: bytes
    wheel: bytes
    npm: bytes

    def evidence(self) -> dict[str, dict[str, object]]:
        return {
            "Generic": {"sha256": _sha256(self.generic), "length": len(self.generic)},
            "PyPI": {"sha256": _sha256(self.wheel), "length": len(self.wheel)},
            "npm": {"sha256": _sha256(self.npm), "length": len(self.npm)},
        }


def _zip_entry(name: str, content: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o100444 << 16
    return info, content


def _wheel() -> bytes:
    metadata = (
        "Metadata-Version: 2.1\n"
        "Name: task012b-fixture\n"
        "Version: 1.0.0\n"
        "Summary: Harmless Task 012B synthetic package\n\n"
    ).encode()
    wheel = b"Wheel-Version: 1.0\nGenerator: task012b\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    marker = b"TASK 012B SYNTHETIC PACKAGE - DO NOT EXECUTE\n"
    record = (
        "task012b_fixture/__init__.py,,\n"
        "task012b_fixture-1.0.0.dist-info/METADATA,,\n"
        "task012b_fixture-1.0.0.dist-info/WHEEL,,\n"
        "task012b_fixture-1.0.0.dist-info/RECORD,,\n"
    ).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w") as archive:
        for info, content in (
            _zip_entry("task012b_fixture/__init__.py", marker),
            _zip_entry("task012b_fixture-1.0.0.dist-info/METADATA", metadata),
            _zip_entry("task012b_fixture-1.0.0.dist-info/WHEEL", wheel),
            _zip_entry("task012b_fixture-1.0.0.dist-info/RECORD", record),
        ):
            archive.writestr(info, content)
    return buffer.getvalue()


def _npm_tarball() -> bytes:
    entries = {
        "package/package.json": json.dumps({
            "name": NPM_NAME,
            "version": VERSION,
            "description": "Harmless Task 012B synthetic package",
            "files": ["README.md"],
        }, sort_keys=True, separators=(",", ":")).encode() + b"\n",
        "package/README.md": b"TASK 012B SYNTHETIC PACKAGE - DO NOT EXECUTE\n",
    }
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, content in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mode = 0o444
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ""
            archive.addfile(member, io.BytesIO(content))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=compressed, mode="wb", mtime=0) as stream:
        stream.write(tar_buffer.getvalue())
    return compressed.getvalue()


def build_packages() -> PackageFixtures:
    return PackageFixtures(
        generic=b"TASK 012B GENERIC SYNTHETIC ARTIFACT\nversion=1.0.0\n",
        wheel=_wheel(),
        npm=_npm_tarball(),
    )


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            for key, value in attrs:
                if key == "href" and value is not None:
                    self.hrefs.append(value)


class ForgejoPackageClient:
    def __init__(self, base_url: str, token: str) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None:
            raise RuntimeError("Forgejo client requires an explicit loopback origin")
        self.base = base_url.rstrip("/")
        self.origin = (parsed.scheme, parsed.hostname, parsed.port)
        self.token = token
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def _url(self, path_or_url: str) -> str:
        url = urljoin(self.base + "/", path_or_url)
        parsed = urlparse(url)
        if (
            (parsed.scheme, parsed.hostname, parsed.port) != self.origin
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise RuntimeError("package URL escaped the isolated Forgejo origin")
        return url

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        expected: set[int] = frozenset({200}),
    ) -> tuple[bytes, object]:
        request_headers = {"Authorization": f"token {self.token}"}
        request_headers.update(headers or {})
        request = Request(self._url(path_or_url), data=body, method=method, headers=request_headers)
        try:
            response = self.opener.open(request, timeout=20)
            status, data, response_headers = response.status, response.read(), response.headers
        except HTTPError as error:
            status, data, response_headers = error.code, error.read(512), error.headers
        if status not in expected:
            detail = data.decode("utf-8", "replace").replace(self.token, "[REDACTED]")
            raise RuntimeError(f"Forgejo package {method} returned HTTP {status}: {detail[:512]}")
        return data, response_headers

    def publish_generic(self, content: bytes) -> None:
        self.request(
            "PUT",
            f"/api/packages/{OWNER}/generic/{GENERIC_NAME}/{VERSION}/artifact.txt",
            body=content,
            headers={"Content-Type": "application/octet-stream"},
            expected={201},
        )

    def generic(self) -> bytes:
        return self.request(
            "GET", f"/api/packages/{OWNER}/generic/{GENERIC_NAME}/{VERSION}/artifact.txt"
        )[0]

    def publish_pypi(self, wheel: bytes) -> None:
        boundary = "task012b-fixed-multipart-boundary"
        fields = {
            ":action": "file_upload",
            "protocol_version": "1",
            "name": PYPI_NAME,
            "version": VERSION,
            "filetype": "bdist_wheel",
            "pyversion": "py3",
            "sha256_digest": _sha256(wheel),
        }
        parts = []
        for name, value in fields.items():
            parts.append(
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode()
            )
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"content\"; filename=\"{WHEEL_NAME}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n".encode() + wheel + b"\r\n"
        )
        parts.append(f"--{boundary}--\r\n".encode())
        self.request(
            "POST",
            f"/api/packages/{OWNER}/pypi",
            body=b"".join(parts),
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            expected={201},
        )

    def pypi(self) -> bytes:
        index, _ = self.request("GET", f"/api/packages/{OWNER}/pypi/simple/{PYPI_NAME}/")
        parser = _Links()
        parser.feed(index.decode("utf-8"))
        matches = [href for href in parser.hrefs if WHEEL_NAME in href]
        if len(matches) != 1:
            raise RuntimeError("PyPI simple index did not contain exactly one expected wheel")
        return self.request("GET", matches[0].split("#", 1)[0])[0]

    def publish_npm(self, tarball: bytes) -> None:
        encoded = quote(NPM_NAME, safe="")
        filename = "task012b-fixture-1.0.0.tgz"
        shasum = hashlib.sha1(tarball, usedforsecurity=False).hexdigest()
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode()
        version = {
            "name": NPM_NAME,
            "version": VERSION,
            "description": "Harmless Task 012B synthetic package",
            "dist": {
                "shasum": shasum,
                "integrity": integrity,
                "tarball": f"{self.base}/api/packages/{OWNER}/npm/{encoded}/-/{filename}",
            },
        }
        document = {
            "_id": NPM_NAME,
            "name": NPM_NAME,
            "dist-tags": {"latest": VERSION},
            "versions": {VERSION: version},
            "_attachments": {
                filename: {
                    "content_type": "application/octet-stream",
                    "data": base64.b64encode(tarball).decode(),
                    "length": len(tarball),
                }
            },
        }
        self.request(
            "PUT",
            f"/api/packages/{OWNER}/npm/{encoded}",
            body=json.dumps(document, separators=(",", ":")).encode(),
            headers={"Content-Type": "application/json"},
            expected={201},
        )

    def npm(self) -> bytes:
        encoded = quote(NPM_NAME, safe="")
        metadata, _ = self.request("GET", f"/api/packages/{OWNER}/npm/{encoded}")
        document = json.loads(metadata)
        if document.get("dist-tags", {}).get("latest") != VERSION:
            raise RuntimeError("npm metadata did not retain the expected version")
        tarball = document.get("versions", {}).get(VERSION, {}).get("dist", {}).get("tarball")
        if not isinstance(tarball, str):
            raise RuntimeError("npm metadata did not contain a tarball URL")
        return self.request("GET", tarball)[0]

    def verify(self, fixtures: PackageFixtures) -> dict[str, bool]:
        observed = {
            "Generic": self.generic(),
            "PyPI": self.pypi(),
            "npm": self.npm(),
        }
        expected = {"Generic": fixtures.generic, "PyPI": fixtures.wheel, "npm": fixtures.npm}
        result = {}
        for name in expected:
            if observed[name] != expected[name] or _sha256(observed[name]) != _sha256(expected[name]):
                raise RuntimeError(f"{name} package bytes changed")
            result[name] = True
        return result
