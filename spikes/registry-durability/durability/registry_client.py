"""Strict local-only OCI Distribution API client for Task 012A."""

from __future__ import annotations

import hashlib
from http.client import HTTPMessage
from urllib.error import HTTPError
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .fixture import MANIFEST_MEDIA_TYPE, REPOSITORY, Release, sha256_digest


ERROR_LIMIT = 512


class NoRedirect(HTTPRedirectHandler):
    """Reject redirects so requests never leave the isolated loopback origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class RegistryClient:
    """Unauthenticated client confined to one explicit HTTP loopback port."""

    def __init__(self, base_url: str) -> None:
        parsed = urlparse(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.port is None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("Task 012 registry must be an exact HTTP 127.0.0.1 origin")
        self.base_url = base_url.rstrip("/")
        self.origin = (parsed.scheme, parsed.hostname, parsed.port)
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def _confined_url(self, path_or_url: str) -> str:
        url = urljoin(self.base_url + "/", path_or_url)
        parsed = urlparse(url)
        if (
            (parsed.scheme, parsed.hostname, parsed.port) != self.origin
            or parsed.username
            or parsed.password
            or parsed.fragment
        ):
            raise RuntimeError("registry request escaped the isolated loopback origin")
        return url

    def request(
        self,
        method: str,
        path_or_url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        expected: set[int] | None = None,
        timeout: float = 10,
    ) -> tuple[int, bytes, HTTPMessage]:
        request = Request(
            self._confined_url(path_or_url),
            data=body,
            method=method,
            headers=headers or {},
        )
        try:
            response = self.opener.open(request, timeout=timeout)
            status, data, response_headers = response.status, response.read(), response.headers
        except HTTPError as error:
            status = error.code
            data = error.read(ERROR_LIMIT + 1)[:ERROR_LIMIT]
            response_headers = error.headers
        if expected is not None and status not in expected:
            detail = data.decode("utf-8", "replace").replace("\r", " ").replace("\n", " ")
            raise RuntimeError(
                f"{method} {urlparse(self._confined_url(path_or_url)).path} "
                f"returned HTTP {status}: {detail[:ERROR_LIMIT]}"
            )
        return status, data, response_headers

    def ping(self) -> None:
        self.request("GET", "/v2/", expected={200})

    def _upload_url(self, location: str, digest: str) -> str:
        if not location or "\\" in location or "\x00" in unquote(location):
            raise RuntimeError("blob upload Location contains unsafe characters")
        supplied = urlparse(location)
        decoded_path = unquote(supplied.path)
        if any(part in (".", "..") for part in decoded_path.split("/")):
            raise RuntimeError("blob upload Location contains path traversal")
        url = self._confined_url(location)
        parsed = urlparse(url)
        expected_prefix = f"/v2/{REPOSITORY}/blobs/uploads/"
        if not parsed.path.startswith(expected_prefix):
            raise RuntimeError("blob upload Location is outside the expected upload route")
        if any(part in ("", ".", "..") for part in unquote(parsed.path).split("/")[1:]):
            raise RuntimeError("blob upload Location path is not canonical")
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if any(key == "digest" for key, _ in query):
            raise RuntimeError("blob upload Location supplied an unexpected digest")
        query.append(("digest", digest))
        return parsed._replace(query=urlencode(query)).geturl()

    def ensure_blob(self, digest: str, content: bytes) -> None:
        path = f"/v2/{REPOSITORY}/blobs/{digest}"
        status, _, _ = self.request("HEAD", path)
        if status == 404:
            _, _, headers = self.request(
                "POST", f"/v2/{REPOSITORY}/blobs/uploads/", body=b"", expected={202}
            )
            target = self._upload_url(headers.get("Location", ""), digest)
            self.request(
                "PUT",
                target,
                body=content,
                headers={"Content-Type": "application/octet-stream"},
                expected={201},
            )
        elif status != 200:
            raise RuntimeError(f"HEAD blob returned HTTP {status}")
        _, observed, _ = self.request("GET", path, expected={200})
        if observed != content or sha256_digest(observed) != digest:
            raise RuntimeError(f"blob {digest} failed exact verification")

    def publish(self, release: Release) -> None:
        self.ensure_blob(release.config_digest, release.config)
        self.ensure_blob(release.layer_digest, release.layer)
        _, _, headers = self.request(
            "PUT",
            f"/v2/{REPOSITORY}/manifests/{quote(release.tag, safe='')}",
            body=release.manifest,
            headers={"Content-Type": MANIFEST_MEDIA_TYPE},
            expected={201},
        )
        returned = headers.get("Docker-Content-Digest")
        if returned is not None and returned != release.manifest_digest:
            raise RuntimeError("registry manifest digest disagrees with local bytes")

    def _manifest(self, reference: str) -> bytes:
        _, data, headers = self.request(
            "GET",
            f"/v2/{REPOSITORY}/manifests/{quote(reference, safe=':')}",
            headers={"Accept": MANIFEST_MEDIA_TYPE},
            expected={200},
        )
        returned = headers.get("Docker-Content-Digest")
        calculated = sha256_digest(data)
        if returned is not None and returned != calculated:
            raise RuntimeError("manifest response digest header disagrees with bytes")
        return data

    def verify_release(self, release: Release) -> dict[str, bool]:
        by_tag = self._manifest(release.tag)
        by_digest = self._manifest(release.manifest_digest)
        if by_tag != release.manifest or by_digest != release.manifest:
            raise RuntimeError(f"{release.name} manifest bytes changed")
        if sha256_digest(by_tag) != release.manifest_digest:
            raise RuntimeError(f"{release.name} manifest digest changed")
        checks: dict[str, bool] = {
            "tag": True,
            "manifest_by_tag": True,
            "manifest_by_digest": True,
        }
        for kind in ("config", "layer"):
            expected = getattr(release, kind)
            digest = getattr(release, f"{kind}_digest")
            _, observed, _ = self.request(
                "GET", f"/v2/{REPOSITORY}/blobs/{digest}", expected={200}
            )
            if observed != expected or hashlib.sha256(observed).hexdigest() != digest.removeprefix("sha256:"):
                raise RuntimeError(f"{release.name} {kind} bytes changed")
            checks[kind] = True
        return checks
