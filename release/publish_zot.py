#!/usr/bin/env python3
"""Publish a prebuilt OCI archive to the reviewed zot origin without rebuilding."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    from .verify_handoff import verify
    from .vulnerability_policy import canonical_bytes
except ImportError:
    from verify_handoff import verify
    from vulnerability_policy import canonical_bytes

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise RuntimeError("registry redirect refused")


class Client:
    def __init__(self, origin: str, token: str, repository: str):
        parsed = urllib.parse.urlsplit(origin)
        if parsed.scheme != "https" or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
            raise ValueError("registry origin is not a bare HTTPS origin")
        self.origin = origin.rstrip("/")
        self.authority = parsed.netloc
        self.repository = repository
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, method: str, path_or_url: str, data: bytes | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, Any, bytes]:
        url = path_or_url if path_or_url.startswith("https://") else self.origin + path_or_url
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != self.authority or parsed.username or parsed.password or parsed.fragment or "\\" in url or "\x00" in urllib.parse.unquote(parsed.path):
            raise ValueError("registry URL escaped the reviewed same-origin boundary")
        request_headers = {"Authorization": f"Bearer {self.token}"}
        request_headers.update(headers or {})
        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        try:
            with self.opener.open(request, timeout=60) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as exc:
            bounded = exc.read(4096).replace(self.token.encode(), b"[REDACTED]")
            return exc.code, exc.headers, bounded

    def upload_blob(self, digest_value: str, data: bytes) -> None:
        if f"sha256:{hashlib.sha256(data).hexdigest()}" != digest_value:
            raise ValueError("local blob digest mismatch")
        prefix = f"/v2/{self.repository}/blobs"
        status, _, body = self.request("HEAD", f"{prefix}/{digest_value}")
        if status == 200:
            return
        if status != 404:
            raise RuntimeError(f"blob HEAD returned HTTP {status}: {body[:256]!r}")
        status, headers, body = self.request("POST", f"{prefix}/uploads/", data=b"")
        if status != 202:
            raise RuntimeError(f"blob upload POST returned HTTP {status}: {body[:256]!r}")
        location = headers.get("Location")
        if not location:
            raise RuntimeError("blob upload response lacks Location")
        upload_url = urllib.parse.urljoin(self.origin, location)
        parsed = urllib.parse.urlsplit(upload_url)
        expected_prefix = f"/v2/{self.repository}/blobs/uploads/"
        decoded_path = urllib.parse.unquote(parsed.path)
        decoded_parts = decoded_path.split("/")
        if (parsed.scheme != "https" or parsed.netloc != self.authority
                or not parsed.path.startswith(expected_prefix)
                or not decoded_path.startswith(expected_prefix)
                or any(part in {".", ".."} for part in decoded_parts)
                or parsed.username or parsed.password or parsed.fragment
                or "\\" in location or "\\" in decoded_path or "\x00" in decoded_path):
            raise RuntimeError("unsafe blob upload Location")
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if any(key == "digest" for key, _ in query):
            raise RuntimeError("blob upload Location supplied an unexpected digest")
        query.append(("digest", digest_value))
        final_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                            urllib.parse.urlencode(query), ""))
        status, _, body = self.request("PUT", final_url, data=data,
                                       headers={"Content-Type": "application/octet-stream"})
        if status != 201:
            raise RuntimeError(f"blob upload PUT returned HTTP {status}: {body[:256]!r}")
        status, _, _ = self.request("HEAD", f"{prefix}/{digest_value}")
        if status != 200:
            raise RuntimeError("uploaded blob is not available")


def _load_token(path: Path) -> str:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o600 or not path.is_file() or path.is_symlink():
        raise ValueError("OIDC token file must be a regular mode-0600 file")
    try:
        token = path.read_text(encoding="utf-8")
    finally:
        path.unlink(missing_ok=True)
    if token.count(".") != 2 or "\n" in token:
        raise ValueError("OIDC token is malformed")
    return token


def publish(handoff: Path, token_file: Path, output: Path, repository_root: Path,
            version: str, source_sha: str) -> None:
    if output.exists() or output.is_symlink():
        raise ValueError("OCI publication output must be new")
    checked = verify(handoff, repository_root, version, source_sha, require_production_evidence=True)
    plan, build = checked["plan"], checked["build_manifest"]
    archive_path = handoff / plan["artifacts"]["oci_archive"]
    expected = build["expected_oci_manifest_digest"]
    if not DIGEST_RE.fullmatch(expected):
        raise ValueError("expected OCI digest is not exact sha256")
    with tarfile.open(archive_path, "r") as archive:
        index_member = archive.getmember("index.json")
        if not index_member.isfile():
            raise ValueError("OCI index is not a regular file")
        index = json.load(archive.extractfile(index_member))  # type: ignore[arg-type]
        descriptor = index["manifests"][0]
        if descriptor["digest"] != expected:
            raise ValueError("OCI index digest differs from handoff")
        manifest_member = archive.getmember(f"blobs/sha256/{expected.removeprefix('sha256:')}")
        manifest = archive.extractfile(manifest_member).read()  # type: ignore[union-attr]
        parsed_manifest = json.loads(manifest)
        blobs = [parsed_manifest["config"], *parsed_manifest["layers"]]
        blob_bytes = {}
        for blob in blobs:
            if not DIGEST_RE.fullmatch(blob["digest"]):
                raise ValueError("OCI descriptor digest is invalid")
            member = archive.getmember(f"blobs/sha256/{blob['digest'].removeprefix('sha256:')}")
            value = archive.extractfile(member).read()  # type: ignore[union-attr]
            if len(value) != blob["size"]:
                raise ValueError("OCI descriptor size mismatch")
            blob_bytes[blob["digest"]] = value
    token = _load_token(token_file)
    client = Client(plan["registries"]["zot_origin"], token, plan["packages"]["oci"]["repository"])
    status, _, _ = client.request("GET", "/v2/")
    if status != 200:
        raise RuntimeError(f"zot registry authentication returned HTTP {status}")
    manifest_path = f"/v2/{client.repository}/manifests/{version}"
    status, _, _ = client.request("HEAD", manifest_path,
                                  headers={"Accept": "application/vnd.oci.image.manifest.v1+json"})
    if status == 200:
        raise RuntimeError("immutable release tag already exists; overwrite refused")
    if status != 404:
        raise RuntimeError(f"pre-publication tag HEAD returned HTTP {status}")
    for digest_value, value in blob_bytes.items():
        client.upload_blob(digest_value, value)
    status, headers, body = client.request(
        "PUT", manifest_path, data=manifest,
        headers={"Content-Type": "application/vnd.oci.image.manifest.v1+json"},
    )
    if status != 201:
        raise RuntimeError(f"manifest PUT returned HTTP {status}: {body[:256]!r}")
    returned = headers.get("Docker-Content-Digest")
    if returned and returned != expected:
        raise RuntimeError("registry returned a different manifest digest")
    for reference in (version, expected):
        status, _, body = client.request(
            "GET", f"/v2/{client.repository}/manifests/{reference}",
            headers={"Accept": "application/vnd.oci.image.manifest.v1+json"},
        )
        if status != 200 or f"sha256:{hashlib.sha256(body).hexdigest()}" != expected:
            raise RuntimeError(f"immutable OCI verification failed for {reference}")
    output.write_bytes(canonical_bytes({
        "schema_version": 1, "registry": plan["registries"]["zot_origin"],
        "repository": client.repository, "tag": version, "manifest_digest": expected,
    }))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    publish(args.handoff, args.token_file, args.output, args.repository, args.version, args.source_sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
