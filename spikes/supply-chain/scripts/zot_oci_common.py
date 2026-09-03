#!/usr/bin/env python3
"""Deterministic OCI fixture and hardened zot Distribution API primitives."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
from typing import Any
from urllib.error import HTTPError
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_TYPE = "application/vnd.oci.image.config.v1+json"
LAYER_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
REPOSITORY = "omnilyzer/task008d-supply-chain-spike"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
TAG_RE = re.compile(r"task008d-[0-9]+-[0-9]+")
ERROR_LIMIT = 512
FILES = {
    "handoff.json", "baseline.config.json", "baseline.layer.tar.gz",
    "baseline.manifest.json", "replacement.config.json",
    "replacement.layer.tar.gz", "replacement.manifest.json",
}


class NoRedirect(HTTPRedirectHandler):
    """Never forward an Authorization header through an implicit redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def make_variant(marker: str, version: str) -> dict[str, Any]:
    payload = f"version={version}\nmarker={marker}\n".encode()
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo("artifact.txt")
        info.size, info.mode, info.mtime = len(payload), 0o644, 0
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        archive.addfile(info, io.BytesIO(payload))
    tar_bytes = tar_buffer.getvalue()
    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=gzip_buffer, mode="wb", mtime=0) as stream:
        stream.write(tar_bytes)
    layer = gzip_buffer.getvalue()
    config = canonical_json({
        "architecture": "amd64",
        "config": {"Labels": {
            "org.opencontainers.image.version": version,
            "task008d.marker": marker,
        }},
        "created": "1970-01-01T00:00:00Z",
        "history": [{
            "created": "1970-01-01T00:00:00Z",
            "created_by": "Task 008D deterministic fixture",
        }],
        "os": "linux",
        "rootfs": {"diff_ids": [digest(tar_bytes)], "type": "layers"},
    })
    manifest = canonical_json({
        "schemaVersion": 2,
        "mediaType": MANIFEST_TYPE,
        "config": {"mediaType": CONFIG_TYPE, "digest": digest(config), "size": len(config)},
        "layers": [{"mediaType": LAYER_TYPE, "digest": digest(layer), "size": len(layer)}],
    })
    return {"config": config, "layer": layer, "manifest": manifest,
            "config_digest": digest(config), "layer_digest": digest(layer),
            "manifest_digest": digest(manifest), "layer_diff_id": digest(tar_bytes)}


def build_handoff(path: Path, source_commit: str, tag: str) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None or TAG_RE.fullmatch(tag) is None:
        raise RuntimeError("source commit or tag is malformed")
    path.mkdir(parents=True, exist_ok=False)
    record: dict[str, Any] = {
        "repository": REPOSITORY, "tag": tag, "version": tag,
        "media_type": MANIFEST_TYPE, "source_commit": source_commit,
    }
    for marker in ("baseline", "replacement"):
        variant = make_variant(marker, tag)
        filenames = {
            "config_filename": f"{marker}.config.json",
            "layer_filename": f"{marker}.layer.tar.gz",
            "manifest_filename": f"{marker}.manifest.json",
        }
        for kind in ("config", "layer", "manifest"):
            (path / filenames[f"{kind}_filename"]).write_bytes(variant[kind])
        record[marker] = {
            **filenames, "marker": marker,
            "config_digest": variant["config_digest"],
            "layer_digest": variant["layer_digest"],
            "layer_diff_id": variant["layer_diff_id"],
            "manifest_digest": variant["manifest_digest"],
        }
    if record["baseline"]["manifest_digest"] == record["replacement"]["manifest_digest"]:
        raise RuntimeError("fixture manifests are unexpectedly identical")
    (path / "handoff.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeError(f"{label} fields are not exact")
    return value


def validate_handoff(path: Path, source_commit: str, tag: str) -> dict[str, Any]:
    root = path.resolve(strict=True)
    entries = list(root.iterdir())
    if {entry.name for entry in entries} != FILES or any(
        not entry.is_file() or entry.is_symlink() for entry in entries
    ):
        raise RuntimeError("handoff file set is not exact")
    record = _exact(json.loads((root / "handoff.json").read_text()), {
        "repository", "tag", "version", "media_type", "source_commit",
        "baseline", "replacement",
    }, "handoff")
    if record["repository"] != REPOSITORY or record["tag"] != tag or record["version"] != tag:
        raise RuntimeError("handoff repository/tag/version is unexpected")
    if record["source_commit"] != source_commit or record["media_type"] != MANIFEST_TYPE:
        raise RuntimeError("handoff source or media type is unexpected")
    for marker in ("baseline", "replacement"):
        item = _exact(record[marker], {
            "marker", "config_filename", "layer_filename", "manifest_filename",
            "config_digest", "layer_digest", "layer_diff_id", "manifest_digest",
        }, marker)
        if item["marker"] != marker:
            raise RuntimeError(f"{marker} identity is unexpected")
        blobs: dict[str, bytes] = {}
        for kind, suffix in (("config", "config.json"), ("layer", "layer.tar.gz"),
                             ("manifest", "manifest.json")):
            if item[f"{kind}_filename"] != f"{marker}.{suffix}":
                raise RuntimeError(f"{marker} filename is unexpected")
            blobs[kind] = (root / item[f"{kind}_filename"]).read_bytes()
            if digest(blobs[kind]) != item[f"{kind}_digest"]:
                raise RuntimeError(f"{marker} {kind} digest mismatch")
        manifest = json.loads(blobs["manifest"])
        config = json.loads(blobs["config"])
        if manifest != {
            "schemaVersion": 2, "mediaType": MANIFEST_TYPE,
            "config": {"mediaType": CONFIG_TYPE, "digest": item["config_digest"],
                       "size": len(blobs["config"])},
            "layers": [{"mediaType": LAYER_TYPE, "digest": item["layer_digest"],
                        "size": len(blobs["layer"])}],
        }:
            raise RuntimeError(f"{marker} manifest descriptors are unexpected")
        labels = config.get("config", {}).get("Labels", {})
        if labels != {"org.opencontainers.image.version": tag, "task008d.marker": marker}:
            raise RuntimeError(f"{marker} labels are unexpected")
        tar_bytes = gzip.decompress(blobs["layer"])
        if digest(tar_bytes) != item["layer_diff_id"]:
            raise RuntimeError(f"{marker} diff ID mismatch")
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            members = archive.getmembers()
            content = archive.extractfile(members[0]) if len(members) == 1 else None
            if len(members) != 1 or members[0].name != "artifact.txt" or content is None:
                raise RuntimeError(f"{marker} layer contents are unexpected")
            if content.read() != f"version={tag}\nmarker={marker}\n".encode():
                raise RuntimeError(f"{marker} layer payload is unexpected")
        item["bytes"] = blobs
    if record["baseline"]["manifest_digest"] == record["replacement"]["manifest_digest"]:
        raise RuntimeError("fixture manifests are identical")
    return record


class RegistryClient:
    """A direct Bearer client confined to one HTTPS origin with no redirects."""

    def __init__(self, registry: str, token_file: Path) -> None:
        parsed = urlparse(registry)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/")
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            raise RuntimeError("registry must be an exact HTTPS origin")
        self.base = registry.rstrip("/")
        self.origin = (parsed.scheme, parsed.hostname, parsed.port or 443)
        token_path = token_file.resolve(strict=True)
        self.token = token_path.read_text().strip()
        token_path.unlink()
        if not self.token:
            raise RuntimeError("OIDC token file is empty")
        self.opener = build_opener(NoRedirect())

    def request(self, method: str, path_or_url: str, *, body: bytes | None = None,
                headers: dict[str, str] | None = None, expected: set[int] | None = None):
        url = urljoin(self.base + "/", path_or_url)
        parsed = urlparse(url)
        if ((parsed.scheme, parsed.hostname, parsed.port or 443) != self.origin
                or parsed.username or parsed.password or parsed.fragment):
            raise RuntimeError("refusing to send bearer token outside registry origin")
        request_headers = {"Authorization": f"Bearer {self.token}"}
        request_headers.update(headers or {})
        request = Request(url, data=body, method=method, headers=request_headers)
        try:
            response = self.opener.open(request, timeout=60)
            status, data, response_headers = response.status, response.read(), response.headers
        except HTTPError as error:
            status, data, response_headers = error.code, error.read(ERROR_LIMIT + 1)[:ERROR_LIMIT], error.headers
        if expected is not None and status not in expected:
            detail = data.decode("utf-8", "replace").replace("\r", " ").replace("\n", " ")
            detail = detail.replace(self.token, "[REDACTED]")
            raise RuntimeError(f"{method} registry operation returned HTTP {status}: {detail[:ERROR_LIMIT]}")
        return status, data, response_headers

    def validate_upload_location(self, location: str, repository: str, blob_digest: str) -> str:
        decoded = unquote(location)
        if not location or "\\" in location or "\x00" in decoded:
            raise RuntimeError("upload Location contains unsafe characters")
        supplied_path = unquote(urlparse(location).path)
        if any(part in (".", "..") for part in supplied_path.split("/")):
            raise RuntimeError("upload Location contains path traversal")
        url = urljoin(self.base + "/", location)
        parsed = urlparse(url)
        if ((parsed.scheme, parsed.hostname, parsed.port or 443) != self.origin
                or parsed.username or parsed.password or parsed.fragment
                or not parsed.path.startswith(f"/v2/{repository}/blobs/uploads/")):
            raise RuntimeError("upload Location is outside the expected same-origin route")
        decoded_path = unquote(parsed.path)
        if any(part in ("", ".", "..") for part in decoded_path.split("/")[1:]):
            raise RuntimeError("upload Location path is not canonical")
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if any(key == "digest" for key, _ in query):
            raise RuntimeError("upload Location supplied an unexpected digest")
        query.append(("digest", blob_digest))
        return parsed._replace(query=urlencode(query)).geturl()

    def ensure_blob(self, repository: str, blob_digest: str, data: bytes) -> None:
        path = f"/v2/{repository}/blobs/{blob_digest}"
        status, _, _ = self.request("HEAD", path)
        if status == 404:
            status, _, headers = self.request(
                "POST", f"/v2/{repository}/blobs/uploads/", body=b"", expected={202}
            )
            location = self.validate_upload_location(headers.get("Location", ""), repository, blob_digest)
            self.request("PUT", location, body=data,
                         headers={"Content-Type": "application/octet-stream"}, expected={201})
        elif status != 200:
            raise RuntimeError(f"HEAD blob returned unexpected HTTP {status}")
        status, observed, _ = self.request("GET", path, expected={200})
        if digest(observed) != blob_digest or observed != data:
            raise RuntimeError("retrieved blob failed exact integrity verification")

    def manifest(self, repository: str, reference: str) -> tuple[bytes, Any]:
        _, data, headers = self.request(
            "GET", f"/v2/{repository}/manifests/{quote(reference, safe=':')}",
            headers={"Accept": MANIFEST_TYPE}, expected={200},
        )
        return data, headers


def verify_baseline(client: RegistryClient, record: dict[str, Any], *, by_tag: bool = True) -> None:
    baseline = record["baseline"]
    references = [record["tag"], baseline["manifest_digest"]] if by_tag else [baseline["manifest_digest"]]
    for reference in references:
        manifest, _ = client.manifest(record["repository"], reference)
        if manifest != baseline["bytes"]["manifest"] or digest(manifest) != baseline["manifest_digest"]:
            raise RuntimeError(f"manifest {reference} failed exact verification")
    for kind in ("config", "layer"):
        _, data, _ = client.request(
            "GET", f"/v2/{record['repository']}/blobs/{baseline[f'{kind}_digest']}", expected={200}
        )
        if data != baseline["bytes"][kind] or digest(data) != baseline[f"{kind}_digest"]:
            raise RuntimeError(f"baseline {kind} failed exact verification")
