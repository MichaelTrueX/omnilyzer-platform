#!/usr/bin/env python3
"""Build, validate, and run the Task 008C direct-Bearer OCI probe."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tarfile
from typing import Any
from urllib.error import HTTPError
from urllib.parse import parse_qsl, quote, unquote, urlencode, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_TYPE = "application/vnd.oci.image.config.v1+json"
LAYER_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
REPOSITORY = "omnilyzer/task008c-supply-chain-spike"
FILES = {
    "handoff.json", "baseline.config.json", "baseline.layer.tar.gz",
    "baseline.manifest.json", "replacement.config.json",
    "replacement.layer.tar.gz", "replacement.manifest.json",
}
ERROR_BODY_LIMIT = 512


class NoRedirect(HTTPRedirectHandler):
    """Prevent implicit credential forwarding across redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def make_variant(marker: str, version: str) -> dict[str, Any]:
    payload = f"version={version}\nmarker={marker}\n".encode()
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        entry = tarfile.TarInfo("artifact.txt")
        entry.size, entry.mode, entry.mtime = len(payload), 0o644, 0
        entry.uid = entry.gid = 0
        entry.uname = entry.gname = ""
        archive.addfile(entry, io.BytesIO(payload))
    tar_bytes = tar_buffer.getvalue()
    gzip_buffer = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=gzip_buffer, mtime=0, compresslevel=9
    ) as stream:
        stream.write(tar_bytes)
    layer = gzip_buffer.getvalue()
    config = canonical_json({
        "architecture": "amd64",
        "config": {"Labels": {
            "org.opencontainers.image.version": version,
            "task008c.marker": marker,
        }},
        "created": "1970-01-01T00:00:00Z",
        "history": [{
            "created": "1970-01-01T00:00:00Z",
            "created_by": "Task 008C deterministic fixture",
        }],
        "os": "linux",
        "rootfs": {"diff_ids": [digest(tar_bytes)], "type": "layers"},
    })
    manifest = canonical_json({
        "config": {"digest": digest(config), "mediaType": CONFIG_TYPE, "size": len(config)},
        "layers": [{"digest": digest(layer), "mediaType": LAYER_TYPE, "size": len(layer)}],
        "mediaType": MANIFEST_TYPE,
        "schemaVersion": 2,
    })
    return {
        "config": config, "config_digest": digest(config),
        "layer": layer, "layer_digest": digest(layer),
        "layer_diff_id": digest(tar_bytes), "manifest": manifest,
        "manifest_digest": digest(manifest),
    }


def build_handoff(path: Path, source: str, run_id: str, attempt: str) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", source) is None:
        raise RuntimeError("source commit is malformed")
    if not run_id.isdigit() or not attempt.isdigit():
        raise RuntimeError("run identity is malformed")
    path.mkdir(parents=True, exist_ok=False)
    version = f"0.0.{run_id}{attempt}"
    variants = {name: make_variant(name, version) for name in ("baseline", "replacement")}
    record: dict[str, Any] = {
        "repository": REPOSITORY, "tag": version, "version": version,
        "media_type": MANIFEST_TYPE, "source_commit": source,
    }
    for name, value in variants.items():
        names = {
            "config_filename": f"{name}.config.json",
            "layer_filename": f"{name}.layer.tar.gz",
            "manifest_filename": f"{name}.manifest.json",
        }
        for kind in ("config", "layer", "manifest"):
            (path / names[f"{kind}_filename"]).write_bytes(value[kind])
        record[name] = {
            **names, "config_digest": value["config_digest"],
            "layer_digest": value["layer_digest"],
            "layer_diff_id": value["layer_diff_id"],
            "manifest_digest": value["manifest_digest"], "marker": name,
        }
    if record["baseline"]["manifest_digest"] == record["replacement"]["manifest_digest"]:
        raise RuntimeError("baseline and replacement manifest digests are identical")
    (path / "handoff.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return record


def exact(value: object, fields: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RuntimeError(f"{context} fields are not exact")
    return value


def validate_variant(path: Path, name: str, raw: object, version: str) -> dict[str, Any]:
    variant = exact(raw, {
        "config_digest", "config_filename", "layer_digest", "layer_diff_id",
        "layer_filename", "manifest_digest", "manifest_filename", "marker",
    }, f"OCI {name} handoff")
    if variant["marker"] != name:
        raise RuntimeError(f"OCI {name} marker is unexpected")
    content: dict[str, bytes] = {}
    for kind, suffix in (("config", "config.json"), ("layer", "layer.tar.gz"),
                         ("manifest", "manifest.json")):
        if variant[f"{kind}_filename"] != f"{name}.{suffix}":
            raise RuntimeError(f"OCI {name} {kind} filename is unexpected")
        content[kind] = (path / variant[f"{kind}_filename"]).read_bytes()
        if digest(content[kind]) != variant[f"{kind}_digest"]:
            raise RuntimeError(f"OCI {name} {kind} digest mismatch")
    try:
        manifest = exact(json.loads(content["manifest"]), {
            "schemaVersion", "mediaType", "config", "layers",
        }, f"OCI {name} manifest")
        config = json.loads(content["config"])
    except json.JSONDecodeError as error:
        raise RuntimeError(f"OCI {name} JSON is malformed") from error
    if manifest["schemaVersion"] != 2 or manifest["mediaType"] != MANIFEST_TYPE:
        raise RuntimeError(f"OCI {name} manifest identity is unexpected")
    if manifest["config"] != {
        "mediaType": CONFIG_TYPE, "digest": variant["config_digest"],
        "size": len(content["config"]),
    }:
        raise RuntimeError(f"OCI {name} config descriptor mismatch")
    if manifest["layers"] != [{
        "mediaType": LAYER_TYPE, "digest": variant["layer_digest"],
        "size": len(content["layer"]),
    }]:
        raise RuntimeError(f"OCI {name} layer descriptor mismatch")
    labels = config.get("config", {}).get("Labels", {}) if isinstance(config, dict) else {}
    if labels != {
        "org.opencontainers.image.version": version, "task008c.marker": name,
    }:
        raise RuntimeError(f"OCI {name} labels are unexpected")
    try:
        tar_bytes = gzip.decompress(content["layer"])
    except gzip.BadGzipFile as error:
        raise RuntimeError(f"OCI {name} layer gzip is malformed") from error
    if digest(tar_bytes) != variant["layer_diff_id"]:
        raise RuntimeError(f"OCI {name} layer diff ID mismatch")
    if config.get("rootfs") != {"diff_ids": [variant["layer_diff_id"]], "type": "layers"}:
        raise RuntimeError(f"OCI {name} config diff ID mismatch")
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
        members = archive.getmembers()
        extracted = archive.extractfile(members[0]) if len(members) == 1 else None
        payload = extracted.read() if extracted is not None else b""
        if len(members) != 1 or members[0].name != "artifact.txt" or not members[0].isfile():
            raise RuntimeError(f"OCI {name} layer contents are unexpected")
    if payload != f"version={version}\nmarker={name}\n".encode():
        raise RuntimeError(f"OCI {name} layer identity is unexpected")
    variant["bytes"] = content
    return variant


def validate_handoff(path: Path, source: str, run_id: str, attempt: str) -> dict[str, Any]:
    path = path.resolve(strict=True)
    entries = list(path.iterdir())
    if (
        {item.name for item in entries} != FILES
        or any(not item.is_file() or item.is_symlink() for item in entries)
    ):
        raise RuntimeError("OCI handoff file set is not exact")
    try:
        raw = json.loads((path / "handoff.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError("OCI handoff JSON is malformed") from error
    record = exact(raw, {
        "baseline", "media_type", "replacement", "repository", "source_commit",
        "tag", "version",
    }, "OCI handoff")
    version = f"0.0.{run_id}{attempt}"
    if record["repository"] != REPOSITORY:
        raise RuntimeError("OCI handoff repository is unexpected")
    if record["tag"] != version or record["version"] != version:
        raise RuntimeError("OCI handoff tag/version is unexpected")
    if record["media_type"] != MANIFEST_TYPE or record["source_commit"] != source:
        raise RuntimeError("OCI handoff media type or source commit is unexpected")
    for name in ("baseline", "replacement"):
        record[name] = validate_variant(path, name, record[name], version)
    if record["baseline"]["manifest_digest"] == record["replacement"]["manifest_digest"]:
        raise RuntimeError("OCI baseline and replacement manifest digests are identical")
    return record


class Probe:
    """Exercise the OCI Distribution API without username-style authentication."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.base_url = args.forgejo_url.rstrip("/")
        parsed = urlparse(self.base_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query
                or parsed.fragment or parsed.username or parsed.password):
            raise RuntimeError("Forgejo URL is not an exact HTTPS origin")
        self.origin = (parsed.scheme, parsed.hostname, parsed.port or 443)
        self.record = validate_handoff(
            Path(args.handoff), args.source_commit, args.run_id, args.run_attempt
        )
        self.repository, self.tag = self.record["repository"], self.record["tag"]
        self.registry_path = f"/v2/{self.repository}"
        self.summary_path = Path(args.summary)
        token_file = Path(args.token_file).resolve(strict=True)
        self.token = token_file.read_text(encoding="utf-8").strip()
        token_file.unlink()
        if not self.token:
            raise RuntimeError("OIDC token file was empty")
        self.opener = build_opener(NoRedirect())
        self.failures: list[str] = []
        self.rows = self.initial_rows()

    def initial_rows(self) -> dict[str, str]:
        return {
            "GitHub OIDC JWT acquisition": "PASS",
            "OCI Bearer authentication": "INCONCLUSIVE",
            "baseline blob upload": "NOT RUN", "baseline manifest push": "NOT RUN",
            "baseline manifest PUT status": "NOT RUN",
            "baseline manifest PUT digest header": "NOT EXPOSED",
            "baseline manifest expected digest A": self.record["baseline"]["manifest_digest"],
            "baseline tag HEAD status": "NOT RUN",
            "baseline tag HEAD digest": "NOT EXPOSED",
            "baseline digest HEAD status": "NOT RUN",
            "baseline digest HEAD digest": "NOT EXPOSED",
            "tags/list status": "NOT RUN", "tags/list repository": "NOT RUN",
            "exact tag present in tags/list": "NOT RUN",
            "baseline digest": self.record["baseline"]["manifest_digest"],
            "pull by tag": "NOT RUN", "pull by digest": "NOT RUN",
            "baseline manifest integrity": "NOT RUN", "baseline config integrity": "NOT RUN",
            "baseline layer integrity": "NOT RUN", "baseline marker/version": "NOT RUN",
            "replacement digest": self.record["replacement"]["manifest_digest"],
            "same-tag replacement HTTP result": "NOT RUN",
            "tag digest before replacement": "NOT RUN", "tag digest after replacement": "NOT RUN",
            "OCI tag immutability": "INCONCLUSIVE",
            "original digest survives tag operation": "NOT RUN",
            "original digest integrity": "NOT RUN",
            "original config survives": "NOT RUN", "original layer survives": "NOT RUN",
            "exact-digest rollback before DELETE": "NOT RUN",
            "DELETE tag": "NOT RUN", "DELETE manifest digest": "NOT RUN",
            "DELETE blob": "NOT RUN", "Public DELETE boundary": "INCONCLUSIVE",
            "post-DELETE manifest retrieval": "NOT RUN",
            "post-DELETE manifest integrity": "NOT RUN",
            "post-DELETE config retrieval": "NOT RUN", "post-DELETE layer retrieval": "NOT RUN",
            "post-DELETE blob integrity": "NOT RUN",
            "post-DELETE tag resolution": "NOT RUN",
            "exact-digest rollback after DELETE": "NOT RUN",
            "Standard Docker/OCI client + OIDC JWT": (
                "INCONCLUSIVE (username-style client auth not established)"
            ),
            "OCI digest append-only / rollback": "INCONCLUSIVE",
            "Exact-digest rollback": "INCONCLUSIVE",
        }

    @staticmethod
    def header(headers: dict[str, str], name: str) -> str | None:
        return next((v for k, v in headers.items() if k.lower() == name.lower()), None)

    @staticmethod
    def phase(message: str) -> None:
        """Emit a short, non-secret progress marker for Actions diagnostics."""

        print(f"OCI PHASE: {message}", flush=True)

    def safe_error_body(self, body: bytes) -> str:
        """Return bounded, single-line registry error detail with JWT redaction."""

        text = body.decode("utf-8", errors="replace").replace(self.token, "[REDACTED]")
        text = re.sub(
            r"(?i)\bauthorization\s*:\s*bearer\s+\S+",
            "[REDACTED AUTHORIZATION]",
            text,
        )
        text = re.sub(r"(?i)\bbearer\s+\S+", "Bearer [REDACTED]", text)
        text = " ".join(text.split())
        if len(text) > ERROR_BODY_LIMIT:
            text = f"{text[:ERROR_BODY_LIMIT]}…"
        return text

    def http_failure(self, prefix: str, status: int, body: bytes) -> RuntimeError:
        detail = self.safe_error_body(body)
        suffix = f"; registry response: {detail}" if detail else ""
        return RuntimeError(f"{prefix} returned HTTP {status}{suffix}")

    def request(self, method: str, target: str, *, body: bytes | None = None,
                content_type: str | None = None,
                accept: str | None = None) -> tuple[int, bytes, dict[str, str]]:
        url = target if target.startswith("https://") else f"{self.base_url}{target}"
        parsed = urlparse(url)
        if ((parsed.scheme, parsed.hostname, parsed.port or 443) != self.origin
                or parsed.username or parsed.password or parsed.fragment):
            raise RuntimeError("SECURITY FAILURE: OCI request escaped the Forgejo origin")
        headers = {"Authorization": f"Bearer {self.token}"}
        if content_type:
            headers["Content-Type"] = content_type
        if accept:
            headers["Accept"] = accept
        request = Request(url, data=body, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=60) as response:
                return response.status, response.read(), dict(response.headers.items())
        except HTTPError as error:
            return (
                error.code,
                error.read(ERROR_BODY_LIMIT + 1),
                dict(error.headers.items()),
            )

    def upload_url(self, location: str, blob_digest: str) -> str:
        resolved = urljoin(f"{self.base_url}/", location)
        parsed = urlparse(resolved)
        prefix = f"{self.registry_path}/blobs/uploads/"
        decoded_path = unquote(parsed.path)
        if (not location or (parsed.scheme, parsed.hostname, parsed.port or 443) != self.origin
                or parsed.username or parsed.password or parsed.fragment
                or not decoded_path.startswith(prefix)
                or any(part in {".", ".."} for part in decoded_path.split("/"))):
            raise RuntimeError("SECURITY FAILURE: unsafe OCI blob upload Location")
        query = parse_qsl(parsed.query, keep_blank_values=True)
        if any(key == "digest" for key, _ in query):
            raise RuntimeError("OCI upload Location already contained a digest")
        query.append(("digest", blob_digest))
        return parsed._replace(query=urlencode(query)).geturl()

    def verify_blob(self, blob_digest: str, expected: bytes, context: str) -> None:
        status, body, _ = self.request(
            "GET", f"{self.registry_path}/blobs/{quote(blob_digest, safe=':')}"
        )
        if status != 200:
            raise RuntimeError(f"{context} blob GET returned HTTP {status}")
        if body != expected or digest(body) != blob_digest:
            raise RuntimeError(f"{context} blob integrity mismatch")

    def ensure_blob(self, blob_digest: str, content: bytes) -> None:
        path = f"{self.registry_path}/blobs/{quote(blob_digest, safe=':')}"
        status, _, headers = self.request("HEAD", path)
        if status == 200:
            exposed = self.header(headers, "Docker-Content-Digest")
            if exposed and exposed != blob_digest:
                raise RuntimeError("existing OCI blob exposed a different digest")
        elif status == 404:
            status, _, headers = self.request(
                "POST", f"{self.registry_path}/blobs/uploads/", body=b""
            )
            if status != 202:
                raise RuntimeError(f"OCI blob upload initiation returned HTTP {status}")
            target = self.upload_url(self.header(headers, "Location") or "", blob_digest)
            status, _, headers = self.request(
                "PUT", target, body=content, content_type="application/octet-stream"
            )
            if status != 201:
                raise RuntimeError(f"OCI blob upload completion returned HTTP {status}")
            exposed = self.header(headers, "Docker-Content-Digest")
            if exposed and exposed != blob_digest:
                raise RuntimeError("uploaded OCI blob exposed a different digest")
        else:
            raise RuntimeError(f"INCONCLUSIVE: OCI blob HEAD returned HTTP {status}")
        self.verify_blob(blob_digest, content, "uploaded")

    def put_manifest(self, reference: str, body: bytes) -> tuple[int, dict[str, str]]:
        status, _, headers = self.request(
            "PUT", f"{self.registry_path}/manifests/{quote(reference, safe=':')}",
            body=body, content_type=MANIFEST_TYPE,
        )
        return status, headers

    def head_manifest(self, reference: str, context: str) -> tuple[int, str | None]:
        self.phase(f"checking {context} HEAD")
        status, _, headers = self.request(
            "HEAD", f"{self.registry_path}/manifests/{quote(reference, safe=':')}",
            accept=MANIFEST_TYPE,
        )
        self.phase(f"{context} HEAD HTTP {status}")
        return status, self.header(headers, "Docker-Content-Digest")

    def get_manifest(self, reference: str, context: str) -> tuple[str, bytes]:
        status, body, headers = self.request(
            "GET", f"{self.registry_path}/manifests/{quote(reference, safe=':')}",
            accept=MANIFEST_TYPE,
        )
        if status != 200:
            raise self.http_failure(
                f"{context}: OCI manifest GET {reference}", status, body
            )
        observed = digest(body)
        exposed = self.header(headers, "Docker-Content-Digest")
        if exposed and exposed != observed:
            raise RuntimeError(
                f"{context}: OCI manifest GET {reference} digest header disagrees with bytes"
            )
        return observed, body

    def list_tags(self) -> list[str]:
        self.phase("querying baseline tags/list")
        status, body, _ = self.request("GET", f"{self.registry_path}/tags/list")
        self.phase(f"baseline tags/list HTTP {status}")
        self.rows["tags/list status"] = f"HTTP {status}"
        if status != 200:
            self.failures.append(str(self.http_failure("baseline tags/list GET", status, body)))
            return []
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as error:
            self.failures.append("baseline tags/list response was malformed JSON")
            return []
        if not isinstance(payload, dict) or payload.get("name") != self.repository:
            self.failures.append("baseline tags/list repository identity was unexpected")
            return []
        self.rows["tags/list repository"] = self.repository
        tags = payload.get("tags")
        if tags is None:
            tags = []
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            self.failures.append("baseline tags/list tags value was malformed")
            return []
        self.rows["exact tag present in tags/list"] = "PASS" if self.tag in tags else "FAIL"
        if self.tag not in tags:
            self.failures.append("baseline exact tag was absent from tags/list")
        return tags

    def verify_variant(self, reference: str, name: str, context: str) -> None:
        variant = self.record[name]
        observed, body = self.get_manifest(reference, context)
        if observed != variant["manifest_digest"] or body != variant["bytes"]["manifest"]:
            raise RuntimeError(f"OCI {name} manifest integrity mismatch")
        self.verify_blob(variant["config_digest"], variant["bytes"]["config"], name)
        self.verify_blob(variant["layer_digest"], variant["bytes"]["layer"], name)
        labels = json.loads(variant["bytes"]["config"])["config"]["Labels"]
        if labels != {
            "org.opencontainers.image.version": self.record["version"],
            "task008c.marker": name,
        }:
            raise RuntimeError(f"OCI {name} remote labels mismatch")

    def delete(self, row: str, path: str) -> None:
        status, _, _ = self.request("DELETE", path, accept=MANIFEST_TYPE)
        if status == 403:
            self.rows[row] = "PASS (HTTP 403)"
        elif 200 <= status < 300:
            self.rows[row] = f"SECURITY FAILURE (HTTP {status})"
            self.failures.append(f"{row} succeeded")
        else:
            self.rows[row] = f"INCONCLUSIVE (HTTP {status}; expected 403)"
            self.failures.append(f"{row} did not prove the Nginx boundary")

    def run(self) -> None:
        status, _, _ = self.request("GET", "/v2/")
        if status != 200:
            raise RuntimeError(f"OCI registry API check returned HTTP {status}")
        self.phase("registry API check passed")
        a, b = self.record["baseline"], self.record["replacement"]
        self.ensure_blob(a["config_digest"], a["bytes"]["config"])
        self.phase("baseline config blob available")
        self.ensure_blob(a["layer_digest"], a["bytes"]["layer"])
        self.phase("baseline layer blob available")
        self.rows["baseline blob upload"] = "PASS"
        self.phase("publishing baseline manifest A")
        status, headers = self.put_manifest(self.tag, a["bytes"]["manifest"])
        put_digest = self.header(headers, "Docker-Content-Digest")
        self.rows["baseline manifest PUT status"] = f"HTTP {status}"
        self.rows["baseline manifest PUT digest header"] = put_digest or "NOT EXPOSED"
        self.phase(f"baseline manifest PUT HTTP {status}")
        if status != 201:
            raise RuntimeError(f"baseline manifest PUT returned HTTP {status}; expected 201")
        if put_digest not in (None, a["manifest_digest"]):
            raise RuntimeError("baseline manifest PUT returned the wrong digest")
        self.rows["OCI Bearer authentication"] = (
            "PASS (manifest PUT with direct GitHub OIDC JWT)"
        )
        self.phase("registry authentication passed")
        self.rows["baseline manifest push"] = "PASS (HTTP 201)"

        tag_head_status, tag_head_digest = self.head_manifest(
            self.tag, "baseline tag"
        )
        self.rows["baseline tag HEAD status"] = f"HTTP {tag_head_status}"
        self.rows["baseline tag HEAD digest"] = tag_head_digest or "NOT EXPOSED"
        if tag_head_status != 200 or tag_head_digest not in (None, a["manifest_digest"]):
            self.failures.append(
                f"baseline tag HEAD {self.tag} returned HTTP {tag_head_status} "
                "or did not prove digest A"
            )
        digest_head_status, digest_head_digest = self.head_manifest(
            a["manifest_digest"], "baseline digest A"
        )
        self.rows["baseline digest HEAD status"] = f"HTTP {digest_head_status}"
        self.rows["baseline digest HEAD digest"] = digest_head_digest or "NOT EXPOSED"
        if digest_head_status != 200 or digest_head_digest not in (None, a["manifest_digest"]):
            self.failures.append(
                f"baseline digest A HEAD {a['manifest_digest']} returned HTTP "
                f"{digest_head_status} or did not prove digest A"
            )
        self.list_tags()

        self.phase("resolving baseline tag")
        before, _ = self.get_manifest(self.tag, "baseline tag after PUT")
        if before != a["manifest_digest"]:
            raise RuntimeError("baseline tag did not resolve to digest A")
        self.rows["tag digest before replacement"] = before
        self.rows["pull by tag"] = "PASS"
        self.phase("resolving baseline digest A")
        self.verify_variant(a["manifest_digest"], "baseline", "baseline digest A")
        for row in ("pull by digest", "baseline manifest integrity",
                    "baseline config integrity", "baseline layer integrity",
                    "baseline marker/version"):
            self.rows[row] = "PASS"

        self.phase("uploading replacement B")
        for kind in ("config", "layer"):
            self.ensure_blob(b[f"{kind}_digest"], b["bytes"][kind])
        self.phase("replacement PUT")
        replacement_status, headers = self.put_manifest(self.tag, b["bytes"]["manifest"])
        self.rows["same-tag replacement HTTP result"] = f"HTTP {replacement_status}"
        self.phase(f"replacement manifest PUT HTTP {replacement_status}")
        if (replacement_status == 201
                and self.header(headers, "Docker-Content-Digest") not in
                (None, b["manifest_digest"])):
            self.failures.append("replacement PUT returned an incoherent digest")
        self.phase("resolving tag after replacement")
        after, after_body = self.get_manifest(
            self.tag, "tag after replacement attempt"
        )
        self.rows["tag digest after replacement"] = after
        if (replacement_status == 201 and after == b["manifest_digest"]
                and after_body == b["bytes"]["manifest"]):
            self.rows["OCI tag immutability"] = "FAIL (same-tag replacement accepted)"
        elif (replacement_status in {400, 403, 405, 409}
              and after == a["manifest_digest"]
              and after_body == a["bytes"]["manifest"]):
            self.rows["OCI tag immutability"] = f"PASS (replacement rejected; HTTP {replacement_status})"
        else:
            self.rows["OCI tag immutability"] = "INCONCLUSIVE"
            self.failures.append("same-tag replacement behavior was incoherent")

        # A mutable tag is an observation, not a reason to skip digest-retention evidence.
        self.phase("verifying original digest A")
        self.verify_variant(
            a["manifest_digest"], "baseline", "digest A after replacement"
        )
        for row in ("original digest survives tag operation", "original config survives",
                    "original layer survives", "original digest integrity",
                    "exact-digest rollback before DELETE"):
            self.rows[row] = "PASS"
        self.phase("DELETE probes")
        self.delete("DELETE manifest digest",
                    f"{self.registry_path}/manifests/{quote(a['manifest_digest'], safe=':')}")
        self.delete("DELETE tag", f"{self.registry_path}/manifests/{quote(self.tag, safe='')}")
        self.delete("DELETE blob",
                    f"{self.registry_path}/blobs/{quote(a['layer_digest'], safe=':')}")
        deletes = (self.rows["DELETE tag"], self.rows["DELETE manifest digest"],
                   self.rows["DELETE blob"])
        if all(value == "PASS (HTTP 403)" for value in deletes):
            self.rows["Public DELETE boundary"] = "PASS"

        self.phase("post-DELETE verification")
        post_tag, post_tag_body = self.get_manifest(
            self.tag, "tag after DELETE attempts"
        )
        expected_tag = (
            b if self.rows["OCI tag immutability"].startswith("FAIL") else a
        )
        if (
            post_tag != expected_tag["manifest_digest"]
            or post_tag_body != expected_tag["bytes"]["manifest"]
        ):
            raise RuntimeError("post-DELETE OCI tag resolved unexpectedly")
        self.rows["post-DELETE tag resolution"] = "PASS"
        self.verify_variant(
            a["manifest_digest"], "baseline", "digest A after DELETE attempts"
        )
        for row in ("post-DELETE manifest retrieval", "post-DELETE manifest integrity",
                    "post-DELETE config retrieval", "post-DELETE layer retrieval",
                    "post-DELETE blob integrity", "exact-digest rollback after DELETE"):
            self.rows[row] = "PASS"
        self.rows["Exact-digest rollback"] = "PASS"
        if self.rows["Public DELETE boundary"] == "PASS":
            self.rows["OCI digest append-only / rollback"] = "PASS"
        if self.failures:
            raise RuntimeError("; ".join(self.failures))

    def write_summary(self) -> None:
        with self.summary_path.open("a", encoding="utf-8") as stream:
            stream.write("## Task 008C Forgejo OCI probe\n\n")
            stream.write(f"- Repository: `{self.base_url}/{self.repository}`\n")
            stream.write(f"- Tag: `{self.tag}`\n")
            stream.write(f"- Digest A: `{self.record['baseline']['manifest_digest']}`\n")
            stream.write(f"- Digest B: `{self.record['replacement']['manifest_digest']}`\n\n")
            stream.write("| Evidence | Result |\n|---|---|\n")
            for name, result in self.rows.items():
                stream.write(f"| {name} | {result} |\n")

    def close(self) -> None:
        self.token = ""


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "validate"):
        command = commands.add_parser(name)
        command.add_argument("--handoff", required=True)
        command.add_argument("--source-commit", required=True)
        command.add_argument("--run-id", required=True)
        command.add_argument("--run-attempt", required=True)
    command = commands.add_parser("probe")
    command.add_argument("--forgejo-url", required=True)
    command.add_argument("--handoff", required=True)
    command.add_argument("--source-commit", required=True)
    command.add_argument("--run-id", required=True)
    command.add_argument("--run-attempt", required=True)
    command.add_argument("--token-file", required=True)
    command.add_argument("--summary", required=True)
    return parser


def main() -> int:
    args = make_parser().parse_args()
    probe: Probe | None = None
    try:
        if args.command == "build":
            build_handoff(Path(args.handoff), args.source_commit, args.run_id, args.run_attempt)
        elif args.command == "validate":
            validate_handoff(Path(args.handoff), args.source_commit, args.run_id, args.run_attempt)
        else:
            probe = Probe(args)
            probe.run()
        return 0
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        if probe is not None:
            probe.write_summary()
            probe.close()


if __name__ == "__main__":
    raise SystemExit(main())
