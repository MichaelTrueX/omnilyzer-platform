#!/usr/bin/env python3
"""File: release/analytics_oci_archive.py

Purpose: Verify a Task013-candidate Analytics OCI archive against the already
reviewed source, original SaaS runtime contract and OCI content digests.
This does NOT authenticate the builder, sign a release, publish to Zot or
authorize the original Task014 broker/executor.

Links: release/analytics_task013_build_input.py, release/executable_oci.py,
release/analytics_source_admission.py, deployment/saas_product_runtime.py,
Dockerfile.analytics in MichaelTrueX/omnilyzer PR45, platform-release.yml.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
from typing import Any

from deployment.policy import DeploymentPolicyError, canonical_bytes
from release.analytics_task013_build_input import build_input

ERROR = "TASK013_ANALYTICS_OCI_DENIED"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
BLOB = re.compile(r"blobs/sha256/[0-9a-f]{64}\Z")
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYERS = frozenset({
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar",
})
MAX_ARCHIVE = 3 * 1024 * 1024 * 1024
MAX_MEMBERS = 10000
MAX_METADATA = 4 * 1024 * 1024
READ_CHUNK = 1024 * 1024
EXPECTED_CMD = [
    "node", "node_modules/next/dist/bin/next", "start",
    "-H", "0.0.0.0", "-p", "3000",
]
DENIED_RUNTIME_NAMES = frozenset({
    "DATABASE_URL", "COLLECTOR_DATABASE_URL",
    "JWT_SECRET", "JWT_REFRESH_SECRET",
})


def _closed_json(raw: bytes, context: str) -> dict[str, Any]:
    """Parse one bounded, duplicate-free JSON metadata document."""
    if not raw or len(raw) > MAX_METADATA:
        raise DeploymentPolicyError(f"{context} metadata size invalid")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """No ambiguous duplicated metadata keys in signed subject inputs."""
        obj: dict[str, Any] = {}
        for key, value in pairs:
            if key in obj:
                raise DeploymentPolicyError("duplicate OCI metadata member")
            obj[key] = value
        return obj

    try:
        result = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise DeploymentPolicyError(f"{context} invalid OCI JSON") from exc
    if type(result) is not dict:
        raise DeploymentPolicyError(f"{context} is not an object")
    return result


def _descriptor(value: Any, context: str, media_type: str | frozenset[str]) -> tuple[str, int]:
    """Extract strict OCI descriptor without trusting mutable tags."""
    if type(value) is not dict or not {"digest", "size", "mediaType"}.issubset(value):
        raise DeploymentPolicyError(f"{context} missing descriptor")
    media = value["mediaType"]
    allowed = frozenset((media_type,)) if type(media_type) is str else media_type
    if (type(media) is not str or media not in allowed
            or type(value["digest"]) is not str
            or DIGEST.fullmatch(value["digest"]) is None
            or type(value["size"]) is not int or value["size"] <= 0
            or value["size"] > MAX_ARCHIVE):
        raise DeploymentPolicyError(f"{context} invalid descriptor")
    return value["digest"], value["size"]


def verify_archive(archive_path: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    """Verify archive layout, every blob hash and strict Next runtime identity.

    This is intentionally independent of the registry-derived digest or
    external-source signature. It checks local content only; neither the
    receipt nor the output constitutes signed provenance.
    """
    if (not isinstance(archive_path, Path) or archive_path.is_symlink()
            or not archive_path.is_file() or archive_path.stat().st_size > MAX_ARCHIVE):
        raise DeploymentPolicyError("OCI archive path is not an approved regular file")
    if (
        type(receipt) is not dict
        or receipt.get("input_kind") != "task013-analytics-oci-review-only"
        or receipt.get("oci_repository") != "omnilyzer/analytics"
        or receipt.get("readiness_path") != "/readyz"
        or receipt.get("source_files_verified") != 78
        or receipt.get("release_authorized") is not False
        or receipt.get("deployment_authorized") is not False
    ):
        raise DeploymentPolicyError("unsigned source build input is invalid")
    if any(type(receipt.get(key)) is not str or
           re.fullmatch(r"[0-9a-f]{64}", receipt[key]) is None
           for key in ("dockerfile_sha256", "dockerignore_sha256",
                       "oci_test_source_sha256", "source_manifest_sha256")):
        raise DeploymentPolicyError("source build identities are missing")

    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        with os.fdopen(os.open(archive_path, flags), "rb") as source, \
                tarfile.open(fileobj=source, mode="r:") as archive:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE:
                raise DeploymentPolicyError("OCI archive is not a bounded regular file")
            items: dict[str, tarfile.TarInfo] = {}
            directories: set[str] = set()
            for member in archive:
                name = member.name
                path = PurePosixPath(name)
                # Docker Buildx emits these two standard OCI parent directories.
                # Accept no other directory or writable/ambiguous members.
                if member.isdir():
                    if name not in {"blobs", "blobs/sha256"} or name in directories or member.size != 0:
                        raise DeploymentPolicyError("unsafe OCI archive directory")
                    directories.add(name)
                    continue
                if (
                    len(items) >= MAX_MEMBERS or name.startswith("./")
                    or path.is_absolute() or ".." in path.parts
                    or "\\" in name or name in items
                    or not member.isfile() or member.issym() or member.islnk()
                    or name not in {"oci-layout", "index.json"}
                    and BLOB.fullmatch(name) is None
                    or member.size < 0 or member.size > MAX_ARCHIVE
                ):
                    raise DeploymentPolicyError("unsafe OCI archive entry")
                items[name] = member
            if "oci-layout" not in items or "index.json" not in items:
                raise DeploymentPolicyError("OCI archive layout files absent")

            def read_meta(name: str) -> bytes:
                """Read only bounded OCI configuration/manifest/index bytes."""
                member = items.get(name)
                if member is None or member.size > MAX_METADATA:
                    raise DeploymentPolicyError("missing or oversized OCI metadata")
                stream = archive.extractfile(member)
                if stream is None:
                    raise DeploymentPolicyError("OCI metadata unavailable")
                with stream:
                    return stream.read(MAX_METADATA + 1)

            def verify_blob(digest: str, size: int) -> bytes | None:
                """Hash the complete layer in bounded chunks, read JSON only."""
                name = f"blobs/sha256/{digest[7:]}"
                member = items.get(name)
                if member is None or member.size != size:
                    raise DeploymentPolicyError("OCI blob missing or different size")
                stream = archive.extractfile(member)
                if stream is None:
                    raise DeploymentPolicyError("OCI blob unavailable")
                hasher = hashlib.sha256()
                captured = bytearray() if size <= MAX_METADATA else None
                with stream:
                    while True:
                        chunk = stream.read(READ_CHUNK)
                        if not chunk:
                            break
                        hasher.update(chunk)
                        if captured is not None:
                            captured.extend(chunk)
                if hasher.hexdigest() != digest[7:]:
                    raise DeploymentPolicyError("OCI content-addressed hash mismatch")
                return bytes(captured) if captured is not None else None

            layout = _closed_json(read_meta("oci-layout"), "layout")
            if layout != {"imageLayoutVersion": "1.0.0"}:
                raise DeploymentPolicyError("incorrect OCI layout version")
            index = _closed_json(read_meta("index.json"), "index")
            manifests = index.get("manifests")
            if (index.get("schemaVersion") != 2 or type(manifests) is not list
                    or len(manifests) != 1
                    or index.get("mediaType") not in (None, OCI_INDEX)):
                raise DeploymentPolicyError("OCI index is not a single release image")
            manifest_digest, manifest_size = _descriptor(manifests[0], "manifest", OCI_MANIFEST)
            manifest_raw = verify_blob(manifest_digest, manifest_size)
            if manifest_raw is None:
                raise DeploymentPolicyError("OCI image manifest too large")
            manifest = _closed_json(manifest_raw, "manifest")
            if (manifest.get("schemaVersion") != 2
                    or manifest.get("mediaType") not in (None, OCI_MANIFEST)):
                raise DeploymentPolicyError("OCI image manifest version invalid")
            config_digest, config_size = _descriptor(manifest.get("config"), "config", OCI_CONFIG)
            config_raw = verify_blob(config_digest, config_size)
            if config_raw is None:
                raise DeploymentPolicyError("OCI image config too large")
            config = _closed_json(config_raw, "config")
            layers = manifest.get("layers")
            if type(layers) is not list or len(layers) < 1 or len(layers) > 512:
                raise DeploymentPolicyError("OCI image layers missing or excessive")
            used = {f"blobs/sha256/{manifest_digest[7:]}", f"blobs/sha256/{config_digest[7:]}"}
            for layer in layers:
                layer_digest, layer_size = _descriptor(layer, "layer", OCI_LAYERS)
                name = f"blobs/sha256/{layer_digest[7:]}"
                if name in used:
                    raise DeploymentPolicyError("duplicate OCI layer")
                used.add(name)
                verify_blob(layer_digest, layer_size)
            if set(items) != used | {"oci-layout", "index.json"}:
                raise DeploymentPolicyError("OCI archive contains unreferenced blobs")
            rootfs = config.get("rootfs")
            runtime = config.get("config")
            if (config.get("architecture") != "amd64"
                    or config.get("os") != "linux"
                    or type(rootfs) is not dict
                    or rootfs.get("type") != "layers"
                    or type(rootfs.get("diff_ids")) is not list
                    or len(rootfs["diff_ids"]) != len(layers)
                    or any(type(v) is not str or DIGEST.fullmatch(v) is None
                           for v in rootfs["diff_ids"])
                    or type(runtime) is not dict):
                raise DeploymentPolicyError("OCI platform or filesystem invalid")
            env = runtime.get("Env")
            if (type(env) is not list
                    or any(type(item) is not str or "=" not in item for item in env)
                    or DENIED_RUNTIME_NAMES.intersection(
                        item.split("=", 1)[0] for item in env
                    )
                    or runtime.get("User") != "10001:10001"
                    or runtime.get("WorkingDir") != "/srv/omnilyzer"
                    or runtime.get("Entrypoint") != ["docker-entrypoint.sh"]
                    or runtime.get("Cmd") != EXPECTED_CMD
                    or runtime.get("ExposedPorts") != {"3000/tcp": {}}):
                raise DeploymentPolicyError("unsafe Analytics OCI runtime configuration")

            return {
                "schema_version": 1,
                "source_commit": receipt["analytics_source_commit"],
                "source_tree": receipt["analytics_tree"],
                "oci_repository": receipt["oci_repository"],
                "local_manifest_digest": manifest_digest,
                "archive_sha256": _sha_stream(source),
                "release_authorized": False,
                "deployment_authorized": False,
            }
    except (OSError, tarfile.TarError) as exc:
        raise DeploymentPolicyError("invalid OCI archive format") from exc


def _sha_stream(source: Any) -> str:
    """Hash the same opened archive descriptor, preventing source replacement."""
    source.seek(0)
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(READ_CHUNK), b""):
        digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    """CLI for isolated Task013 candidate verification, never publication."""
    parser = argparse.ArgumentParser(description="Unsigned original-Task013 Analytics OCI archive verifier")
    parser.add_argument("--analytics-checkout", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = build_input(args.analytics_checkout)
        verified = verify_archive(args.archive, receipt)
    except (DeploymentPolicyError, OSError, ValueError) as exc:
        print(f"{ERROR}: {exc}", file=sys.stderr)
        return 1
    print(canonical_bytes(verified).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
