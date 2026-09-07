#!/usr/bin/env python3
"""Fail-closed validation for the executable canary OCI archive."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from typing import Any


BASE_IMAGE_DIGEST = "sha256:bbdc4d1e20995d9bb9f9935188844c824b40969de4bb1f0eaadacda4c8d4121e"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
SEMVER_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


class ExecutableOCIError(ValueError):
    pass


def _json(raw: bytes, context: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ExecutableOCIError(f"{context} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ExecutableOCIError(f"{context} must be an object")
    return value


def _blob(files: dict[str, bytes], descriptor: Any, context: str) -> bytes:
    if not isinstance(descriptor, dict):
        raise ExecutableOCIError(f"{context} descriptor must be an object")
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if not isinstance(digest, str) or DIGEST_RE.fullmatch(digest) is None:
        raise ExecutableOCIError(f"{context} descriptor digest is invalid")
    path = f"blobs/sha256/{digest.removeprefix('sha256:')}"
    raw = files.get(path)
    if raw is None or size != len(raw) or hashlib.sha256(raw).hexdigest() != digest.removeprefix("sha256:"):
        raise ExecutableOCIError(f"{context} blob size or digest differs")
    return raw


def _archive_files(path: Path) -> dict[str, bytes]:
    if path.is_symlink() or not path.is_file():
        raise ExecutableOCIError("OCI archive must be a regular file")
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(path, "r") as archive:
            for member in archive:
                name = member.name.removeprefix("./")
                pure = PurePosixPath(name)
                if (pure.is_absolute() or ".." in pure.parts or "\\" in name
                        or member.issym() or member.islnk()):
                    raise ExecutableOCIError("OCI archive contains an unsafe member")
                if member.isdir():
                    continue
                if not member.isfile() or name in files:
                    raise ExecutableOCIError("OCI archive contains a duplicate or unsupported member")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ExecutableOCIError("OCI archive member cannot be read")
                files[name] = stream.read()
    except (OSError, tarfile.TarError) as exc:
        raise ExecutableOCIError("OCI archive cannot be read") from exc
    if "oci-layout" not in files or "index.json" not in files:
        raise ExecutableOCIError("OCI archive lacks its layout or index")
    allowed = {"oci-layout", "index.json"}
    if any(name not in allowed and not re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name)
           for name in files):
        raise ExecutableOCIError("OCI archive contains an unexpected file")
    return files


def verify_executable_archive(
    path: Path, release_version: str, source_sha: str, repository: str,
) -> str:
    if SEMVER_RE.fullmatch(release_version) is None:
        raise ExecutableOCIError("expected release version is invalid")
    if SOURCE_SHA_RE.fullmatch(source_sha) is None or source_sha == "0" * 40:
        raise ExecutableOCIError("expected source SHA is invalid")
    files = _archive_files(path)
    if _json(files["oci-layout"], "OCI layout") != {"imageLayoutVersion": "1.0.0"}:
        raise ExecutableOCIError("OCI layout version differs")
    index = _json(files["index.json"], "OCI index")
    if (index.get("schemaVersion") != 2
            or index.get("mediaType") != "application/vnd.oci.image.index.v1+json"):
        raise ExecutableOCIError("OCI index schema or media type differs")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise ExecutableOCIError("OCI index must identify exactly one final image")
    manifest_descriptor = manifests[0]
    manifest_raw = _blob(files, manifest_descriptor, "manifest")
    if manifest_descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
        raise ExecutableOCIError("final image manifest media type differs")
    manifest = _json(manifest_raw, "OCI manifest")
    if (manifest.get("schemaVersion") != 2
            or manifest.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"):
        raise ExecutableOCIError("OCI manifest schema or media type differs")
    config_raw = _blob(files, manifest.get("config"), "configuration")
    if manifest["config"].get("mediaType") != "application/vnd.oci.image.config.v1+json":
        raise ExecutableOCIError("OCI configuration media type differs")
    layers = manifest.get("layers")
    if not isinstance(layers, list) or len(layers) < 2:
        raise ExecutableOCIError("executable image must contain its pinned base and canary layer")
    for index_, descriptor in enumerate(layers):
        if not isinstance(descriptor, dict) or descriptor.get("mediaType") != "application/vnd.oci.image.layer.v1.tar+gzip":
            raise ExecutableOCIError(f"layer {index_} media type differs")
        _blob(files, descriptor, f"layer {index_}")
    config = _json(config_raw, "OCI configuration")
    if config.get("architecture") != "amd64" or config.get("os") != "linux":
        raise ExecutableOCIError("OCI platform must be exactly linux/amd64")
    runtime = config.get("config")
    if not isinstance(runtime, dict):
        raise ExecutableOCIError("OCI runtime configuration is absent")
    labels = runtime.get("Labels")
    if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in {
        "org.opencontainers.image.title": repository,
        "org.opencontainers.image.version": release_version,
        "org.opencontainers.image.revision": source_sha,
        "ai.omnilyzer.canary": "true",
        "ai.omnilyzer.base.digest": BASE_IMAGE_DIGEST,
    }.items()):
        raise ExecutableOCIError("OCI labels do not bind the reviewed release identity")
    environment = runtime.get("Env")
    if not isinstance(environment, list):
        raise ExecutableOCIError("OCI environment is absent")
    required_environment = {
        f"CANARY_RELEASE_VERSION={release_version}",
        f"CANARY_SOURCE_SHA={source_sha}",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONUNBUFFERED=1",
    }
    if not required_environment.issubset(set(environment)):
        raise ExecutableOCIError("OCI environment does not bind release metadata")
    if runtime.get("User") != "10001:10001":
        raise ExecutableOCIError("OCI runtime user is not the reviewed non-root UID/GID")
    if runtime.get("Entrypoint") != ["/usr/bin/python", "/app/canary_runtime.py"]:
        raise ExecutableOCIError("OCI entrypoint is not the reviewed executable command")
    if runtime.get("Cmd") not in (None, []):
        raise ExecutableOCIError("OCI command contains unexpected arguments")
    if runtime.get("ExposedPorts") != {"8080/tcp": {}}:
        raise ExecutableOCIError("OCI image must expose only internal TCP port 8080")
    rootfs = config.get("rootfs")
    if (not isinstance(rootfs, dict) or rootfs.get("type") != "layers"
            or not isinstance(rootfs.get("diff_ids"), list)
            or len(rootfs["diff_ids"]) != len(layers)
            or any(not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None
                   for value in rootfs["diff_ids"])):
        raise ExecutableOCIError("OCI root filesystem does not match its layers")
    return manifest_descriptor["digest"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    print(verify_executable_archive(
        args.archive, args.release_version, args.source_sha, args.repository,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
