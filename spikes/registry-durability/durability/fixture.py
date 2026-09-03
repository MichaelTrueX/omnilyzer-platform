"""Build deterministic, harmless OCI fixtures without executing an image."""

from __future__ import annotations

from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import tarfile


MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"
REPOSITORY = "omnilyzer/task012-durability-spike"


def canonical_json(value: object) -> bytes:
    """Return stable compact JSON bytes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class Release:
    """One deterministic synthetic OCI release and its local identities."""

    name: str
    tag: str
    manifest: bytes
    config: bytes
    layer: bytes
    manifest_digest: str
    config_digest: str
    layer_digest: str

    def evidence(self) -> dict[str, object]:
        return {
            "tag": self.tag,
            "manifest_digest": self.manifest_digest,
            "manifest_length": len(self.manifest),
            "config_digest": self.config_digest,
            "config_length": len(self.config),
            "layer_digest": self.layer_digest,
            "layer_length": len(self.layer),
        }


def build_release(name: str, tag: str) -> Release:
    """Build one non-executable scratch-style OCI image deterministically."""
    payload = (
        "Task 012A synthetic durability fixture\n"
        f"release={name}\n"
        f"tag={tag}\n"
    ).encode("utf-8")
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        member = tarfile.TarInfo("evidence.txt")
        member.size = len(payload)
        member.mode = 0o444
        member.mtime = 0
        member.uid = member.gid = 0
        member.uname = member.gname = ""
        archive.addfile(member, io.BytesIO(payload))
    uncompressed_layer = tar_buffer.getvalue()
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=compressed, mode="wb", mtime=0) as stream:
        stream.write(uncompressed_layer)
    layer = compressed.getvalue()
    config = canonical_json({
        "architecture": "amd64",
        "config": {"Labels": {
            "org.opencontainers.image.version": tag,
            "task012.release": name,
            "task012.synthetic": "true",
        }},
        "created": "1970-01-01T00:00:00Z",
        "history": [{
            "created": "1970-01-01T00:00:00Z",
            "created_by": "Task 012A deterministic non-executable fixture",
        }],
        "os": "linux",
        "rootfs": {"diff_ids": [sha256_digest(uncompressed_layer)], "type": "layers"},
    })
    manifest = canonical_json({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": CONFIG_MEDIA_TYPE,
            "digest": sha256_digest(config),
            "size": len(config),
        },
        "layers": [{
            "mediaType": LAYER_MEDIA_TYPE,
            "digest": sha256_digest(layer),
            "size": len(layer),
        }],
    })
    return Release(
        name=name,
        tag=tag,
        manifest=manifest,
        config=config,
        layer=layer,
        manifest_digest=sha256_digest(manifest),
        config_digest=sha256_digest(config),
        layer_digest=sha256_digest(layer),
    )


def build_fixture() -> tuple[Release, Release]:
    current = build_release("CURRENT", "task012-current")
    rollback = build_release("ROLLBACK", "task012-rollback")
    if len({current.manifest_digest, rollback.manifest_digest}) != 2:
        raise RuntimeError("CURRENT and ROLLBACK manifests are not distinct")
    if len({current.config_digest, rollback.config_digest}) != 2:
        raise RuntimeError("CURRENT and ROLLBACK configs are not distinct")
    if len({current.layer_digest, rollback.layer_digest}) != 2:
        raise RuntimeError("CURRENT and ROLLBACK layers are not distinct")
    return current, rollback
