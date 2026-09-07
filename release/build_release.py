#!/usr/bin/env python3
"""Build coordinated release artifacts in the build-only trust zone."""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import io
import json
import shutil
import tarfile
import tomllib
import zipfile
from pathlib import Path
from typing import Any

try:
    from .executable_oci import verify_executable_archive
    from .release_plan import load_json, validate_plan
    from .vulnerability_policy import canonical_bytes
except ImportError:  # Direct execution in GitHub Actions.
    from executable_oci import verify_executable_archive
    from release_plan import load_json, validate_plan
    from vulnerability_policy import canonical_bytes

EPOCH = 946684800  # 2000-01-01, supported by ZIP and tar.


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _zip_write(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, (2000, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data)


def _source_files(source: Path) -> list[tuple[str, bytes]]:
    entries: list[tuple[str, bytes]] = []
    for path in sorted(source.rglob("*")):
        relative_path = path.relative_to(source)
        if path.is_symlink():
            raise ValueError(f"source contains a symlink: {relative_path}")
        if any(part in {"__pycache__", "node_modules", ".git"} for part in relative_path.parts) or path.suffix == ".pyc":
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"source contains unsupported filesystem entry: {path.relative_to(source)}")
        relative = relative_path.as_posix()
        if relative.startswith("../") or "\\" in relative:
            raise ValueError("source entry escaped its build root")
        entries.append((relative, path.read_bytes()))
    if not entries:
        raise ValueError("source directory is empty")
    return entries


def build_wheel(source: Path, package_name: str, version: str) -> bytes:
    project = tomllib.loads((source / "pyproject.toml").read_text(encoding="utf-8")).get("project", {})
    if project.get("name") != package_name:
        raise ValueError("Python source identity differs from release plan")
    description = project.get("description")
    if not isinstance(description, str) or "\n" in description:
        raise ValueError("Python project description must be a single string")
    module_name = package_name.replace("-", "_")
    module_prefix = f"src/{module_name}/"
    module_files = {name.removeprefix("src/"): data for name, data in _source_files(source)
                    if name.startswith(module_prefix)}
    if f"{module_name}/__init__.py" not in module_files:
        raise ValueError(f"Python source lacks src/{module_name}/__init__.py")
    dist = f"{module_name}-{version}.dist-info"
    metadata = (
        f"Metadata-Version: 2.3\nName: {package_name}\n"
        f"Version: {version}\nSummary: {description}\n\n"
    ).encode()
    wheel = b"Wheel-Version: 1.0\nGenerator: omnilyzer-task013\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    entries = {
        **module_files,
        f"{dist}/METADATA": metadata,
        f"{dist}/WHEEL": wheel,
    }
    records: list[list[str]] = []
    for name in sorted(entries):
        value = entries[name]
        encoded = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode()
        records.append([name, f"sha256={encoded}", str(len(value))])
    record_name = f"{dist}/RECORD"
    records.append([record_name, "", ""])
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(records)
    entries[record_name] = output.getvalue().encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in sorted(entries):
            _zip_write(archive, name, entries[name])
    return buffer.getvalue()


def _tar_info(name: str, size: int, mode: int = 0o644) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = mode
    info.mtime = EPOCH
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def build_npm(source: Path, package_name: str, version: str) -> bytes:
    package = json.loads((source / "package.json").read_text(encoding="utf-8"))
    if package.get("name") != package_name:
        raise ValueError("npm source identity differs from release plan")
    package["version"] = version
    entries = {f"package/{name}": data for name, data in _source_files(source) if name != "package.json"}
    entries["package/package.json"] = canonical_bytes(package)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(entries):
            data = entries[name]
            archive.addfile(_tar_info(name, len(data)), io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=0) as stream:
        stream.write(raw.getvalue())
    return compressed.getvalue()


def build_oci(source: Path, repository_name: str, version: str) -> tuple[bytes, str]:
    layer_tar = io.BytesIO()
    with tarfile.open(fileobj=layer_tar, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, payload in _source_files(source):
            archive.addfile(_tar_info(name, len(payload)), io.BytesIO(payload))
    layer_raw = layer_tar.getvalue()
    layer_gz = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=layer_gz, mtime=0) as stream:
        stream.write(layer_raw)
    layer = layer_gz.getvalue()
    config = canonical_bytes({
        "architecture": "amd64", "os": "linux",
        "config": {"Labels": {"org.opencontainers.image.version": version,
                               "org.opencontainers.image.title": repository_name}},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{digest(layer_raw)}"]},
        "history": [{"created_by": "Omnilyzer deterministic release builder"}],
    })
    manifest = canonical_bytes({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": f"sha256:{digest(config)}", "size": len(config)},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": f"sha256:{digest(layer)}", "size": len(layer)}],
    })
    manifest_digest = f"sha256:{digest(manifest)}"
    index = canonical_bytes({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                       "digest": manifest_digest, "size": len(manifest),
                       "annotations": {"org.opencontainers.image.ref.name": version}}],
    })
    entries = {
        "oci-layout": canonical_bytes({"imageLayoutVersion": "1.0.0"}),
        "index.json": index,
        f"blobs/sha256/{digest(config)}": config,
        f"blobs/sha256/{digest(layer)}": layer,
        f"blobs/sha256/{digest(manifest)}": manifest,
    }
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(entries):
            data = entries[name]
            archive.addfile(_tar_info(name, len(data)), io.BytesIO(data))
    return output.getvalue(), manifest_digest


def artifact_record(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    return {"filename": path.name, "sha256": digest(raw), "size": len(raw)}


def build_packages(plan_path: Path, output: Path, repository: Path) -> dict[str, Any]:
    plan = validate_plan(load_json(plan_path), repository)
    if output.exists() and any(output.iterdir()):
        raise ValueError("output directory must be new or empty")
    output.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(plan_path, output / "release-plan.json")
    version = plan["platform_version"]
    sources = {key: repository / value for key, value in plan["sources"].items()}
    artifacts = plan["artifacts"]
    wheel = build_wheel(sources["python"], plan["packages"]["python"]["name"], version)
    npm = build_npm(sources["npm"], plan["packages"]["npm"]["name"], version)
    for filename, data in ((artifacts["python_wheel"], wheel), (artifacts["npm_tarball"], npm)):
        (output / filename).write_bytes(data)
    return {"oci_source": sources["oci"], "oci_archive": output / artifacts["oci_archive"]}


def synthetic_sbom(name: str, artifact: Path) -> dict[str, Any]:
    raw = artifact.read_bytes()
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "file", "name": name,
                                    "hashes": [{"alg": "SHA-256", "content": digest(raw)}]}},
        "components": [],
    }


def local_canary(plan_path: Path, output: Path, repository: Path, policy: Path, evaluation_date: str) -> None:
    from datetime import date
    try:
        from .vulnerability_policy import evaluate
    except ImportError:
        from vulnerability_policy import evaluate
    info = build_packages(plan_path, output, repository)
    plan = load_json(output / "release-plan.json")
    oci, manifest_digest = build_oci(
        info["oci_source"], plan["packages"]["oci"]["repository"], plan["platform_version"],
    )
    info["oci_archive"].write_bytes(oci)
    artifact_paths = {
        "python": output / plan["artifacts"]["python_wheel"],
        "npm": output / plan["artifacts"]["npm_tarball"],
        "oci": output / plan["artifacts"]["oci_archive"],
    }
    for kind, path in artifact_paths.items():
        (output / plan["artifacts"]["sboms"][kind]).write_bytes(canonical_bytes(synthetic_sbom(kind, path)))
        report = {"descriptor": {"name": "grype", "version": plan["tool_versions"]["grype"]},
                  "matches": [], "source": {"type": "local-synthetic-canary"}}
        (output / plan["artifacts"]["vulnerability_reports"][kind]).write_bytes(canonical_bytes(report))
    shutil.copyfile(policy, output / "vulnerability-policy.json")
    result = evaluate(output / "vulnerability-policy.json",
                      {kind: output / plan["artifacts"]["vulnerability_reports"][kind]
                       for kind in artifact_paths}, date.fromisoformat(evaluation_date))
    (output / "vulnerability-policy-result.json").write_bytes(canonical_bytes(result))
    (output / "grype-db-status.json").write_bytes(canonical_bytes({
        "built": "2000-01-01T00:00:00Z", "checksum": f"sha256:{'0' * 64}",
        "schema_version": "local-synthetic-canary", "valid": True,
    }))
    finalize(output, repository, manifest_digest, "local-synthetic-canary")


def finalize(root: Path, repository: Path, expected_oci_digest: str, evidence_mode: str) -> None:
    plan_path = root / "release-plan.json"
    plan = validate_plan(load_json(plan_path), repository)
    oci_archive = root / plan["artifacts"]["oci_archive"]
    if evidence_mode == "production-tools":
        verified_digest = verify_executable_archive(
            oci_archive, plan["platform_version"], plan["source_commit"],
            plan["packages"]["oci"]["repository"],
        )
        if verified_digest != expected_oci_digest:
            raise ValueError("verified executable OCI digest differs from the final archive")
    artifacts = {
        key: artifact_record(root / plan["artifacts"][field])
        for key, field in (("python", "python_wheel"), ("npm", "npm_tarball"), ("oci", "oci_archive"))
    }
    sboms = {key: artifact_record(root / filename) for key, filename in plan["artifacts"]["sboms"].items()}
    reports = {key: artifact_record(root / filename)
               for key, filename in plan["artifacts"]["vulnerability_reports"].items()}
    policy = (root / "vulnerability-policy.json").read_bytes()
    database_status = root / "grype-db-status.json"
    policy_result_path = root / "vulnerability-policy-result.json"
    result = load_json(root / "vulnerability-policy-result.json")
    if result.get("decision") != "PASS" or result.get("policy_sha256") != digest(policy):
        raise ValueError("vulnerability evidence is not an exact PASS for the bundled policy")
    manifest = {
        "schema_version": 1,
        "platform_version": plan["platform_version"], "source_commit": plan["source_commit"],
        "plan_sha256": digest(plan_path.read_bytes()), "artifacts": artifacts, "sboms": sboms,
        "vulnerability_reports": reports, "vulnerability_policy_sha256": digest(policy),
        "vulnerability_policy_result_sha256": digest(policy_result_path.read_bytes()),
        "grype_database_status_sha256": digest(database_status.read_bytes()),
        "expected_oci_manifest_digest": expected_oci_digest,
        "tool_versions": plan["tool_versions"], "evidence_mode": evidence_mode,
    }
    (root / "build-manifest.json").write_bytes(canonical_bytes(manifest))


def oci_digest_from_archive(path: Path) -> str:
    with tarfile.open(path, "r") as archive:
        index_file = archive.extractfile("index.json")
        if index_file is None:
            raise ValueError("OCI archive lacks index.json")
        index = json.load(index_file)
    digest_value = index["manifests"][0]["digest"]
    if not isinstance(digest_value, str) or not digest_value.startswith("sha256:"):
        raise ValueError("OCI archive index lacks exact manifest digest")
    return digest_value


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    packages = sub.add_parser("packages")
    local = sub.add_parser("local-canary")
    final = sub.add_parser("finalize")
    for command in (packages, local):
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--repository", type=Path, default=Path.cwd())
    local.add_argument("--policy", type=Path, required=True)
    local.add_argument("--evaluation-date", required=True)
    final.add_argument("--handoff", type=Path, required=True)
    final.add_argument("--repository", type=Path, default=Path.cwd())
    final.add_argument("--evidence-mode", choices=("production-tools",), required=True)
    args = parser.parse_args()
    if args.command == "packages":
        build_packages(args.plan, args.output, args.repository)
    elif args.command == "local-canary":
        local_canary(args.plan, args.output, args.repository, args.policy, args.evaluation_date)
    else:
        plan = load_json(args.handoff / "release-plan.json")
        oci = args.handoff / plan["artifacts"]["oci_archive"]
        finalize(args.handoff, args.repository, oci_digest_from_archive(oci), args.evidence_mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
