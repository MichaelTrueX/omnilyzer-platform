#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from common import load_json, sha256_file


FORBIDDEN = re.compile(r"(?:^|/)(?:\.git|\.env|__pycache__|node_modules|dist|\.venv)(?:/|$)|(?:\.pem|\.key)$", re.I)
DEVELOPER_PATH = re.compile(rb"/(?:home|users|repos?|workspaces?)/|[a-z]:\\users\\", re.I)


def has_sensitive_content(content):
    return DEVELOPER_PATH.search(content) is not None or b"PRIVATE KEY" in content


def validate_release_set(manifest):
    release = manifest["platformReleaseVersion"]
    artifacts = manifest["artifacts"]
    if len(artifacts) != 3:
        raise AssertionError("a coordinated release manifest must identify exactly three artifacts")
    if any(item["artifactPackageVersion"] != release for item in artifacts):
        raise AssertionError("mixed package versions are forbidden in a coordinated release set")
    if len({item["artifactPackageName"] for item in artifacts}) != 3:
        raise AssertionError("release manifest package names must be unique")


def verify_hashes(release_dir: Path, manifest=None):
    manifest = manifest or load_json(release_dir / "release-manifest.json")
    validate_release_set(manifest)
    for item in manifest["artifacts"]:
        artifact = release_dir / item["artifactFilename"]
        if sha256_file(artifact) != item["artifactSha256"]:
            raise AssertionError(f"artifact hash mismatch: {artifact.name}")


def safe_members(names):
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise AssertionError(f"unsafe archive path: {name}")
        if FORBIDDEN.search(name) or "omnilyzer-platform/" in name:
            raise AssertionError(f"forbidden archive content: {name}")


def inspect_archives(release_dir: Path):
    manifest = load_json(release_dir / "release-manifest.json")
    for item in manifest["artifacts"]:
        artifact = release_dir / item["artifactFilename"]
        if item["artifactType"] == "python-wheel":
            with zipfile.ZipFile(artifact) as archive:
                names = archive.namelist()
                safe_members(names)
                allowed_package = {
                    "omnilyzer_platform_core/__init__.py",
                    "omnilyzer_platform_core/_internal.py",
                    "omnilyzer_platform_core/public-contract.json",
                }
                for name in names:
                    if not (name in allowed_package or ".dist-info/" in name):
                        raise AssertionError(f"unexpected wheel member: {name}")
                    content = archive.read(name)
                    if has_sensitive_content(content):
                        raise AssertionError(f"sensitive/source path content in wheel: {name}")
                metadata = next(name for name in names if name.endswith(".dist-info/METADATA"))
                if f"Version: {item['artifactPackageVersion']}" not in archive.read(metadata).decode():
                    raise AssertionError("wheel metadata version does not match release")
        else:
            with tarfile.open(artifact, "r:gz") as archive:
                names = archive.getnames()
                safe_members(names)
                package_name = item["artifactPackageName"]
                expected = {"package/package.json", "package/public-contract.json"}
                expected |= ({"package/index.js"} if package_name.endswith("web-contract") else {"package/cli.js", "package/rules.js"})
                if set(names) != expected:
                    raise AssertionError(f"unexpected npm archive members: {set(names) ^ expected}")
                package = json.load(archive.extractfile("package/package.json"))
                if package.get("version") != item["artifactPackageVersion"]:
                    raise AssertionError("npm package version does not match release")
                if any(key in package for key in ("scripts", "preinstall", "install", "postinstall")):
                    raise AssertionError("npm lifecycle scripts are forbidden")
                if package.get("dependencies"):
                    raise AssertionError("runtime dependencies/network access are forbidden")
                for member in archive.getmembers():
                    if member.isfile():
                        content = archive.extractfile(member).read()
                        if has_sensitive_content(content):
                            raise AssertionError(f"sensitive/source path content in npm artifact: {member.name}")
