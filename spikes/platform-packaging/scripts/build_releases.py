#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.metadata
import platform
import shutil
from pathlib import Path

from common import (PACKAGE_NAMES, PACKAGES, ROOT, VERSIONS, clean_environment,
                    dump_json, run, sha256_file, source_tree_sha256)


def build_all(output_root: Path, tooling_python: Path, node_bin: Path) -> None:
    env = clean_environment(node_bin)
    identity = {
        "python": platform.python_version(),
        "build": importlib.metadata.version("build"),
        "hatchling": importlib.metadata.version("hatchling"),
        "node": run([node_bin / "node", "--version"], env=env).stdout.strip(),
        "npm": run([node_bin / "npm", "--version"], env=env).stdout.strip(),
    }
    for version in VERSIONS:
        release_output = output_root / version
        release_output.mkdir(parents=True)
        artifacts = []
        for package in PACKAGES:
            source = ROOT / "release-sources" / version / package
            if package == "python-core":
                run([tooling_python, "-m", "build", "--wheel", "--no-isolation", "--outdir", release_output, source], env=env)
                artifact = next(release_output.glob("omnilyzer_platform_core-*.whl"))
                artifact_type = "python-wheel"
            else:
                before = set(release_output.glob("*.tgz"))
                run([node_bin / "npm", "pack", "--ignore-scripts", "--pack-destination", release_output, source], env=env)
                artifact = next(iter(set(release_output.glob("*.tgz")) - before))
                artifact_type = "npm-tarball"
            artifacts.append({
                "artifactFilename": artifact.name,
                "artifactPackageName": PACKAGE_NAMES[package],
                "artifactPackageVersion": version,
                "artifactSha256": sha256_file(artifact),
                "artifactType": artifact_type,
                "sourceTreeSha256": source_tree_sha256(source),
            })
        manifest = {
            "artifacts": sorted(artifacts, key=lambda item: item["artifactPackageName"]),
            "buildRuntimeToolIdentity": identity,
            "platformReleaseVersion": version,
            "schemaVersion": 1,
        }
        dump_json(release_output / "release-manifest.json", manifest)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("tooling_python", type=Path)
    parser.add_argument("node_bin", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        shutil.rmtree(args.output)
    build_all(args.output, args.tooling_python, args.node_bin)


if __name__ == "__main__":
    main()
