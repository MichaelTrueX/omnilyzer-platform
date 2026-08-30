#!/usr/bin/env python3
"""File: spikes/supply-chain/scripts/prepare_release.py
Purpose: Prepare coordinated synthetic release inputs outside committed fixtures.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil


VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
PLACEHOLDER = "0.0.0"
SPIKE_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = SPIKE_ROOT / "fixtures"
MUTABLE_FILES = (
    Path("python/pyproject.toml"),
    Path("python/src/omnilyzer_supply_chain_spike/__init__.py"),
    Path("npm/package.json"),
    Path("npm/index.js"),
    Path("oci/Dockerfile"),
)


def validate_version(version: str) -> str:
    """Accept only the deliberately narrow X.Y.Z release syntax."""
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError("release version must match X.Y.Z using decimal digits")
    return version


def prepare_release(version: str, output: Path) -> Path:
    """Copy fixtures into a new external directory and coordinate their version."""
    validated = validate_version(version)
    if not output.is_absolute():
        raise ValueError("output directory must be an absolute path")

    resolved_output = output.resolve(strict=False)
    if resolved_output == SPIKE_ROOT or SPIKE_ROOT in resolved_output.parents:
        raise ValueError("output directory must be outside committed spike sources")
    if resolved_output.exists():
        raise FileExistsError("output directory must not already exist")

    resolved_output.mkdir(parents=True)
    for family in ("python", "npm", "oci"):
        shutil.copytree(FIXTURE_ROOT / family, resolved_output / family)

    for relative_path in MUTABLE_FILES:
        target = resolved_output / relative_path
        content = target.read_text(encoding="utf-8")
        occurrences = content.count(PLACEHOLDER)
        if occurrences != 1:
            raise RuntimeError(
                f"expected one version placeholder in {relative_path}, found {occurrences}"
            )
        target.write_text(content.replace(PLACEHOLDER, validated), encoding="utf-8")

    record = {
        "version": validated,
        "python": {
            "name": "omnilyzer-supply-chain-spike",
            "wheel": f"omnilyzer_supply_chain_spike-{validated}-py3-none-any.whl",
        },
        "npm": {
            "name": "@omnilyzer/supply-chain-spike",
            "tarball": f"omnilyzer-supply-chain-spike-{validated}.tgz",
        },
        "oci": {
            "image": (
                "docker.cloudsmith.io/omnilyzer/platform-spike/"
                f"omnilyzer-supply-chain-spike:{validated}"
            )
        },
    }
    manifest = resolved_output / "release.json"
    manifest.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main() -> None:
    """Parse the narrow command-line interface and prepare release inputs."""
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="coordinated X.Y.Z release version")
    parser.add_argument("output", type=Path, help="new absolute output directory")
    arguments = parser.parse_args()
    manifest = prepare_release(arguments.version, arguments.output)
    print(manifest)


if __name__ == "__main__":
    main()
