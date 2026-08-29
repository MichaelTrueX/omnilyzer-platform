from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = ROOT.parents[1]
VERSIONS = ("1.0.0", "1.1.0")
PACKAGES = ("python-core", "web-contract", "design-governance")
PACKAGE_NAMES = {
    "python-core": "omnilyzer-platform-core",
    "web-contract": "@omnilyzer/platform-web-contract",
    "design-governance": "@omnilyzer/design-governance",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_tree_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    for file_path in sorted(item for item in path.rglob("*") if item.is_file()):
        relative = file_path.relative_to(path).as_posix().encode()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        content = file_path.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def run(command, *, cwd=None, env=None, expect=0):
    completed = subprocess.run(
        [str(value) for value in command], cwd=cwd, env=env,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    if completed.returncode != expect:
        raise AssertionError(
            f"command returned {completed.returncode}, expected {expect}: {' '.join(map(str, command))}\n{completed.stdout}"
        )
    return completed


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def clean_environment(node_bin: Path | None = None):
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONHASHSEED"] = "0"
    env["SOURCE_DATE_EPOCH"] = "1704067200"
    env["TZ"] = "UTC"
    env["LC_ALL"] = "C.UTF-8"
    if node_bin:
        env["PATH"] = str(node_bin) + os.pathsep + env.get("PATH", "")
    return env

