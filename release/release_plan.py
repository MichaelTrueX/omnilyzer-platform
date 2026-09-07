#!/usr/bin/env python3
"""Strict release-plan parsing and Task 013 plan materialization."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SEMVER_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
NAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
PYTHON_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
NPM_NAME_RE = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\Z")
FILENAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
OCI_RE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+\Z")

FORGEJO_ORIGIN = "https://registry-dev.omnilyzer.ai"
ZOT_ORIGIN = "https://oci-dev.omnilyzer.ai"
EXPECTED_WORKFLOW_REF = (
    "MichaelTrueX/omnilyzer-platform/.github/workflows/platform-release.yml"
    "@refs/heads/main"
)


class PlanError(ValueError):
    """The release plan is unsafe or does not satisfy its closed schema."""


def _object(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PlanError(f"{context} must be an object")
    actual = set(value)
    if actual != keys:
        raise PlanError(
            f"{context} fields differ: missing={sorted(keys - actual)} "
            f"unknown={sorted(actual - keys)}"
        )
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise PlanError(f"{context} must be a non-empty string")
    return value


def safe_source_path(repository: Path, relative: str) -> Path:
    """Resolve a committed source path without accepting escape or symlink tricks."""
    raw = _string(relative, "source path")
    if "\\" in raw:
        raise PlanError("source path may not contain backslashes")
    rel = Path(raw)
    if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
        raise PlanError(f"unsafe source path: {raw}")
    root = repository.resolve(strict=True)
    candidate = root.joinpath(rel)
    current = root
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            raise PlanError(f"source path traverses symlink: {raw}")
    resolved = candidate.resolve(strict=True)
    if root not in resolved.parents:
        raise PlanError(f"source path escapes repository: {raw}")
    if not resolved.is_dir():
        raise PlanError(f"source is not a directory: {raw}")
    return resolved


def _filename(value: Any, context: str) -> str:
    name = _string(value, context)
    if (Path(name).name != name or name in {".", ".."} or "\\" in name
            or FILENAME_RE.fullmatch(name) is None):
        raise PlanError(f"{context} must be a plain filename")
    return name


def validate_semver(value: str) -> str:
    if not SEMVER_RE.fullmatch(value):
        raise PlanError("platform_version must be strict X.Y.Z SemVer")
    return value


def validate_source_sha(value: str) -> str:
    if not SHA_RE.fullmatch(value) or value == "0" * 40:
        raise PlanError("source_commit must be a non-zero lowercase 40-character SHA")
    return value


def validate_environment(data: Any) -> dict[str, Any]:
    env = _object(
        data,
        {
            "schema_version", "publishing_enabled", "forgejo_origin",
            "forgejo_oidc_audience", "zot_origin", "zot_oidc_audience",
            "workflow_ref",
        },
        "environment",
    )
    if env["schema_version"] != 1:
        raise PlanError("unsupported environment schema_version")
    if not isinstance(env["publishing_enabled"], bool):
        raise PlanError("publishing_enabled must be boolean")
    if env["forgejo_origin"] != FORGEJO_ORIGIN or env["zot_origin"] != ZOT_ORIGIN:
        raise PlanError("registry origins differ from the reviewed DEV allowlist")
    if env["zot_oidc_audience"] != ZOT_ORIGIN:
        raise PlanError("zot OIDC audience must equal the reviewed DEV origin")
    _string(env["forgejo_oidc_audience"], "forgejo_oidc_audience")
    if env["workflow_ref"] != EXPECTED_WORKFLOW_REF:
        raise PlanError("workflow_ref is not the exact reviewed workflow identity")
    return env


def validate_plan(data: Any, repository: Path, *, check_sources: bool = True) -> dict[str, Any]:
    plan = _object(
        data,
        {"schema_version", "plan_id", "platform_version", "source_commit", "sources",
         "packages", "registries", "artifacts", "tool_versions"},
        "release plan",
    )
    if plan["schema_version"] != 1:
        raise PlanError("unsupported release-plan schema_version")
    if not NAME_RE.fullmatch(_string(plan["plan_id"], "plan_id")):
        raise PlanError("invalid plan_id")
    validate_semver(_string(plan["platform_version"], "platform_version"))
    validate_source_sha(_string(plan["source_commit"], "source_commit"))

    sources = _object(plan["sources"], {"python", "npm", "oci"}, "sources")
    if check_sources:
        for kind, path in sources.items():
            safe_source_path(repository, _string(path, f"sources.{kind}"))

    packages = _object(plan["packages"], {"python", "npm", "evidence", "oci"}, "packages")
    identities: list[str] = []
    for kind in ("python", "npm", "evidence"):
        package = _object(packages[kind], {"name", "owner"}, f"packages.{kind}")
        name = _string(package["name"], f"packages.{kind}.name")
        owner = _string(package["owner"], f"packages.{kind}.owner")
        if NAME_RE.fullmatch(owner) is None:
            raise PlanError("Forgejo owner is not a bounded package owner")
        if owner != "omnilyzer":
            raise PlanError("Forgejo package owner differs from the reviewed namespace")
        if kind == "npm" and NPM_NAME_RE.fullmatch(name) is None:
            raise PlanError("npm package name is not a bounded identity")
        if kind == "npm" and not name.startswith("@omnilyzer/"):
            raise PlanError("npm package is outside the reviewed @omnilyzer scope")
        if kind in {"python", "evidence"} and PYTHON_NAME_RE.fullmatch(name) is None:
            raise PlanError(f"{kind} package name is not a bounded identity")
        identities.append(f"{kind}:{owner}/{name}")
    oci = _object(packages["oci"], {"repository"}, "packages.oci")
    repository_name = _string(oci["repository"], "packages.oci.repository")
    if not OCI_RE.fullmatch(repository_name) or ":" in repository_name or "@" in repository_name:
        raise PlanError("OCI repository must be a bounded repository name without tag/digest")
    if not repository_name.startswith("omnilyzer/"):
        raise PlanError("OCI repository is outside the reviewed omnilyzer namespace")
    identities.append(f"oci:{repository_name}")
    if len(identities) != len(set(identities)):
        raise PlanError("duplicate package identities")

    registries = _object(plan["registries"], {"forgejo_origin", "zot_origin"}, "registries")
    if registries != {"forgejo_origin": FORGEJO_ORIGIN, "zot_origin": ZOT_ORIGIN}:
        raise PlanError("registry destinations differ from the reviewed DEV allowlist")

    artifacts = _object(
        plan["artifacts"],
        {"python_wheel", "npm_tarball", "oci_archive", "sboms", "vulnerability_reports"},
        "artifacts",
    )
    filenames = [
        _filename(artifacts["python_wheel"], "python_wheel"),
        _filename(artifacts["npm_tarball"], "npm_tarball"),
        _filename(artifacts["oci_archive"], "oci_archive"),
    ]
    sboms = _object(artifacts["sboms"], {"python", "npm", "oci"}, "artifacts.sboms")
    reports = _object(
        artifacts["vulnerability_reports"], {"python", "npm", "oci"},
        "artifacts.vulnerability_reports",
    )
    filenames.extend(_filename(value, f"sbom.{key}") for key, value in sboms.items())
    filenames.extend(_filename(value, f"report.{key}") for key, value in reports.items())
    if len(filenames) != len(set(filenames)):
        raise PlanError("artifact filenames must be unique")
    version = plan["platform_version"]
    if version not in artifacts["python_wheel"] or version not in artifacts["npm_tarball"] or version not in artifacts["oci_archive"]:
        raise PlanError("versioned artifacts must contain the coordinated platform version")
    if not artifacts["python_wheel"].endswith(".whl") or not artifacts["npm_tarball"].endswith(".tgz") or not artifacts["oci_archive"].endswith(".oci.tar"):
        raise PlanError("artifact filename extensions are not the reviewed formats")

    tools = _object(
        plan["tool_versions"],
        {"syft", "grype", "cosign", "cyclonedx_spec", "buildx", "buildkit"},
        "tool_versions",
    )
    expected_tools = {
        "syft": "1.51.0", "grype": "0.118.0", "cosign": "3.1.2",
        "cyclonedx_spec": "1.6", "buildx": "0.36.1", "buildkit": "0.24.0",
    }
    if tools != expected_tools:
        raise PlanError("tool versions differ from reviewed pins")
    return plan


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PlanError(f"cannot parse JSON {path}: {exc}") from exc


def materialize(template_path: Path, version: str, source_sha: str, output: Path, repository: Path) -> dict[str, Any]:
    validate_semver(version)
    validate_source_sha(source_sha)
    template = load_json(template_path)
    # Substitution is limited to string values and the two exact placeholders.
    def substitute(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: substitute(item) for key, item in value.items()}
        if isinstance(value, list):
            return [substitute(item) for item in value]
        if isinstance(value, str):
            return value.replace("{version}", version).replace("{source_commit}", source_sha)
        return value
    plan = substitute(template)
    validate_plan(plan, repository)
    if plan["platform_version"] != version or plan["source_commit"] != source_sha:
        raise PlanError("template did not bind the requested version and source SHA")
    if output.exists() or output.is_symlink():
        raise PlanError("refusing to overwrite a materialized release plan")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return plan


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("plan", type=Path)
    validate.add_argument("--repository", type=Path, default=Path.cwd())
    mat = sub.add_parser("materialize")
    mat.add_argument("template", type=Path)
    mat.add_argument("version")
    mat.add_argument("source_sha")
    mat.add_argument("output", type=Path)
    mat.add_argument("--repository", type=Path, default=Path.cwd())
    env = sub.add_parser("validate-environment")
    env.add_argument("path", type=Path)
    args = parser.parse_args()
    if args.command == "validate":
        validate_plan(load_json(args.plan), args.repository)
    elif args.command == "materialize":
        materialize(args.template, args.version, args.source_sha, args.output, args.repository)
    else:
        checked = validate_environment(load_json(args.path))
        print("true" if checked["publishing_enabled"] else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
