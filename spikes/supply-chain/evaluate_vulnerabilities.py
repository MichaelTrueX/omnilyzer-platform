"""Deterministically evaluate Grype SBOM scan reports against release policy."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import date, datetime
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qs, urlparse


SCHEMA_VERSION = 1
SCANNER_NAME = "grype"
SCANNER_VERSION = "0.118.0"
SEVERITIES = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")
POLICY_FIELDS = {"schema_version", "block_severities", "exceptions"}
EXCEPTION_FIELDS = {
    "vulnerability_id",
    "package_name",
    "package_version",
    "expires_on",
    "rationale",
}
TARGET_FILENAMES = {
    "python": "python-vulnerabilities.grype.json",
    "npm": "npm-vulnerabilities.grype.json",
    "oci": "oci-vulnerabilities.grype.json",
}
RAW_DATABASE_STATUS_FIELDS = {"schemaVersion", "from", "built", "path", "valid"}
SANITIZED_DATABASE_STATUS_FIELDS = {"built", "checksum", "schema_version", "valid"}
PATTERN_MARKERS = re.compile(r"[*?\[\]{}()|^$\\]")
RFC3339_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)


class EvaluationError(ValueError):
    """Raised when policy or scanner evidence cannot be evaluated safely."""


def _load_json(path: Path, description: str) -> Any:
    """Load one UTF-8 JSON document and convert parse failures to fail-closed errors."""

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvaluationError(f"invalid {description}: {error}") from error


def _sha256(path: Path) -> str:
    """Return the lowercase SHA-256 digest of a regular local evidence file."""

    if path.is_symlink() or not path.is_file():
        raise EvaluationError(f"evidence input is not a regular file: {path}")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise EvaluationError(f"unable to hash evidence input: {path}") from error
    return digest.hexdigest()


def parse_evaluation_date(value: str) -> date:
    """Parse an explicitly supplied canonical UTC calendar date."""

    try:
        parsed = date.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise EvaluationError("current date must be YYYY-MM-DD") from error
    if parsed.isoformat() != value:
        raise EvaluationError("current date must be canonical YYYY-MM-DD")
    return parsed


def _require_exact_identity(value: Any, field: str) -> str:
    """Validate a non-empty literal exception identity with no pattern syntax."""

    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise EvaluationError(f"exception {field} must be a non-empty exact string")
    if PATTERN_MARKERS.search(value):
        raise EvaluationError(f"exception {field} must not contain wildcard or regex syntax")
    return value


def validate_policy(document: Any, evaluated_on: date) -> dict[str, Any]:
    """Validate the complete versioned policy and all time-bounded exceptions."""

    if not isinstance(document, dict) or set(document) != POLICY_FIELDS:
        raise EvaluationError("policy must contain exactly the supported fields")
    if document.get("schema_version") != SCHEMA_VERSION:
        raise EvaluationError("unsupported policy schema_version")
    block_severities = document.get("block_severities")
    if (
        not isinstance(block_severities, list)
        or not block_severities
        or any(severity not in SEVERITIES for severity in block_severities)
        or len(set(block_severities)) != len(block_severities)
    ):
        raise EvaluationError("block_severities must be a unique list of known severities")
    exceptions = document.get("exceptions")
    if not isinstance(exceptions, list):
        raise EvaluationError("policy exceptions must be a list")

    validated_exceptions: list[dict[str, str]] = []
    observed: set[tuple[str, str, str]] = set()
    for exception in exceptions:
        if not isinstance(exception, dict) or set(exception) != EXCEPTION_FIELDS:
            raise EvaluationError("each exception must contain exactly the supported fields")
        vulnerability_id = _require_exact_identity(
            exception.get("vulnerability_id"), "vulnerability_id"
        )
        package_name = _require_exact_identity(exception.get("package_name"), "package_name")
        package_version = _require_exact_identity(
            exception.get("package_version"), "package_version"
        )
        rationale = exception.get("rationale")
        if not isinstance(rationale, str) or not rationale.strip():
            raise EvaluationError("exception rationale must be non-empty")
        expires_value = exception.get("expires_on")
        try:
            expires_on = date.fromisoformat(expires_value)
        except (TypeError, ValueError) as error:
            raise EvaluationError("exception expires_on must be YYYY-MM-DD") from error
        if expires_on.isoformat() != expires_value:
            raise EvaluationError("exception expires_on must be canonical YYYY-MM-DD")
        if evaluated_on >= expires_on:
            raise EvaluationError("expired exception makes policy invalid")
        identity = (vulnerability_id, package_name, package_version)
        if identity in observed:
            raise EvaluationError("duplicate vulnerability exception")
        observed.add(identity)
        validated_exceptions.append(
            {
                "vulnerability_id": vulnerability_id,
                "package_name": package_name,
                "package_version": package_version,
                "expires_on": expires_value,
                "rationale": rationale.strip(),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "block_severities": list(block_severities),
        "exceptions": validated_exceptions,
    }


def sanitize_raw_database_status(document: Any) -> dict[str, Any]:
    """Convert a Grype v0.118 ProviderStatus into canonical path-free evidence."""

    if not isinstance(document, dict):
        raise EvaluationError("raw Grype DB status must be a JSON object")
    fields = set(document)
    if fields != RAW_DATABASE_STATUS_FIELDS and fields != RAW_DATABASE_STATUS_FIELDS | {"error"}:
        raise EvaluationError("raw Grype DB status has unexpected fields")
    schema_version = document.get("schemaVersion")
    built = document.get("built")
    source = document.get("from")
    database_path = document.get("path")
    if not isinstance(schema_version, str) or not schema_version.strip():
        raise EvaluationError("raw Grype DB status has no schemaVersion")
    if not isinstance(built, str) or RFC3339_PATTERN.fullmatch(built) is None:
        raise EvaluationError("raw Grype DB status built is not RFC3339")
    try:
        timestamp = built.removesuffix("Z") + ("+00:00" if built.endswith("Z") else "")
        parsed_built = datetime.fromisoformat(timestamp)
    except ValueError as error:
        raise EvaluationError("raw Grype DB status built is not RFC3339") from error
    if parsed_built.tzinfo is None:
        raise EvaluationError("raw Grype DB status built has no timezone")
    if not isinstance(database_path, str) or not database_path.strip():
        raise EvaluationError("raw Grype DB status has no path")
    if document.get("valid") is not True:
        raise EvaluationError("raw Grype DB status is not valid")
    if document.get("error") not in (None, ""):
        raise EvaluationError("raw Grype DB status reports an error")
    if not isinstance(source, str):
        raise EvaluationError("raw Grype DB status has no from URL")
    parsed_source = urlparse(source)
    if parsed_source.scheme != "https" or not parsed_source.netloc:
        raise EvaluationError("raw Grype DB status from must be an HTTPS URL")
    try:
        query = parse_qs(parsed_source.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as error:
        raise EvaluationError("raw Grype DB status from has a malformed query") from error
    checksums = query.get("checksum")
    if not isinstance(checksums, list) or len(checksums) != 1:
        raise EvaluationError("raw Grype DB status must contain exactly one checksum")
    checksum = checksums[0]
    if re.fullmatch(r"sha256:[0-9a-f]{64}", checksum) is None:
        raise EvaluationError("raw Grype DB status checksum is malformed")
    return {
        "built": built,
        "checksum": checksum,
        "schema_version": schema_version,
        "valid": True,
    }


def validate_database_status(document: Any) -> dict[str, Any]:
    """Require the exact canonical sanitized Grype database evidence structure."""

    if not isinstance(document, dict) or set(document) != SANITIZED_DATABASE_STATUS_FIELDS:
        raise EvaluationError("sanitized Grype DB status has unexpected fields")
    schema_version = document.get("schema_version")
    built = document.get("built")
    checksum = document.get("checksum")
    if not isinstance(schema_version, str) or not schema_version.strip():
        raise EvaluationError("sanitized Grype DB status has no schema version")
    if not isinstance(built, str) or not built.strip():
        raise EvaluationError("sanitized Grype DB status has no build identity")
    if not isinstance(checksum, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", checksum) is None:
        raise EvaluationError("sanitized Grype DB status has no valid checksum")
    if document.get("valid") is not True:
        raise EvaluationError("sanitized Grype DB status is not valid")
    return dict(document)


def sanitize_database_status_file(raw_path: Path, output_path: Path) -> None:
    """Read raw ProviderStatus JSON and write deterministic canonical evidence."""

    if output_path.exists():
        raise EvaluationError("refusing to overwrite sanitized Grype DB status")
    sanitized = sanitize_raw_database_status(_load_json(raw_path, "raw Grype DB status"))
    try:
        output_path.write_text(
            json.dumps(sanitized, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as error:
        raise EvaluationError("unable to write sanitized Grype DB status") from error


def _validate_finding(match: Any, target: str) -> dict[str, str]:
    """Normalize the exact Grype fields needed for one policy decision."""

    if not isinstance(match, dict):
        raise EvaluationError(f"{target} Grype match must be an object")
    vulnerability = match.get("vulnerability")
    artifact = match.get("artifact")
    if not isinstance(vulnerability, dict) or not isinstance(artifact, dict):
        raise EvaluationError(f"{target} Grype match lacks vulnerability or artifact data")
    finding = {
        "vulnerability_id": vulnerability.get("id"),
        "severity": vulnerability.get("severity"),
        "package_name": artifact.get("name"),
        "package_version": artifact.get("version"),
    }
    for field, value in finding.items():
        if not isinstance(value, str) or not value:
            raise EvaluationError(f"{target} Grype match has invalid {field}")
    if finding["severity"] not in SEVERITIES:
        raise EvaluationError(f"{target} Grype match has an unexpected severity")
    return finding


def validate_grype_report(document: Any, target: str) -> list[dict[str, str]]:
    """Validate a Grype-compatible result structure and normalize its matches."""

    if not isinstance(document, dict):
        raise EvaluationError(f"{target} Grype report must be a JSON object")
    descriptor = document.get("descriptor")
    if not isinstance(descriptor, dict):
        raise EvaluationError(f"{target} Grype report has no descriptor")
    if descriptor.get("name") != SCANNER_NAME or descriptor.get("version") != SCANNER_VERSION:
        raise EvaluationError(f"{target} Grype report has an unexpected scanner identity")
    matches = document.get("matches")
    if not isinstance(matches, list):
        raise EvaluationError(f"{target} Grype report has no matches list")
    findings = [_validate_finding(match, target) for match in matches]
    return sorted(
        findings,
        key=lambda finding: (
            finding["vulnerability_id"],
            finding["package_name"],
            finding["package_version"],
            finding["severity"],
        ),
    )


def evaluate(
    policy_path: Path,
    report_paths: Mapping[str, Path],
    database_status_path: Path,
    evaluated_at_date: str,
) -> dict[str, Any]:
    """Evaluate three Grype reports and return stable, non-secret decision evidence."""

    if set(report_paths) != set(TARGET_FILENAMES):
        raise EvaluationError("exactly python, npm, and oci reports are required")
    evaluated_on = parse_evaluation_date(evaluated_at_date)
    policy = validate_policy(_load_json(policy_path, "vulnerability policy"), evaluated_on)
    database = validate_database_status(
        _load_json(database_status_path, "Grype DB status")
    )
    exceptions = {
        (
            item["vulnerability_id"],
            item["package_name"],
            item["package_version"],
        ): item
        for item in policy["exceptions"]
    }
    targets: dict[str, Any] = {}
    release_blocked = False
    for target in sorted(TARGET_FILENAMES):
        path = report_paths[target]
        if path.name != TARGET_FILENAMES[target]:
            raise EvaluationError(f"unexpected {target} scan report filename")
        findings = validate_grype_report(_load_json(path, f"{target} Grype report"), target)
        severity_counts = Counter(finding["severity"] for finding in findings)
        blocking: list[dict[str, str]] = []
        excepted: list[dict[str, str]] = []
        for finding in findings:
            if finding["severity"] not in policy["block_severities"]:
                continue
            identity = (
                finding["vulnerability_id"],
                finding["package_name"],
                finding["package_version"],
            )
            exception = exceptions.get(identity)
            if exception is None:
                blocking.append(finding)
            else:
                excepted.append(
                    {
                        **finding,
                        "expires_on": exception["expires_on"],
                        "rationale": exception["rationale"],
                    }
                )
        if blocking:
            release_blocked = True
        targets[target] = {
            "scan_report_filename": path.name,
            "scan_report_sha256": _sha256(path),
            "total_matches": len(findings),
            "severity_counts": {
                severity: severity_counts.get(severity, 0) for severity in SEVERITIES
            },
            "blocking_findings": blocking,
            "excepted_findings": excepted,
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "policy": {
            "block_severities": policy["block_severities"],
            "policy_sha256": _sha256(policy_path),
        },
        "scanner": {"name": SCANNER_NAME, "version": SCANNER_VERSION},
        "database": database,
        "targets": targets,
        "decision": "BLOCK" if release_blocked else "PASS",
        "evaluated_at_date": evaluated_on.isoformat(),
    }


def write_result(path: Path, result: Mapping[str, Any]) -> None:
    """Write newline-terminated JSON with deterministic key and list ordering."""

    if path.exists():
        raise EvaluationError("refusing to overwrite vulnerability policy result")
    try:
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as error:
        raise EvaluationError(f"unable to write policy result: {path}") from error


def _parser() -> argparse.ArgumentParser:
    """Build the command-line interface used by the non-OIDC build job."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--python-report", type=Path, required=True)
    parser.add_argument("--npm-report", type=Path, required=True)
    parser.add_argument("--oci-report", type=Path, required=True)
    parser.add_argument("--db-status", type=Path, required=True)
    parser.add_argument("--current-date", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Evaluate CLI inputs, write evidence for PASS/BLOCK, and fail closed on BLOCK."""

    arguments_list = list(sys.argv[1:] if argv is None else argv)
    if arguments_list[:1] == ["sanitize-db-status"]:
        if len(arguments_list) != 3:
            print(
                "usage: evaluate_vulnerabilities.py sanitize-db-status RAW OUTPUT",
                file=sys.stderr,
            )
            return 2
        try:
            sanitize_database_status_file(
                Path(arguments_list[1]), Path(arguments_list[2])
            )
        except EvaluationError as error:
            print(f"Grype DB status sanitization failed: {error}", file=sys.stderr)
            return 2
        return 0
    arguments = _parser().parse_args(arguments_list)
    try:
        result = evaluate(
            arguments.policy,
            {
                "python": arguments.python_report,
                "npm": arguments.npm_report,
                "oci": arguments.oci_report,
            },
            arguments.db_status,
            arguments.current_date,
        )
        write_result(arguments.output, result)
    except EvaluationError as error:
        print(f"vulnerability policy evaluation failed: {error}", file=sys.stderr)
        return 2
    return 0 if result["decision"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
