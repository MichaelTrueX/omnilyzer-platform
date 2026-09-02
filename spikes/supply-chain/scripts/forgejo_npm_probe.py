#!/usr/bin/env python3
"""Run the Task 008C standard-npm Forgejo append-only probe."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
from urllib.error import HTTPError
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request, urlopen


PACKAGE_NAME = "@omnilyzer/supply-chain-spike"
REPLACEMENT_PATTERN = re.compile(
    r"(?:EPUBLISHCONFLICT|cannot\s+publish\s+over|previously\s+published|"
    r"already\s+exists?|version[^\n]{0,80}already\s+exists?|"
    r"E409|HTTP[^\n]{0,20}409|\b409\b[^\n]*conflict)",
    re.IGNORECASE,
)
UNPUBLISH_DENIAL_PATTERN = re.compile(r"(?:\b403\b|forbidden|E403)", re.IGNORECASE)


def file_digest(path: Path, algorithm: str) -> str:
    """Hash a file without loading an arbitrary package into memory."""

    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class Probe:
    """Exercise npm interoperability and append-only behavior independently."""

    def __init__(self, arguments: argparse.Namespace) -> None:
        self.base_url = arguments.forgejo_url.rstrip("/")
        self.owner = arguments.owner
        self.registry = f"{self.base_url}/api/packages/{quote(self.owner)}/npm/"
        self.handoff = Path(arguments.handoff).resolve(strict=True)
        self.summary_path = Path(arguments.summary)
        self.temp_root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        self.token_file = Path(arguments.token_file).resolve(strict=True)
        self.results = {
            "GitHub OIDC JWT acquisition": "FAIL",
            "Standard npm + OIDC JWT": "FAIL",
            "npm publish": "FAIL",
            "npm metadata read": "FAIL",
            "npm tarball retrieval": "FAIL",
            "npm SHA-256 round trip": "FAIL",
            "npm metadata SHA-1": "NOT EXPOSED",
            "npm metadata SHA-512 integrity": "NOT EXPOSED",
            "npm local install": "FAIL",
            "npm report() version": "FAIL",
            "standard npm pack/download": "FAIL",
            "same-version replacement": "FAIL",
            "post-replacement retrieval": "FAIL",
            "post-replacement integrity": "FAIL",
            "npm unpublish denied": "FAIL (not attempted)",
            "REST DELETE": "FAIL (not attempted)",
            "post-DELETE retrieval": "FAIL",
            "post-DELETE integrity": "FAIL",
            "Core npm append-only": "FAIL",
        }
        self.token = self.token_file.read_text(encoding="utf-8").strip()
        self.token_file.unlink()
        if not self.token:
            raise RuntimeError("OIDC token file was empty")
        self.results["GitHub OIDC JWT acquisition"] = "PASS"
        self.manifest = json.loads(
            (self.handoff / "handoff.json").read_text(encoding="utf-8")
        )
        self.package_name = self.manifest["package_name"]
        self.version = self.manifest["version"]
        self.tarball_name = self.manifest["tarball_filename"]
        self.baseline_sha256 = self.manifest["baseline_sha256"]
        self.replacement_sha256 = self.manifest["replacement_sha256"]
        self.baseline = self.handoff / "baseline" / self.tarball_name
        self.replacement = self.handoff / "replacement" / self.tarball_name
        self.npmrc = self.temp_root / "task008c-forgejo-npmrc"
        self.npm_cache = self.temp_root / "task008c-npm-cache"

    def verify_handoff(self) -> None:
        """Recheck the exact handoff and both package identities."""

        fields = {
            "package_name",
            "version",
            "tarball_filename",
            "baseline_sha256",
            "replacement_sha256",
            "baseline_sha1",
            "baseline_sha512",
            "source_commit",
        }
        if set(self.manifest) != fields:
            raise RuntimeError("npm handoff manifest fields are not exact")
        expected_version = (
            f"0.0.{os.environ['GITHUB_RUN_ID']}{os.environ['GITHUB_RUN_ATTEMPT']}"
        )
        if self.package_name != PACKAGE_NAME or self.version != expected_version:
            raise RuntimeError("npm handoff identity is unexpected")
        if self.manifest["source_commit"] != os.environ["GITHUB_SHA"]:
            raise RuntimeError("npm handoff source commit is unexpected")
        baseline_files = list((self.handoff / "baseline").glob("*.tgz"))
        replacement_files = list((self.handoff / "replacement").glob("*.tgz"))
        if baseline_files != [self.baseline] or replacement_files != [self.replacement]:
            raise RuntimeError("npm handoff tarball set is not exact")
        observed = {
            "baseline_sha256": file_digest(self.baseline, "sha256"),
            "replacement_sha256": file_digest(self.replacement, "sha256"),
            "baseline_sha1": file_digest(self.baseline, "sha1"),
            "baseline_sha512": file_digest(self.baseline, "sha512"),
        }
        for field, digest in observed.items():
            if not re.fullmatch(r"[0-9a-f]+", self.manifest[field]):
                raise RuntimeError(f"npm handoff {field} is malformed")
            if digest != self.manifest[field]:
                raise RuntimeError(f"npm handoff {field} mismatch")
        if self.baseline_sha256 == self.replacement_sha256:
            raise RuntimeError("npm baseline and replacement bytes are identical")
        for tarball in (self.baseline, self.replacement):
            with tarfile.open(tarball, "r:gz") as archive:
                package_json = json.load(archive.extractfile("package/package.json"))
            if package_json.get("name") != self.package_name:
                raise RuntimeError("npm tarball package name changed")
            if package_json.get("version") != self.version:
                raise RuntimeError("npm tarball package version changed")

    def configure_npm(self) -> dict[str, str]:
        """Write a path-scoped npm token configuration under RUNNER_TEMP."""

        parsed = urlparse(self.registry)
        auth_scope = f"//{parsed.netloc}{parsed.path}:_authToken"
        self.npmrc.write_text(
            f"@omnilyzer:registry={self.registry}\n"
            f"{auth_scope}={self.token}\n",
            encoding="utf-8",
        )
        self.npmrc.chmod(0o600)
        environment = os.environ.copy()
        environment.update(
            {
                "NPM_CONFIG_USERCONFIG": str(self.npmrc),
                "NPM_CONFIG_CACHE": str(self.npm_cache),
                "NPM_CONFIG_IGNORE_SCRIPTS": "true",
                "NPM_CONFIG_PROVENANCE": "false",
                "NPM_CONFIG_AUDIT": "false",
                "NPM_CONFIG_FUND": "false",
                "NPM_CONFIG_LOGS_MAX": "0",
            }
        )
        return environment

    def npm(
        self,
        arguments: list[str],
        environment: dict[str, str],
        log_name: str,
        *,
        cwd: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run standard npm with captured output so credentials cannot reach logs."""

        completed = subprocess.run(
            ["npm", *arguments],
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        combined_output = completed.stdout + completed.stderr
        if self.token in combined_output:
            raise RuntimeError("SECURITY FAILURE: npm output contained the OIDC JWT")
        log = self.temp_root / log_name
        log.write_text(combined_output, encoding="utf-8")
        return completed

    def publish_baseline(self, environment: dict[str, str]) -> None:
        completed = self.npm(
            [
                "publish",
                str(self.baseline),
                "--ignore-scripts",
                "--provenance=false",
            ],
            environment,
            "task008c-npm-publish.log",
        )
        if completed.returncode != 0:
            raise RuntimeError("standard npm baseline publication failed")
        self.results["Standard npm + OIDC JWT"] = "PASS"
        self.results["npm publish"] = "PASS"

    def metadata(self, environment: dict[str, str], label: str) -> dict[str, object]:
        completed = self.npm(
            ["view", f"{self.package_name}@{self.version}", "--json"],
            environment,
            f"task008c-npm-{label}-metadata.log",
        )
        if completed.returncode != 0:
            raise RuntimeError(f"npm metadata read failed during {label}")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError("npm metadata response was malformed") from error
        if not isinstance(payload, dict):
            raise RuntimeError("npm metadata response was not an object")
        if payload.get("name") != self.package_name or payload.get("version") != self.version:
            raise RuntimeError("npm metadata identity mismatch")
        dist = payload.get("dist")
        if not isinstance(dist, dict) or not isinstance(dist.get("tarball"), str):
            raise RuntimeError("npm metadata has no usable dist.tarball")
        self.results["npm metadata read"] = "PASS"
        return dist

    def validate_tarball_url(self, value: str) -> str:
        """Confine Forgejo's opaque server-controlled URL to this npm registry."""

        parsed_registry = urlparse(self.registry)
        parsed = urlparse(value)
        if parsed.scheme != "https":
            raise RuntimeError("npm metadata tarball URL escaped the Forgejo origin")
        if parsed.username is not None or parsed.password is not None:
            raise RuntimeError("npm metadata tarball URL contains credentials")
        try:
            configured_port = parsed_registry.port or 443
            observed_port = parsed.port or 443
        except ValueError as error:
            raise RuntimeError("npm metadata tarball URL has an invalid port") from error
        if (
            parsed.hostname is None
            or parsed_registry.hostname is None
            or parsed.hostname.lower() != parsed_registry.hostname.lower()
            or observed_port != configured_port
        ):
            raise RuntimeError("npm metadata tarball URL escaped the Forgejo origin")
        if parsed.query or parsed.fragment:
            raise RuntimeError("npm metadata tarball URL has unexpected suffix data")

        decoded_registry_path = unquote(parsed_registry.path)
        decoded_path = unquote(parsed.path)
        if "\\" in decoded_path or "\x00" in decoded_path:
            raise RuntimeError("npm metadata tarball URL contains an unsafe path")
        path_parts = decoded_path.split("/")
        if any(part in (".", "..") for part in path_parts):
            raise RuntimeError("npm metadata tarball URL contains path traversal")
        if not decoded_registry_path.endswith("/"):
            raise RuntimeError("configured Forgejo npm registry path is not canonical")
        if not decoded_path.startswith(decoded_registry_path):
            raise RuntimeError("npm metadata tarball URL escaped the Forgejo registry path")
        opaque_path = decoded_path.removeprefix(decoded_registry_path)
        if not any(part for part in opaque_path.split("/")):
            raise RuntimeError("npm metadata tarball URL has no registry object path")
        return value

    def download(self, tarball_url: str, label: str) -> Path:
        destination_directory = self.temp_root / f"task008c-npm-{label}"
        destination_directory.mkdir()
        destination = destination_directory / self.tarball_name
        request = Request(
            self.validate_tarball_url(tarball_url),
            headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            with urlopen(request, timeout=60) as response:
                if response.status != 200:
                    raise RuntimeError(
                        f"npm tarball retrieval returned HTTP {response.status}"
                    )
                destination.write_bytes(response.read())
        except HTTPError as error:
            raise RuntimeError(
                f"npm tarball retrieval returned HTTP {error.code}"
            ) from error
        self.results["npm tarball retrieval"] = "PASS"
        return destination

    def require_baseline_integrity(self, tarball: Path) -> None:
        observed = file_digest(tarball, "sha256")
        if observed == self.replacement_sha256:
            raise RuntimeError("SECURITY FAILURE: replacement npm tarball was published")
        if observed != self.baseline_sha256:
            raise RuntimeError("SECURITY FAILURE: published npm tarball bytes changed")

    def verify_metadata_hashes(self, dist: dict[str, object]) -> None:
        shasum = dist.get("shasum")
        if shasum is not None:
            if shasum != self.manifest["baseline_sha1"]:
                raise RuntimeError("npm metadata SHA-1 differs from baseline")
            self.results["npm metadata SHA-1"] = "PASS"
        integrity = dist.get("integrity")
        if isinstance(integrity, str) and integrity.startswith("sha512-"):
            expected = base64.b64encode(bytes.fromhex(self.manifest["baseline_sha512"])).decode()
            if integrity.removeprefix("sha512-") != expected:
                raise RuntimeError("npm metadata SHA-512 integrity differs from baseline")
            self.results["npm metadata SHA-512 integrity"] = "PASS"
        elif integrity is not None:
            self.results["npm metadata SHA-512 integrity"] = "NOT EXPOSED (non-sha512)"

    def install_downloaded(self, tarball: Path, environment: dict[str, str]) -> None:
        consumer = self.temp_root / "task008c-npm-consumer"
        consumer.mkdir()
        (consumer / "package.json").write_text(
            json.dumps({"name": "task008c-npm-consumer", "private": True}) + "\n",
            encoding="utf-8",
        )
        completed = self.npm(
            [
                "install",
                "--offline",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                str(tarball),
            ],
            environment,
            "task008c-npm-local-install.log",
            cwd=consumer,
        )
        if completed.returncode != 0:
            raise RuntimeError("registry-downloaded npm tarball installation failed")
        self.results["npm local install"] = "PASS"
        reported = subprocess.run(
            [
                "node",
                "--input-type=module",
                "--eval",
                (
                    "import { report } from '@omnilyzer/supply-chain-spike'; "
                    "process.stdout.write(report());"
                ),
            ],
            cwd=consumer,
            capture_output=True,
            text=True,
            check=True,
        )
        if reported.stdout != self.version:
            raise RuntimeError("installed npm package reported an unexpected version")
        self.results["npm report() version"] = "PASS"

    def standard_pack(self, environment: dict[str, str]) -> None:
        destination = self.temp_root / "task008c-npm-standard-pack"
        destination.mkdir()
        completed = self.npm(
            [
                "pack",
                f"{self.package_name}@{self.version}",
                "--ignore-scripts",
                "--pack-destination",
                str(destination),
            ],
            environment,
            "task008c-npm-standard-pack.log",
        )
        tarballs = list(destination.glob("*.tgz"))
        if completed.returncode != 0 or tarballs != [destination / self.tarball_name]:
            raise RuntimeError("standard npm pack did not retrieve the exact tarball")
        self.require_baseline_integrity(tarballs[0])
        self.results["standard npm pack/download"] = "PASS"

    def reject_replacement(self, environment: dict[str, str]) -> None:
        completed = self.npm(
            [
                "publish",
                str(self.replacement),
                "--ignore-scripts",
                "--provenance=false",
            ],
            environment,
            "task008c-npm-replacement.log",
        )
        if completed.returncode == 0:
            raise RuntimeError("SECURITY FAILURE: npm same-version replacement succeeded")
        output = completed.stdout + completed.stderr
        if REPLACEMENT_PATTERN.search(output) is None:
            raise RuntimeError(
                "npm replacement failed without recognizable conflict semantics"
            )
        self.results["same-version replacement"] = "PASS"

    def reject_unpublish(self, environment: dict[str, str]) -> None:
        completed = self.npm(
            ["unpublish", f"{self.package_name}@{self.version}", "--force"],
            environment,
            "task008c-npm-unpublish.log",
        )
        if completed.returncode == 0:
            raise RuntimeError("SECURITY FAILURE: npm unpublish succeeded")
        output = completed.stdout + completed.stderr
        if UNPUBLISH_DENIAL_PATTERN.search(output) is None:
            self.results["npm unpublish denied"] = "INCONCLUSIVE"
            raise RuntimeError("INCONCLUSIVE: npm unpublish failed without HTTP 403 evidence")
        self.results["npm unpublish denied"] = "PASS (HTTP 403)"

    def rest_delete(self) -> None:
        delete_url = (
            f"{self.base_url}/api/v1/packages/{quote(self.owner)}/npm/"
            f"{quote(self.package_name, safe='')}/{quote(self.version)}"
        )
        request = Request(
            delete_url,
            method="DELETE",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        try:
            with urlopen(request, timeout=30) as response:
                status = response.status
        except HTTPError as error:
            status = error.code
        self.results["REST DELETE"] = (
            f"PASS (HTTP {status})" if status == 403 else f"FAIL (HTTP {status})"
        )
        if 200 <= status < 300:
            raise RuntimeError("SECURITY FAILURE: npm package-version DELETE succeeded")
        if status != 403:
            raise RuntimeError(
                f"INCONCLUSIVE: npm package-version DELETE returned HTTP {status}"
            )

    def verify_survival(
        self,
        environment: dict[str, str],
        label: str,
        retrieval_result: str,
        integrity_result: str,
    ) -> None:
        dist = self.metadata(environment, label)
        tarball = self.download(str(dist["tarball"]), label)
        self.results[retrieval_result] = "PASS"
        self.require_baseline_integrity(tarball)
        self.results[integrity_result] = "PASS"

    def write_summary(self) -> None:
        labels = tuple(self.results)
        with self.summary_path.open("a", encoding="utf-8") as summary:
            summary.write("## Task 008C Forgejo npm probe\n\n")
            summary.write("| Assertion | Result |\n|---|---|\n")
            for label in labels:
                summary.write(f"| {label} | {self.results[label]} |\n")
            summary.write(
                "\n`STANDARD_NPM_OIDC_AUTH = "
                f"{self.results['Standard npm + OIDC JWT']}`\n"
            )
            summary.write(
                "\nStandard npm interoperability, optional registry metadata hashes, "
                "and append-only enforcement are independent findings.\n"
            )

    def run(self) -> None:
        self.verify_handoff()
        environment = self.configure_npm()
        self.publish_baseline(environment)

        dist = self.metadata(environment, "initial")
        initial = self.download(str(dist["tarball"]), "initial")
        self.require_baseline_integrity(initial)
        self.results["npm SHA-256 round trip"] = "PASS"
        self.verify_metadata_hashes(dist)
        self.install_downloaded(initial, environment)
        self.standard_pack(environment)

        self.reject_replacement(environment)
        self.verify_survival(
            environment,
            "after-replacement",
            "post-replacement retrieval",
            "post-replacement integrity",
        )
        self.reject_unpublish(environment)
        self.rest_delete()
        self.verify_survival(
            environment,
            "after-delete",
            "post-DELETE retrieval",
            "post-DELETE integrity",
        )
        self.results["Core npm append-only"] = "PASS"

    def close(self) -> None:
        self.npmrc.unlink(missing_ok=True)
        self.token = ""


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--forgejo-url", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--handoff", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--summary", required=True)
    return parser.parse_args()


def main() -> int:
    probe: Probe | None = None
    try:
        probe = Probe(parse_arguments())
        probe.run()
        return 0
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        if probe is not None:
            probe.write_summary()
            probe.close()


if __name__ == "__main__":
    raise SystemExit(main())
