#!/usr/bin/env python3
"""Run the Task 008C Bearer-authenticated Forgejo PyPI probe."""

from __future__ import annotations

import argparse
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import quote, urljoin, urlparse

import requests
from twine.package import PackageFile
from twine.repository import Repository


PACKAGE_NAME = "omnilyzer-supply-chain-spike"
DUPLICATE_PATTERN = re.compile(
    r"(?:already\s+(?:exists?|been\s+published)|duplicate|"
    r"same\s+(?:name|version)|version[^\n]{0,80}(?:exists?|published))",
    re.IGNORECASE,
)


class SimpleLinks(HTMLParser):
    """Collect href attributes from a PEP 503 project page."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value is not None:
                self.hrefs.append(value)


class BearerAuth(requests.auth.AuthBase):
    """Apply Authorized Integration Bearer auth after netrc processing."""

    def __init__(self, token: str) -> None:
        self.token = token

    def __call__(self, request: requests.PreparedRequest) -> requests.PreparedRequest:
        request.headers["Authorization"] = f"Bearer {self.token}"
        return request


def sha256(path: Path) -> str:
    """Return a lowercase SHA-256 digest."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_status(response: requests.Response, expected: int, operation: str) -> None:
    """Fail without echoing response bodies or credentials."""

    if response.status_code != expected:
        raise RuntimeError(f"{operation} returned HTTP {response.status_code}")


class Probe:
    """Keep each independently reported assertion explicit and fail closed."""

    def __init__(self, arguments: argparse.Namespace) -> None:
        self.base_url = arguments.forgejo_url.rstrip("/")
        self.owner = arguments.owner
        self.handoff = Path(arguments.handoff).resolve(strict=True)
        self.manifest_path = self.handoff / "handoff.json"
        self.token_file = Path(arguments.token_file).resolve(strict=True)
        self.summary_path = Path(arguments.summary)
        self.temp_root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        self.results = {
            "GitHub OIDC JWT acquisition": "FAIL",
            "Package Bearer authentication": "FAIL",
            "Current-user API": "FAIL (not attempted)",
            "PyPI publish": "FAIL",
            "PyPI Simple API read": "FAIL",
            "Wheel SHA-256 round trip": "FAIL",
            "Wheel install": "FAIL",
            "Duplicate same-version publish": "FAIL",
            "Post-duplicate integrity": "FAIL",
            "DELETE": "FAIL (not attempted)",
            "Post-DELETE retrieval": "FAIL",
            "Post-DELETE integrity": "FAIL",
            "Standard Twine + OIDC JWT": "INCONCLUSIVE (not attempted)",
            "Standard pip + OIDC JWT": "INCONCLUSIVE (not attempted)",
        }
        self.token = self.token_file.read_text(encoding="utf-8").strip()
        self.token_file.unlink()
        if not self.token:
            raise RuntimeError("OIDC token file was empty")
        self.results["GitHub OIDC JWT acquisition"] = "PASS"
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.package = self.manifest["package_name"]
        self.version = self.manifest["version"]
        self.wheel_name = self.manifest["wheel_filename"]
        self.expected_sha = self.manifest["sha256"]
        self.wheel = self.handoff / self.wheel_name
        self.upload_url = f"{self.base_url}/api/packages/{quote(self.owner)}/pypi"
        self.simple_url = (
            f"{self.base_url}/api/packages/{quote(self.owner)}/pypi/simple/"
            f"{quote(self.package)}/"
        )
        self.session = requests.Session()
        self.session.auth = BearerAuth(self.token)

    def verify_handoff(self) -> None:
        """Recheck the non-OIDC job's narrow, machine-readable handoff."""

        required = {
            "package_name",
            "version",
            "wheel_filename",
            "sha256",
            "source_commit",
        }
        if set(self.manifest) != required:
            raise RuntimeError("handoff manifest fields are not exact")
        expected_version = f"0.0.{os.environ['GITHUB_RUN_ID']}{os.environ['GITHUB_RUN_ATTEMPT']}"
        if self.package != PACKAGE_NAME or self.version != expected_version:
            raise RuntimeError("handoff package name or unique version is unexpected")
        if self.manifest["source_commit"] != os.environ["GITHUB_SHA"]:
            raise RuntimeError("handoff source commit does not match this workflow")
        if not re.fullmatch(r"[0-9a-f]{64}", self.expected_sha):
            raise RuntimeError("handoff SHA-256 is malformed")
        wheels = list(self.handoff.glob("*.whl"))
        if len(wheels) != 1 or wheels[0].name != self.wheel_name:
            raise RuntimeError("handoff does not contain exactly the declared wheel")
        if sha256(self.wheel) != self.expected_sha:
            raise RuntimeError("handoff wheel SHA-256 mismatch")
        package = PackageFile.from_filename(str(self.wheel), None)
        if package.safe_name != PACKAGE_NAME or package.version != self.version:
            raise RuntimeError("wheel metadata does not match the handoff")

    def current_user(self) -> str | None:
        """Optionally resolve a login for standard Basic-auth client probes."""

        try:
            response = self.session.get(f"{self.base_url}/api/v1/user", timeout=30)
        except requests.RequestException as error:
            self.results["Current-user API"] = "FAIL (request error)"
            raise RuntimeError("Forgejo current-user API request failed") from error
        if response.status_code in (401, 403):
            self.results["Current-user API"] = f"FAIL (HTTP {response.status_code})"
            return None
        if response.status_code != 200:
            self.results["Current-user API"] = f"FAIL (HTTP {response.status_code})"
            raise RuntimeError(
                f"Forgejo current-user API returned unexpected HTTP {response.status_code}"
            )
        try:
            payload = response.json()
        except requests.exceptions.JSONDecodeError as error:
            self.results["Current-user API"] = "FAIL (malformed response)"
            raise RuntimeError(
                "Forgejo current-user API returned malformed JSON"
            ) from error
        if not isinstance(payload, dict):
            self.results["Current-user API"] = "FAIL (malformed response)"
            raise RuntimeError("Forgejo current-user API returned malformed JSON")
        login = payload.get("login")
        if not isinstance(login, str) or re.fullmatch(r"[A-Za-z0-9_.-]+", login) is None:
            self.results["Current-user API"] = "FAIL (malformed response)"
            raise RuntimeError("Forgejo current-user API returned no safe login")
        self.results["Current-user API"] = "PASS"
        return login

    def twine_upload(self, login: str) -> bool:
        """Test unmodified Twine's normal Basic credential flow with the JWT."""

        log = self.temp_root / "task008c-standard-twine.log"
        environment = os.environ.copy()
        environment.update(
            {
                "TWINE_USERNAME": login,
                "TWINE_PASSWORD": self.token,
                "TWINE_NON_INTERACTIVE": "1",
            }
        )
        with log.open("wb") as output:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "twine",
                    "upload",
                    "--non-interactive",
                    "--disable-progress-bar",
                    "--repository-url",
                    self.upload_url,
                    str(self.wheel),
                ],
                env=environment,
                stdout=output,
                stderr=subprocess.STDOUT,
                check=False,
            )
        return completed.returncode == 0

    def bearer_upload(self) -> requests.Response:
        """Use Twine's package parser and multipart uploader with Bearer auth."""

        package = PackageFile.from_filename(str(self.wheel), None)
        repository = Repository(self.upload_url, None, None, disable_progress_bar=True)
        repository.session.headers["Authorization"] = f"Bearer {self.token}"
        repository.session.auth = BearerAuth(self.token)
        try:
            response = repository.upload(package, max_redirects=1)
            if 200 <= response.status_code < 300:
                self.results["Package Bearer authentication"] = "PASS"
            return response
        finally:
            repository.close()

    def exact_wheel_url(self) -> str:
        """Require one exact wheel link on the authenticated Simple API page."""

        response = self.session.get(self.simple_url, timeout=30)
        require_status(response, 200, "PyPI Simple API")
        self.results["Package Bearer authentication"] = "PASS"
        parser = SimpleLinks()
        parser.feed(response.text)
        matches = []
        for href in parser.hrefs:
            absolute = urljoin(self.simple_url, href)
            filename = Path(urlparse(absolute).path).name
            if filename == self.wheel_name:
                matches.append(absolute)
        if len(matches) != 1:
            raise RuntimeError(
                f"PyPI Simple API exposed {len(matches)} links for the exact wheel"
            )
        self.results["PyPI Simple API read"] = "PASS"
        return matches[0]

    def download_exact(self, destination: Path) -> None:
        """Download the exact Simple API wheel and require HTTP 200."""

        if destination.name != self.wheel_name:
            raise RuntimeError("download destination does not preserve wheel filename")
        response = self.session.get(self.exact_wheel_url(), timeout=60)
        require_status(response, 200, "exact PyPI wheel retrieval")
        destination.write_bytes(response.content)

    def wheel_destination(self, probe_name: str) -> Path:
        """Create an isolated download directory preserving the wheel basename."""

        destination_directory = self.temp_root / f"task008c-{probe_name}"
        destination_directory.mkdir()
        return destination_directory / self.wheel_name

    def require_integrity(self, destination: Path) -> None:
        if sha256(destination) != self.expected_sha:
            raise RuntimeError("retrieved wheel SHA-256 differs from the build handoff")

    def install_wheel(self, downloaded: Path) -> None:
        """Install only the retrieved local wheel and call the fixture report API."""

        environment_dir = self.temp_root / "task008c-wheel-install"
        subprocess.run([sys.executable, "-m", "venv", str(environment_dir)], check=True)
        python = environment_dir / "bin/python"
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-index",
                "--no-deps",
                str(downloaded),
            ],
            check=True,
        )
        completed = subprocess.run(
            [
                str(python),
                "-c",
                (
                    "from omnilyzer_supply_chain_spike import report; "
                    "print(report())"
                ),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        if completed.stdout.strip() != self.version:
            raise RuntimeError("installed wheel reported an unexpected version")

    def pip_compatibility(self, login: str) -> bool:
        """Test standard pip with a temporary netrc, never a credentialed URL."""

        pip_root = Path(tempfile.mkdtemp(prefix="task008c-pip-", dir=self.temp_root))
        netrc = pip_root / "netrc"
        host = urlparse(self.base_url).hostname
        if host is None:
            raise RuntimeError("Forgejo URL has no hostname")
        netrc.write_text(
            f"machine {host}\nlogin {login}\npassword {self.token}\n",
            encoding="utf-8",
        )
        netrc.chmod(0o600)
        destination = pip_root / "download"
        destination.mkdir()
        environment = os.environ.copy()
        environment.update(
            {
                "NETRC": str(netrc),
                "PIP_INDEX_URL": self.simple_url.rsplit(f"{quote(self.package)}/", 1)[0],
                "PIP_NO_INPUT": "1",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            }
        )
        log = pip_root / "pip.log"
        with log.open("wb") as output:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "download",
                    "--no-deps",
                    "--no-cache-dir",
                    "--dest",
                    str(destination),
                    f"{self.package}=={self.version}",
                ],
                env=environment,
                stdout=output,
                stderr=subprocess.STDOUT,
                check=False,
            )
        candidates = list(destination.glob("*.whl"))
        passed = (
            completed.returncode == 0
            and len(candidates) == 1
            and candidates[0].name == self.wheel_name
            and sha256(candidates[0]) == self.expected_sha
        )
        netrc.unlink(missing_ok=True)
        return passed

    def write_summary(self) -> None:
        """Always preserve protocol, client, and append-only results separately."""

        labels = (
            "GitHub OIDC JWT acquisition",
            "Package Bearer authentication",
            "Current-user API",
            "PyPI publish",
            "PyPI Simple API read",
            "Wheel SHA-256 round trip",
            "Wheel install",
            "Duplicate same-version publish",
            "Post-duplicate integrity",
            "DELETE",
            "Post-DELETE retrieval",
            "Post-DELETE integrity",
            "Standard Twine + OIDC JWT",
            "Standard pip + OIDC JWT",
        )
        with self.summary_path.open("a", encoding="utf-8") as summary:
            summary.write("## Task 008C Forgejo PyPI probe\n\n")
            summary.write("| Assertion | Result |\n|---|---|\n")
            for label in labels:
                summary.write(f"| {label} | {self.results[label]} |\n")
            summary.write(
                "\nBearer registry protocol support, standard Twine/pip "
                "interoperability, and the Nginx append-only DELETE boundary "
                "are independent findings.\n"
            )
            summary.write(
                "\n`STANDARD_TWINE_OIDC_AUTH = "
                f"{self.results['Standard Twine + OIDC JWT']}`  \n"
                "`STANDARD_PIP_OIDC_AUTH = "
                f"{self.results['Standard pip + OIDC JWT']}`\n"
            )

    def run(self) -> None:
        self.verify_handoff()
        login = self.current_user()

        twine_passed = False
        baseline_exists = False
        if login is None:
            unavailable = "INCONCLUSIVE (Forgejo login unavailable)"
            self.results["Standard Twine + OIDC JWT"] = unavailable
            self.results["Standard pip + OIDC JWT"] = unavailable
        else:
            twine_passed = self.twine_upload(login)
            self.results["Standard Twine + OIDC JWT"] = (
                "PASS" if twine_passed else "FAIL"
            )
        if login is not None and not twine_passed:
            try:
                candidate = self.wheel_destination("after-twine")
                self.download_exact(candidate)
                self.require_integrity(candidate)
                baseline_exists = True
            except (requests.RequestException, RuntimeError):
                self.results["PyPI Simple API read"] = "FAIL"
        if not twine_passed and not baseline_exists:
            response = self.bearer_upload()
            if not 200 <= response.status_code < 300:
                raise RuntimeError(
                    f"Bearer PyPI publication returned HTTP {response.status_code}"
                )
        self.results["PyPI publish"] = "PASS"

        initial = self.wheel_destination("initial")
        self.download_exact(initial)
        self.require_integrity(initial)
        self.results["Wheel SHA-256 round trip"] = "PASS"
        self.install_wheel(initial)
        self.results["Wheel install"] = "PASS"

        if login is not None:
            self.results["Standard pip + OIDC JWT"] = (
                "PASS" if self.pip_compatibility(login) else "FAIL"
            )

        duplicate = self.bearer_upload()
        duplicate_text = f"{duplicate.reason}\n{duplicate.text[:4096]}"
        if 200 <= duplicate.status_code < 300:
            raise RuntimeError("SECURITY FAILURE: duplicate PyPI publication succeeded")
        if DUPLICATE_PATTERN.search(duplicate_text) is None:
            raise RuntimeError(
                "duplicate publication failed without recognizable already-exists semantics "
                f"(HTTP {duplicate.status_code})"
            )
        self.results["Duplicate same-version publish"] = "PASS"

        after_duplicate = self.wheel_destination("after-duplicate")
        self.download_exact(after_duplicate)
        self.require_integrity(after_duplicate)
        self.results["Post-duplicate integrity"] = "PASS"

        delete_url = (
            f"{self.base_url}/api/v1/packages/{quote(self.owner)}/pypi/"
            f"{quote(self.package)}/{quote(self.version)}"
        )
        deleted = self.session.delete(delete_url, timeout=30)
        self.results["DELETE"] = (
            f"PASS (HTTP {deleted.status_code})"
            if deleted.status_code == 403
            else f"FAIL (HTTP {deleted.status_code})"
        )
        if 200 <= deleted.status_code < 300:
            raise RuntimeError("SECURITY FAILURE: PyPI package-version DELETE succeeded")
        if deleted.status_code != 403:
            raise RuntimeError(
                f"INCONCLUSIVE: PyPI package-version DELETE returned HTTP {deleted.status_code}"
            )

        after_delete = self.wheel_destination("after-delete")
        self.download_exact(after_delete)
        self.results["Post-DELETE retrieval"] = "PASS"
        self.require_integrity(after_delete)
        self.results["Post-DELETE integrity"] = "PASS"


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
            probe.token = ""


if __name__ == "__main__":
    raise SystemExit(main())
