#!/usr/bin/env python3
"""File: deployment/analytics_prod_oci_pull_once.py

Purpose: Run the already approved M05 Analytics 0.16.0 GitHub-to-PROD
         encrypted OIDC handoff as ONE attended owner command on michael-laptop.
Related: .github/workflows/platform-promote.yml,
         release/analytics_prod_credential_handoff.py,
         deployment/analytics_prod_authenticated_pull.py,
         deployment/runtime/prod/analytics.compose.private.yaml.

Sections:
  1. Fixed owner, source SHA, SSH endpoint and signed PROD receiver.
  2. Read-only local/remote preflight and original source validation.
  3. Dispatch one existing, protected GitHub workflow and require success.
  4. Download one ciphertext artifact into a disposable owner-only directory.
  5. Send ciphertext over already trusted SSH and invoke the reviewed
     PROD UID990 decrypt -> original signed --pull-only pipeline immediately.
  6. Verify exact image digest, remove ciphertext and report one result.

Not a new release framework. No credential values in argv, environment,
logfiles, GitHub comments or stdout. No new secrets, containers, database
migrations, public Nginx changes, or automated retries. Explicit --run only.
Do not run this from PROD or through the restricted Desktop Commander tool.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

REPO = "MichaelTrueX/omnilyzer-platform"
WORKFLOW = "platform-promote.yml"
OWNER = "MichaelTrueX"
PROD_ADDRESS = "46.62.147.181"
PROD_PORT = "2222"
PROD_USER = "trusthansen"
PROD_TARGET = f"{PROD_USER}@{PROD_ADDRESS}"
PROD_RECEIVER = "/var/lib/omnilyzer/analytics/prod/analytics_prod_authenticated_pull_v3.py"
PROD_RECEIVER_SHA = "b52e7ea706a239c8f0472536576d82513ca4e655ed9a182b56e875e84208eb9d"
AGE_IDENTITY = "/var/lib/omnilyzer/analytics/prod/registry-token-age.key"
IMAGE = (
    "oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:"
    "a0ce1e63dd379c939a2e558b04307b129fa79128da1362caa90d963d8bb3f6a1"
)
IMAGE_ID = "sha256:8ddf7273804b8c9a5a964fb85b573de25f66915dd5ef33465522742f5a5df76e"
EXPECTED_MARKER = "ANALYTICS_PROD_SIGNED_IMAGE_AUTHENTICATED_PULL_PASS"
SSH_OPTS = (
    "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
    "-o", "ConnectTimeout=8", "-o", "NumberOfPasswordPrompts=0",
)
RUN_DISCOVERY_TIMEOUT = 35
RUN_COMPLETION_TIMEOUT = 90
ARTIFACT_MAX = 16_384


class ReleaseHold(RuntimeError):
    """Fail closed with fixed, non-sensitive diagnostic messages."""


def execute(argv: list[str], *, timeout: int = 30, input_text: str | None = None) -> str:
    """Use fixed subprocess argv and redact all child errors from the terminal."""
    try:
        result = subprocess.run(
            argv, input=input_text, text=True, capture_output=True,
            timeout=timeout, check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.SubprocessError):
        raise ReleaseHold("required command unavailable or timed out") from None
    if result.returncode:
        raise ReleaseHold("approved command rejected; inspect the original GitHub run or SSH access")
    return result.stdout


def ssh_args() -> list[str]:
    """Reuse the already validated existing SSH host key on port 2222."""
    return ["ssh", *SSH_OPTS, "-p", PROD_PORT, PROD_TARGET]


def scp_args() -> list[str]:
    """Transfer ciphertext only with the same strict SSH host verification."""
    return ["scp", "-q", *SSH_OPTS, "-P", PROD_PORT]


def check_owner() -> None:
    """Require the actual local owner laptop, not a PROD or DEV service shell."""
    if socket.gethostname().split(".")[0] != "michael-laptop" or os.geteuid() == 0:
        raise ReleaseHold("run only as the normal owner on michael-laptop")
    for command in ("gh", "ssh", "scp"):
        if not shutil.which(command):
            raise ReleaseHold("GitHub CLI or SSH client unavailable")
    identity = json.loads(execute(["gh", "api", "user", "--jq", "{login: .login}"], timeout=12))
    if identity != {"login": OWNER}:
        raise ReleaseHold("GitHub session is not the approved owner")


def remote_preflight() -> None:
    """Check original signed PROD receiver without changing Docker or the DB."""
    code = (
        "set -eu; "
        f"test \"$(sha256sum {PROD_RECEIVER} | cut -d' ' -f1)\" = {PROD_RECEIVER_SHA}; "
        "sudo -n /usr/sbin/runuser -u omnilyzer-analytics -- "
        f"/usr/bin/python3 -I -B {PROD_RECEIVER} --preflight"
    )
    result = execute([*ssh_args(), code], timeout=45)
    if "ANALYTICS_PROD_SIGNED_REGISTRY_PULL_READONLY_PASS" not in result:
        raise ReleaseHold("real signed PROD preflight did not pass")


def workflow_runs() -> list[dict]:
    """List this one workflow's newest dispatches without reading job secrets."""
    raw = execute([
        "gh", "run", "list", "-R", REPO, "-w", WORKFLOW,
        "--limit", "12", "--json",
        "databaseId,status,conclusion,headSha,event,createdAt",
    ], timeout=15)
    value = json.loads(raw)
    if not isinstance(value, list):
        raise ReleaseHold("GitHub run inventory invalid")
    return value


def protected_main_sha() -> str:
    """Require the exact protected GitHub main that receives the dispatch."""
    value = execute([
        "gh", "api", f"repos/{REPO}/git/ref/heads/main", "--jq", ".object.sha",
    ], timeout=15).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ReleaseHold("protected main commit unavailable")
    return value


def dispatch_once() -> int:
    """Submit ONE source-bound credential-only job, never a Task014 deploy."""
    expected_sha = protected_main_sha()
    before = {int(run["databaseId"]) for run in workflow_runs()}
    started = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=10)
    execute([
        "gh", "workflow", "run", WORKFLOW, "-R", REPO, "--ref", "main",
        "-f", "auth_probe=true", "-f", "target_stage=prod",
        "-f", "product_id=analytics",
    ], timeout=20)
    until = time.monotonic() + RUN_DISCOVERY_TIMEOUT
    while time.monotonic() < until:
        matches = [
            v for v in workflow_runs()
            if int(v["databaseId"]) not in before
            and v.get("headSha") == expected_sha
            and v.get("event") == "workflow_dispatch"
            and dt.datetime.fromisoformat(v["createdAt"].replace("Z", "+00:00")) >= started
        ]
        if len(matches) == 1:
            return int(matches[0]["databaseId"])
        if len(matches) > 1:
            raise ReleaseHold("ambiguous concurrent workflow dispatch; no artifact consumed")
        time.sleep(2)
    raise ReleaseHold("one protected workflow dispatch not identifiable")


def wait_success(run_id: int) -> None:
    """Accept ONLY the new credential job success, original jobs skipped."""
    until = time.monotonic() + RUN_COMPLETION_TIMEOUT
    while time.monotonic() < until:
        raw = execute([
            "gh", "run", "view", str(run_id), "-R", REPO,
            "--json", "status,conclusion,jobs",
        ], timeout=12)
        result = json.loads(raw)
        if result["status"] == "completed":
            jobs = {job["name"]: job["conclusion"] for job in result["jobs"]}
            if (result["conclusion"] != "success"
                    or jobs.get("prod_analytics_registry_credential") != "success"
                    or any(jobs.get(name) != "skipped" for name in (
                        "private_zot_readonly_probe", "gate", "deploy_dev"))):
                raise ReleaseHold("credential-only workflow or isolation failed")
            return
        time.sleep(2)
    raise ReleaseHold("encrypted handoff workflow too slow; never reuse its expiring token")


def encrypted_artifact(run_id: int, folder: Path) -> Path:
    """Download only the named age ciphertext and check its bounded format."""
    execute([
        "gh", "run", "download", str(run_id), "-R", REPO,
        "-n", f"m05-prod-oci-credential-{run_id}-1", "-D", str(folder),
    ], timeout=20)
    members = list(folder.iterdir())
    if len(members) != 1 or members[0].name != "m05-analytics-prod-registry-token.age":
        raise ReleaseHold("unexpected encrypted artifact inventory")
    value = members[0]
    if value.is_symlink() or not value.is_file() or not 1 <= value.stat().st_size <= ARTIFACT_MAX:
        raise ReleaseHold("encrypted credential artifact invalid")
    value.chmod(0o600)
    return value


def remote_pull(run_id: int, artifact: Path) -> None:
    """Send only ciphertext; owner-attended SSH executes fixed original UID990 pull."""
    if not 1 <= run_id <= 999_999_999_999:
        raise ReleaseHold("GitHub run ID invalid")
    staged = f"/home/{PROD_USER}/m05-oci-token-{run_id}.age"
    sealed = f"/run/user/990/m05-oci-token-{run_id}.age"
    execute([*ssh_args(), f"test ! -e {staged} && sudo -n test ! -e {sealed}"],
            timeout=12)
    execute([*scp_args(), str(artifact), f"{PROD_TARGET}:{staged}"], timeout=20)
    # This exact command is executed by the OWNER's attended SSH session,
    # not by ChatGPT's restricted remote execution tool.
    remote = (
        "set -Eeuo pipefail\n"
        "trap 'rm -f " + staged + "; sudo -n /usr/bin/rm -f " + sealed + "' EXIT\n"
        "sudo -n /usr/bin/install -o omnilyzer-analytics "
        "-g omnilyzer-analytics -m 0400 " + staged + " " + sealed + "\n"
        "sudo -n /usr/sbin/runuser -u omnilyzer-analytics -- /bin/bash -c "
        "'set -o pipefail; "
        "/usr/bin/age --decrypt --identity " + AGE_IDENTITY + " " + sealed
        + " | /usr/bin/python3 -I -B " + PROD_RECEIVER + " --pull-only'\n"
    )
    output = execute([*ssh_args(), "/bin/bash", "-s"], timeout=120,
                     input_text=remote)
    if EXPECTED_MARKER not in output:
        raise ReleaseHold("no authenticated signed Docker pull success receipt")
    print(EXPECTED_MARKER)


def verify_postpull() -> None:
    """Check rootless Docker's actual original image digest with no credentials."""
    command = (
        "sudo -n /usr/sbin/runuser -u omnilyzer-analytics -- "
        "/usr/bin/docker --host unix:///run/user/990/docker.sock "
        "image inspect --format '{{json .RepoDigests}}|{{.Id}}' " + IMAGE
    )
    output = execute([*ssh_args(), command], timeout=20).strip()
    parts = output.split("|")
    if len(parts) != 2 or parts[1] != IMAGE_ID:
        raise ReleaseHold("actual rootless Docker config digest differs")
    if IMAGE not in json.loads(parts[0]):
        raise ReleaseHold("actual rootless Docker manifest digest differs")
    print("ANALYTICS_PROD_SIGNED_IMAGE_DOCKER_READBACK_PASS")


def main() -> int:
    """Allow explicit --preflight or one owner-attended --run; never background work."""
    parser = argparse.ArgumentParser(description="Owner-attended Analytics 0.16.0 PROD signed image pull")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--preflight", action="store_true")
    modes.add_argument("--run", action="store_true")
    args = parser.parse_args()
    try:
        check_owner()
        remote_preflight()
        if args.preflight:
            print("ANALYTICS_PROD_OWNER_ONE_COMMAND_PREFLIGHT_PASS")
            return 0
        with tempfile.TemporaryDirectory(prefix="m05-analytics-oidc-") as directory:
            work = Path(directory)
            os.chmod(work, 0o700)
            run_id = dispatch_once()
            print(f"ANALYTICS_PROD_AUTHENTICATED_HANDOFF_RUN {run_id}", flush=True)
            wait_success(run_id)
            artifact = encrypted_artifact(run_id, work)
            remote_pull(run_id, artifact)
        verify_postpull()
        print("ANALYTICS_PROD_OWNER_ONE_COMMAND_PULL_PASS container=not_started")
        return 0
    except (ReleaseHold, ValueError, KeyError, TypeError, OSError) as exc:
        print(f"ANALYTICS_PROD_OWNER_ONE_COMMAND_HOLD {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
