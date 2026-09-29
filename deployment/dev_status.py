"""Read-only, bounded development-environment status for local handoffs.

File: deployment/dev_status.py

Purpose:
    Collects bounded repository, host, security-boundary, and environment facts.

Related files:
    - deployment/dev_handoff.py: uses the collected facts for ChatGPT handoffs.
    - deployment/tests/test_dev_status.py: focused tests for this module.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import platform
import pwd
import select
import socket
import stat
import subprocess
import sys
import time


# Bounds for command output, displayed paths, and command duration.
MAX_COMMAND_BYTES = 65536
MAX_CHANGED_PATHS = 20
MAX_PATH_CHARS = 240
COMMAND_TIMEOUT_SECONDS = 5


class StatusError(Exception):
    """A required repository fact could not be collected."""


# Bounded subprocess and Git helpers keep diagnostics out of the handoff.
def _command(arguments: list[str], *, cwd: str | None = None,
             limit: int = MAX_COMMAND_BYTES) -> tuple[bytes, bool]:
    """Read at most limit bytes of stdout without exposing command diagnostics."""
    try:
        with subprocess.Popen(arguments, cwd=cwd, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL) as process:
            assert process.stdout is not None
            try:
                output = bytearray()
                deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise StatusError("command timed out")
                    readable, _, _ = select.select([process.stdout], [], [], remaining)
                    if not readable:
                        raise StatusError("command timed out")
                    chunk = os.read(process.stdout.fileno(), min(8192, limit + 1 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > limit:
                        process.kill()
                        process.wait()
                        return bytes(output[:limit]), True
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
                if process.returncode != 0:
                    raise StatusError("command failed")
                return bytes(output), False
            except (StatusError, subprocess.TimeoutExpired):
                if process.poll() is None:
                    process.kill()
                    process.wait()
                raise
    except (OSError, subprocess.TimeoutExpired):
        raise StatusError("command unavailable") from None


def _git(arguments: list[str], *, cwd: str | None = None,
         limit: int = MAX_COMMAND_BYTES) -> bytes:
    """Return complete bounded Git output or a generic failure."""
    output, truncated = _command(["git", *arguments], cwd=cwd, limit=limit)
    if truncated:
        raise StatusError("Git output exceeded limit")
    return output


def _changed_paths(raw: bytes, *, truncated: bool) -> tuple[list[str], bool]:
    """Extract a bounded set of paths from NUL-delimited porcelain v1 output."""
    paths = []
    entries = raw.split(b"\0")
    position = 0
    while position < len(entries):
        entry = entries[position]
        if not entry or len(entry) < 4 or entry[2:3] != b" ":
            break
        if len(paths) == MAX_CHANGED_PATHS:
            truncated = True
            break
        path = entry[3:].decode("utf-8", errors="replace")
        if len(path) > MAX_PATH_CHARS:
            path = path[:MAX_PATH_CHARS] + "…"
        paths.append(path)
        position += 1
        if b"R" in entry[:2] or b"C" in entry[:2]:
            position += 1  # A rename/copy includes its second path as another NUL field.
    return paths, truncated or position < len(entries) - 1


# Collect local observations for both developer workflow commands.
def collect_status() -> dict[str, object]:
    """Collect repository and host facts without changing persistent state."""
    root = _git(["rev-parse", "--show-toplevel"], limit=4096).decode("utf-8", "replace").strip()
    if not root or not Path(root).is_dir():
        raise StatusError("repository unavailable")
    branch = _git(["branch", "--show-current"], cwd=root, limit=4096).decode("utf-8", "replace").strip()
    commit = _git(["rev-parse", "HEAD"], cwd=root, limit=128).decode("ascii", "replace").strip()
    if len(commit) not in (40, 64) or any(character not in "0123456789abcdef" for character in commit):
        raise StatusError("HEAD unavailable")
    status_raw, status_truncated = _command(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=normal"], cwd=root,
    )
    paths, paths_truncated = _changed_paths(status_raw, truncated=status_truncated)

    try:
        username = pwd.getpwuid(os.getuid()).pw_name
    except (KeyError, OSError):
        username = "unavailable"
    try:
        group_ids = {os.getgid(), *os.getgroups()}
        groups = sorted({grp.getgrgid(group_id).gr_name for group_id in group_ids})
    except (KeyError, OSError):
        groups = []
    try:
        docker_mode = os.stat("/var/run/docker.sock").st_mode
        docker_exists = True
        docker_is_socket = stat.S_ISSOCK(docker_mode)
    except OSError:
        docker_exists = False
        docker_is_socket = False
    try:
        sudo_output, sudo_truncated = _command(["sudo", "-n", "true"], limit=128)
        sudo_noninteractive = not sudo_truncated and not sudo_output
    except StatusError:
        sudo_noninteractive = False
    try:
        git_version = _git(["--version"], limit=256).decode("utf-8", "replace").strip()
    except StatusError:
        git_version = "unavailable"

    return {
        "repository": {
            "root": root, "branch": branch or "(detached)", "head": commit,
            "worktree": "dirty" if status_raw else "clean",
            "changed_paths": paths, "changed_paths_truncated": paths_truncated,
        },
        "host": {"hostname": socket.gethostname(), "username": username, "groups": groups},
        "security_boundary": {
            "sudo_noninteractive_available": sudo_noninteractive,
            "docker_socket_exists": docker_exists,
            "docker_socket_is_unix_socket": docker_is_socket,
        },
        "environment": {"python_version": platform.python_version(), "git_version": git_version},
    }


# Render collected facts and expose the command-line entrypoint.
def render_human(status: dict[str, object]) -> str:
    """Render collected facts as a compact, deterministic text summary."""
    repository = status["repository"]
    host = status["host"]
    boundary = status["security_boundary"]
    environment = status["environment"]
    assert isinstance(repository, dict) and isinstance(host, dict)
    assert isinstance(boundary, dict) and isinstance(environment, dict)
    lines = [
        f"Repository: {repository['root']}",
        f"Branch: {repository['branch']}",
        f"HEAD: {repository['head']}",
        f"Worktree: {repository['worktree']}",
        "Changed paths: " + json.dumps(repository["changed_paths"], ensure_ascii=True)
        + (" (truncated)" if repository["changed_paths_truncated"] else ""),
        f"Hostname: {host['hostname']}",
        f"Username: {host['username']}",
        "Groups: " + json.dumps(host["groups"], ensure_ascii=True),
        f"Non-interactive sudo: {boundary['sudo_noninteractive_available']}",
        f"Docker socket exists: {boundary['docker_socket_exists']}",
        f"Docker Unix socket: {boundary['docker_socket_is_unix_socket']}",
        f"Python: {environment['python_version']}",
        f"Git: {environment['git_version']}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Print human or JSON status; return nonzero for required Git failures."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="emit compact JSON")
    arguments = parser.parse_args(argv)
    try:
        status = collect_status()
    except StatusError:
        print("Development status unavailable: Git repository status could not be collected.",
              file=sys.stderr)
        return 1
    if arguments.json:
        print(json.dumps(status, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    else:
        print(render_human(status))
    return 0


if __name__ == "__main__":
    sys.exit(main())
