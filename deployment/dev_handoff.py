"""Compact, read-only local facts for a ChatGPT development handoff.

File: deployment/dev_handoff.py

Purpose:
    Produces a bounded local development handoff in human or JSON form.

Related files:
    - deployment/dev_status.py: provides repository and host observations.
    - deployment/tests/test_dev_handoff.py: focused tests for this module.
"""

from __future__ import annotations

import argparse
import json
import sys

from deployment import dev_status


# Bounds for displayed labels, groups, and numeric summaries.
MAX_TEXT_CHARS = 240
MAX_GROUPS = 20
MAX_COUNT = 1_000_000_000


# Summarize local Git state without exposing patches or file contents.
def _text(value: object) -> str:
    """Keep externally supplied labels short and safe for a one-line handoff."""
    rendered = "".join(character if character.isprintable() else f"\\u{ord(character):04x}"
                       for character in str(value))
    return rendered[:MAX_TEXT_CHARS] + ("…" if len(rendered) > MAX_TEXT_CHARS else "")


def _numstat(root: str, *, staged: bool) -> tuple[int | None, int | None, int | None,
                                                   set[bytes] | None]:
    """Count changed files and text lines without reading or printing patches."""
    arguments = ["diff", "--numstat", "-z", "--no-ext-diff", "--no-textconv", "--no-renames"]
    if staged:
        arguments.insert(1, "--cached")
    try:
        raw = dev_status._git(arguments, cwd=root)
    except dev_status.StatusError:
        return None, None, None, None
    if not raw:
        return 0, 0, 0, set()
    if not raw.endswith(b"\0"):
        return None, None, None, None
    files = insertions = deletions = 0
    paths = set()
    for entry in raw[:-1].split(b"\0"):
        fields = entry.split(b"\t", 2)
        if len(fields) != 3 or not fields[2]:
            return None, None, None, None
        files += 1
        paths.add(fields[2])
        if fields[0] == fields[1] == b"-":
            insertions = deletions = None
        elif fields[0].isdigit() and fields[1].isdigit():
            if insertions is not None:
                insertions += int(fields[0])
                deletions += int(fields[1])
        else:
            return None, None, None, None
        if files > MAX_COUNT or (insertions is not None and
                                 (insertions > MAX_COUNT or deletions > MAX_COUNT)):
            return None, None, None, None
    return files, insertions, deletions, paths


def _untracked_count(root: str) -> tuple[int | None, set[bytes] | None]:
    """Count untracked paths from bounded, NUL-delimited local Git output."""
    try:
        raw = dev_status._git(["ls-files", "--others", "--exclude-standard", "-z"], cwd=root)
    except dev_status.StatusError:
        return None, None
    if raw and not raw.endswith(b"\0"):
        return None, None
    paths = set(raw[:-1].split(b"\0")) if raw else set()
    return len(paths), paths


def _upstream(root: str) -> tuple[str, int | None, int | None]:
    """Report the configured upstream and local ahead/behind counts."""
    try:
        name = dev_status._git(
            ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"],
            cwd=root, limit=4096,
        ).decode("utf-8", "replace").strip()
    except dev_status.StatusError:
        return "(none)", None, None
    if not name:
        return "(none)", None, None
    try:
        raw = dev_status._git(["rev-list", "--left-right", "--count", "HEAD...@{upstream}"],
                              cwd=root, limit=128)
        fields = raw.split()
        if len(fields) != 2 or any(not field.isdigit() for field in fields):
            raise ValueError("invalid revision counts")
        ahead, behind = map(int, fields)
        if ahead > MAX_COUNT or behind > MAX_COUNT:
            raise ValueError("revision counts too large")
    except (dev_status.StatusError, ValueError):
        return _text(name), None, None
    return _text(name), ahead, behind


# Combine shared status observations with local Git summaries.
def collect_handoff() -> dict[str, object]:
    """Extend dev_status facts with bounded, local-only Git summaries."""
    status = dev_status.collect_status()
    source_repository = status["repository"]
    source_host = status["host"]
    source_boundary = status["security_boundary"]
    source_environment = status["environment"]
    root = source_repository["root"]
    upstream, ahead, behind = _upstream(root)
    staged_files, staged_insertions, staged_deletions, staged_paths = _numstat(root, staged=True)
    unstaged_files, unstaged_insertions, unstaged_deletions, unstaged_paths = _numstat(
        root, staged=False)
    untracked_files, untracked_paths = _untracked_count(root)
    changed_files = (len(staged_paths | unstaged_paths | untracked_paths)
                     if staged_paths is not None and unstaged_paths is not None
                     and untracked_paths is not None else None)
    insertions = (staged_insertions + unstaged_insertions
                  if staged_insertions is not None and unstaged_insertions is not None else None)
    deletions = (staged_deletions + unstaged_deletions
                 if staged_deletions is not None and unstaged_deletions is not None else None)
    if insertions is not None and insertions > MAX_COUNT:
        insertions = None
    if deletions is not None and deletions > MAX_COUNT:
        deletions = None
    paths = [_text(path) for path in source_repository["changed_paths"][:dev_status.MAX_CHANGED_PATHS]]
    groups = [_text(group) for group in source_host["groups"][:MAX_GROUPS]]
    return {
        "repository": {
            "branch": _text(source_repository["branch"]), "head": source_repository["head"],
            "worktree": source_repository["worktree"], "upstream": upstream,
            "ahead": ahead, "behind": behind,
        },
        "changes": {
            "changed_files": changed_files, "staged_files": staged_files,
            "unstaged_files": unstaged_files,
            "untracked_files": untracked_files, "insertions": insertions,
            "deletions": deletions, "staged_insertions": staged_insertions,
            "staged_deletions": staged_deletions, "unstaged_insertions": unstaged_insertions,
            "unstaged_deletions": unstaged_deletions, "paths": paths,
            "paths_truncated": source_repository["changed_paths_truncated"] or
            len(source_repository["changed_paths"]) > dev_status.MAX_CHANGED_PATHS,
        },
        "host": {"hostname": _text(source_host["hostname"]),
                 "username": _text(source_host["username"]), "groups": groups,
                 "groups_truncated": len(source_host["groups"]) > MAX_GROUPS},
        "security_boundary": dict(source_boundary),
        "environment": {"python_version": _text(source_environment["python_version"]),
                        "git_version": _text(source_environment["git_version"])},
    }


# Render the paste-ready handoff and expose the command-line entrypoint.
def render_human(handoff: dict[str, object]) -> str:
    """Format the collected handoff as compact, labeled text."""
    repository = handoff["repository"]
    changes = handoff["changes"]
    host = handoff["host"]
    boundary = handoff["security_boundary"]
    environment = handoff["environment"]

    def count(value: int | None) -> str:
        """Show unavailable counts without implying a zero value."""
        return str(value) if value is not None else "unavailable"

    return "\n".join([
        "OMNILYZER DEV HANDOFF", "", "Repository",
        f"  Branch: {repository['branch']}", f"  HEAD: {repository['head']}",
        f"  Worktree: {repository['worktree']}", f"  Upstream: {repository['upstream']}",
        f"  Ahead: {count(repository['ahead'])}", f"  Behind: {count(repository['behind'])}",
        "", "Changes",
        f"  Changed files: {count(changes['changed_files'])}",
        f"  Staged files: {count(changes['staged_files'])}",
        f"  Unstaged files: {count(changes['unstaged_files'])}",
        f"  Untracked files: {count(changes['untracked_files'])}",
        f"  Staged +/-: {count(changes['staged_insertions'])}/{count(changes['staged_deletions'])}",
        f"  Unstaged +/-: {count(changes['unstaged_insertions'])}/{count(changes['unstaged_deletions'])}",
        f"  Insertions: {count(changes['insertions'])}",
        f"  Deletions: {count(changes['deletions'])}",
        "  Paths: " + json.dumps(changes["paths"], ensure_ascii=True)
        + (" (truncated)" if changes["paths_truncated"] else ""),
        "", "Host",
        f"  Hostname: {host['hostname']}", f"  Username: {host['username']}",
        "  Groups: " + json.dumps(host["groups"], ensure_ascii=True)
        + (" (truncated)" if host["groups_truncated"] else ""),
        "", "Security boundary",
        f"  Passwordless sudo: {boundary['passwordless_sudo_available']}",
        f"  Docker socket: exists={boundary['docker_socket_exists']}, "
        f"unix={boundary['docker_socket_is_unix_socket']}",
        "", "Environment",
        f"  Python: {environment['python_version']}", f"  Git: {environment['git_version']}",
    ])


def main(argv: list[str] | None = None) -> int:
    """Print the human or JSON handoff; fail on required status errors."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="emit compact JSON")
    arguments = parser.parse_args(argv)
    try:
        handoff = collect_handoff()
    except dev_status.StatusError:
        print("Development handoff unavailable: Git repository status could not be collected.",
              file=sys.stderr)
        return 1
    if arguments.json:
        print(json.dumps(handoff, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    else:
        print(render_human(handoff))
    return 0


if __name__ == "__main__":
    sys.exit(main())
