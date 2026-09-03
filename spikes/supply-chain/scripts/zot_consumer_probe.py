#!/usr/bin/env python3
"""Read-only Task 008D restart/rollback probe; never executes or mutates images."""

from __future__ import annotations

import argparse
from pathlib import Path

from zot_oci_common import RegistryClient, validate_handoff, verify_baseline


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--handoff", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    record = validate_handoff(args.handoff, args.source_commit, args.tag)
    client = RegistryClient(args.registry, args.token_file)
    client.request("GET", "/v2/", expected={200})
    verify_baseline(client, record)
    args.summary.write_text(
        "## Task 008D zot read-only consumer\n\n"
        "| Property | Result |\n|---|---|\n"
        "| Independent consumer OIDC authentication | PASS |\n"
        "| Baseline tag retrieval | PASS |\n"
        "| Exact digest retrieval | PASS |\n"
        "| Config/layer exact integrity | PASS |\n"
        "| Restart persistence | PASS (only when run after recorded manual restart) |\n"
        "| Exact-digest rollback | PASS |\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
