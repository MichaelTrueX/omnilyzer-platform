#!/usr/bin/env python3
"""Build a deterministic non-executable Task 008D OCI handoff."""

from __future__ import annotations

import argparse
from pathlib import Path

from zot_oci_common import build_handoff


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    record = build_handoff(args.output, args.source_commit, args.tag)
    print(record["baseline"]["manifest_digest"])


if __name__ == "__main__":
    main()
