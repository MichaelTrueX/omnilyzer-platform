#!/usr/bin/env python3
"""Validate exact Buildx and BuildKit versions from their command output."""

from __future__ import annotations

import argparse
import re
import sys
from typing import Callable


EXPECTED_BUILDX_VERSION = "v0.36.1"
EXPECTED_BUILDKIT_VERSION = "v0.24.0"
MAX_OUTPUT_LENGTH = 64 * 1024

BUILDX_LINE = re.compile(
    r"github\.com/docker/buildx[ \t]+(v[0-9]+\.[0-9]+\.[0-9]+)"
    r"(?:[ \t]+[0-9a-f]{40})?[ \t]*\Z",
)
BUILDKIT_LINE = re.compile(
    r"BuildKit version:[ \t]+(v[0-9]+\.[0-9]+\.[0-9]+)[ \t]*\Z",
)


class BuilderVersionError(ValueError):
    pass


def _validate_output(output: str) -> list[str]:
    if len(output) > MAX_OUTPUT_LENGTH:
        raise BuilderVersionError("builder version output exceeds the size limit")
    if "\x00" in output:
        raise BuilderVersionError("builder version output contains NUL")
    return output.splitlines()


def _require_exact_field(
    output: str,
    *,
    prefix: str,
    pattern: re.Pattern[str],
    expected: str,
    tool: str,
) -> str:
    lines = _validate_output(output)
    fields = [line for line in lines if line.startswith(prefix)]
    if len(fields) != 1:
        raise BuilderVersionError(f"expected exactly one {tool} version field")
    match = pattern.fullmatch(fields[0])
    if match is None or match.group(1) != expected:
        raise BuilderVersionError(f"{tool} version is not exactly {expected}")
    return match.group(1)


def verify_buildx_output(output: str) -> str:
    return _require_exact_field(
        output,
        prefix="github.com/docker/buildx",
        pattern=BUILDX_LINE,
        expected=EXPECTED_BUILDX_VERSION,
        tool="Buildx",
    )


def verify_buildkit_output(output: str) -> str:
    return _require_exact_field(
        output,
        prefix="BuildKit version:",
        pattern=BUILDKIT_LINE,
        expected=EXPECTED_BUILDKIT_VERSION,
        tool="BuildKit",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("tool", choices=("buildx", "buildkit"))
    args = parser.parse_args()
    validators: dict[str, Callable[[str], str]] = {
        "buildx": verify_buildx_output,
        "buildkit": verify_buildkit_output,
    }
    try:
        print(validators[args.tool](sys.stdin.read()))
    except BuilderVersionError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
