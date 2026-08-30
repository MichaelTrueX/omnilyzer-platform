#!/usr/bin/env python3
"""Task 009 Django management entry point."""

from __future__ import annotations

import os
import sys


def main() -> None:
    """Run Django management commands for the isolated fixture."""

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "observability_spike.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
