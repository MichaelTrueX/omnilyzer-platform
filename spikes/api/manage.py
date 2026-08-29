#!/usr/bin/env python3
"""spikes/api/manage.py: Run Django commands for the removable API spike.

Related modules: config.settings and config.urls.
"""
import os
import sys


def main() -> None:
    """Configure the spike settings module and dispatch a Django command."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
