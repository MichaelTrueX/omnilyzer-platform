"""deployment/executor_service_entrypoint.py — closed C20 process entrypoint.

Purpose: map one C19 ``run_dev_executor_service_once()`` attempt to a fixed
process status. The supported execution form is
``python -m deployment.executor_service_entrypoint``. Import is inert. Normal
success exits with 0; ordinary failure or an unexpected non-``None`` result
exits with 1; unsupported trailing arguments exit with 2. No systemd or other
service asset is installed or started, no host resource is provisioned, and no
deployment authority is automatically activated.
"""

from __future__ import annotations

import sys as _sys

from .executor_service_bootstrap import (
    run_dev_executor_service_once as _run_dev_executor_service_once,
)


__all__ = (
    "main",
)

_SUCCESS_EXIT_CODE = 0
_FAILURE_EXIT_CODE = 1
_USAGE_EXIT_CODE = 2


def main() -> int:
    """Run exactly one C19 attempt and map its normal outcome to 0 or 1."""

    try:
        result = _run_dev_executor_service_once()
    except Exception:
        return _FAILURE_EXIT_CODE
    if result is None:
        return _SUCCESS_EXIT_CODE
    return _FAILURE_EXIT_CODE


# Reject unsupported process arguments before crossing the C19 boundary.
if __name__ == "__main__":
    if len(_sys.argv) != 1:
        raise SystemExit(_USAGE_EXIT_CODE)
    raise SystemExit(main())
