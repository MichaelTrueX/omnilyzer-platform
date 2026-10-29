"""File: deployment/analytics_executor_service_entrypoint.py

Purpose: Explicit process entrypoint for the separately approved Analytics
         Task014 root-controlled systemd service. No imported module, direct
         call, or repo PR activates a service.
Related: deployment/analytics_executor_service_bootstrap.py,
         deployment/systemd/dev/omnilyzer-deployment-analytics-executor.service,
         deployment/tests/test_analytics_executor_service_bootstrap.py.

Sections: one closed main entrypoint, process exit code and redacted failure.
"""
from __future__ import annotations

from .analytics_executor_service_bootstrap import (
    AnalyticsExecutorBootstrapError,
    run_analytics_executor_service_once,
)


def main() -> int:
    """Serve one authorized inherited Analytics FD or exit with failure."""
    try:
        run_analytics_executor_service_once()
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except AnalyticsExecutorBootstrapError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
