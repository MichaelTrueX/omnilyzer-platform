"""Quiet test runner so expected request telemetry does not obscure evidence output."""

from __future__ import annotations

import logging

from django.test.runner import DiscoverRunner


class QuietObservabilityRunner(DiscoverRunner):
    """Suppress routine fixture logs while tests assert them through explicit handlers."""

    def setup_test_environment(self, **kwargs) -> None:
        super().setup_test_environment(**kwargs)
        logger = logging.getLogger("omnilyzer.observability")
        logger.handlers = [logging.NullHandler()]
        logger.propagate = False
