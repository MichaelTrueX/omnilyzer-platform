"""Fail-closed parsing for bounded observability configuration."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Mapping
from urllib.parse import urlparse


_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
_ENVIRONMENTS = {"local", "test", "dev", "staging", "prod"}


def _boolean(value: str, name: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError(f"{name} must be exactly true or false")


def _integer(value: str, name: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _endpoint(value: str, environment: str) -> str:
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != "/v1/traces"
    ):
        raise ValueError("OTLP endpoint must be a credential-free HTTP(S) /v1/traces URL")
    if parsed.scheme == "http" and environment not in {"local", "test", "dev"}:
        raise ValueError("plaintext OTLP is restricted to local, test, or dev")
    if parsed.scheme == "http":
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            address = None
        if environment in {"local", "test"} and not (address and address.is_loopback):
            raise ValueError("local and test plaintext OTLP must use a loopback address")
    return value


@dataclass(frozen=True, slots=True)
class ObservabilityConfig:
    """Validated settings controlling only product-side trace export."""

    enabled: bool
    service: str
    product: str
    environment: str
    trust_incoming_request_id: bool
    trust_incoming_trace_context: bool
    otlp_endpoint: str | None
    export_timeout_millis: int
    schedule_delay_millis: int
    max_queue_size: int
    max_export_batch_size: int

    @classmethod
    def from_mapping(cls, values: Mapping[str, str]) -> "ObservabilityConfig":
        """Parse a small explicit configuration surface with bounded values."""

        enabled = _boolean(values.get("OBSERVABILITY_ENABLED", "false"), "OBSERVABILITY_ENABLED")
        service = values.get("OBSERVABILITY_SERVICE", "observability-spike")
        product = values.get("OBSERVABILITY_PRODUCT", "synthetic-product")
        environment = values.get("OBSERVABILITY_ENVIRONMENT", "test")
        trust_incoming_request_id = _boolean(
            values.get("OBSERVABILITY_TRUST_INCOMING_REQUEST_ID", "false"),
            "OBSERVABILITY_TRUST_INCOMING_REQUEST_ID",
        )
        trust_incoming_trace_context = _boolean(
            values.get("OBSERVABILITY_TRUST_INCOMING_TRACE_CONTEXT", "false"),
            "OBSERVABILITY_TRUST_INCOMING_TRACE_CONTEXT",
        )
        if _NAME.fullmatch(service) is None or _NAME.fullmatch(product) is None:
            raise ValueError("service and product must use bounded lowercase slug format")
        if environment not in _ENVIRONMENTS:
            raise ValueError("environment is not in the bounded allowlist")
        raw_endpoint = values.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        endpoint = _endpoint(raw_endpoint, environment) if raw_endpoint else None
        if enabled and endpoint is None:
            raise ValueError("enabled tracing requires an explicit OTLP traces endpoint")
        timeout = _integer(values.get("OTEL_EXPORT_TIMEOUT_MILLIS", "250"), "OTEL_EXPORT_TIMEOUT_MILLIS", 50, 5000)
        delay = _integer(values.get("OTEL_BSP_SCHEDULE_DELAY_MILLIS", "50"), "OTEL_BSP_SCHEDULE_DELAY_MILLIS", 10, 5000)
        queue = _integer(values.get("OTEL_BSP_MAX_QUEUE_SIZE", "128"), "OTEL_BSP_MAX_QUEUE_SIZE", 16, 4096)
        batch = _integer(values.get("OTEL_BSP_MAX_EXPORT_BATCH_SIZE", "32"), "OTEL_BSP_MAX_EXPORT_BATCH_SIZE", 1, queue)
        return cls(
            enabled,
            service,
            product,
            environment,
            trust_incoming_request_id,
            trust_incoming_trace_context,
            endpoint,
            timeout,
            delay,
            queue,
            batch,
        )
