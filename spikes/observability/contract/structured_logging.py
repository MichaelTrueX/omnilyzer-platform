"""Standard-library JSON logging with defensive sensitive-data redaction."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Mapping

from .context import current_request_id, current_trace_id


_EVENT = re.compile(r"[a-z][a-z0-9_.]{0,63}")
_SENSITIVE_KEY = re.compile(
    r"(?:password|access[_-]?token|refresh[_-]?token|authorization|cookie|"
    r"csrf|api[_-]?key|secret|request[_-]?body|document[_-]?content)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|access[_-]?token|refresh[_-]?token|authorization|"
    r"csrf[_-]?token|api[_-]?key|session(?:id)?|secret)\s*[:=]\s*[^\s,;]+"
)
_COOKIE = re.compile(r"(?i)(?:__Host-[^=;\s]+|sessionid|csrftoken)=[^;\s]+")
REDACTED = "[REDACTED]"


def redact(value: Any, *, key: str | None = None) -> Any:
    """Recursively redact denylisted fields and recognizable credential strings."""

    if key is not None and _SENSITIVE_KEY.search(key):
        return REDACTED
    if isinstance(value, Mapping):
        return {str(item_key): redact(item, key=str(item_key)) for item_key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        sanitized = _BEARER.sub("Bearer [REDACTED]", value)
        sanitized = _ASSIGNMENT.sub(lambda match: f"{match.group(1)}={REDACTED}", sanitized)
        return _COOKIE.sub(REDACTED, sanitized)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


class JsonFormatter(logging.Formatter):
    """Serialize the bounded logging contract as one newline-delimited JSON object."""

    def __init__(self, *, service: str, product: str, environment: str) -> None:
        super().__init__()
        self._metadata = {
            "service": service,
            "product": product,
            "environment": environment,
        }

    def format(self, record: logging.LogRecord) -> str:
        event = getattr(record, "event", record.getMessage())
        if not isinstance(event, str) or _EVENT.fullmatch(event) is None:
            event = "logging.invalid_event"
        timestamp = datetime.fromtimestamp(record.created, timezone.utc).isoformat(
            timespec="milliseconds"
        ).replace("+00:00", "Z")
        payload: dict[str, Any] = {
            "timestamp": timestamp,
            "level": record.levelname,
            **self._metadata,
            "event": event,
            "request_id": current_request_id(),
            "trace_id": current_trace_id(),
        }
        fields = getattr(record, "event_fields", {})
        payload["fields"] = redact(fields if isinstance(fields, Mapping) else {})
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def event(
    logger: logging.Logger,
    name: str,
    *,
    level: int = logging.INFO,
    fields: Mapping[str, Any] | None = None,
) -> None:
    """Emit a structured event without interpolating arbitrary values into its name."""

    logger.log(level, name, extra={"event": name, "event_fields": dict(fields or {})})
