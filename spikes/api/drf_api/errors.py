"""spikes/api/drf_api/errors.py: Normalize DRF and application exceptions.

Related modules: domain.exceptions, drf_api.serializers, and config.settings.
Unexpected exceptions are logged server-side and never serialized to clients.
"""
import logging
from typing import Any
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.views import exception_handler
from domain.exceptions import ApplicationError

logger = logging.getLogger(__name__)


def _plain(value: Any) -> Any:
    """Convert DRF lazy error values into JSON-safe built-in values."""
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return str(value)


def error_payload(
    *, code: str, message: str, details: dict[str, object] | list[object] | None = None
) -> dict[str, object]:
    """Build the normalized experimental error envelope."""
    return {
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        }
    }


def normalized_exception_handler(exc: Exception, context: dict[str, Any]) -> Response:
    """Map expected and unexpected DRF errors to safe normalized responses."""
    if isinstance(exc, ApplicationError):
        return Response(
            error_payload(code=exc.code, message=exc.message, details=exc.details),
            status=exc.status_code,
        )
    if isinstance(exc, exceptions.ValidationError):
        return Response(
            error_payload(
                code="validation_error",
                message="Request validation failed.",
                details=_plain(exc.detail),
            ),
            status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )
    if isinstance(exc, exceptions.ParseError):
        return Response(
            error_payload(
                code="malformed_request",
                message="Request body is malformed.",
            ),
            status=status.HTTP_400_BAD_REQUEST,
        )
    if isinstance(exc, (exceptions.AuthenticationFailed, exceptions.NotAuthenticated)):
        return Response(
            error_payload(
                code="authentication_required",
                message="Authentication is required.",
            ),
            status=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Synthetic"},
        )
    if isinstance(exc, exceptions.MethodNotAllowed):
        return Response(
            error_payload(
                code="method_not_allowed",
                message="HTTP method is not allowed.",
            ),
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )
    response = exception_handler(exc, context)
    if response is not None:
        return Response(
            error_payload(
                code="request_error",
                message="The request could not be completed.",
                details=_plain(response.data),
            ),
            status=response.status_code,
        )
    logger.exception("Unhandled DRF spike API exception", exc_info=exc)
    return Response(
        error_payload(
            code="internal_error",
            message="An internal error occurred.",
        ),
        status=status.HTTP_500_INTERNAL_SERVER_ERROR,
    )
