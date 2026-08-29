from contextlib import contextmanager
from uuid import UUID

from django.db import connections, transaction


@contextmanager
def workspace_scope(workspace_id):
    """Run runtime-role work in one transaction-local Workspace context.

    The caller must authorize the Workspace before entering this scope. RLS only
    enforces the supplied boundary; it does not decide whether a caller belongs
    to that Workspace. Nested transactions/scopes are rejected so the context
    cannot be rebound before the outer transaction finishes.
    """

    workspace_uuid = UUID(str(workspace_id))
    connection = connections["default"]
    if connection.in_atomic_block:
        raise RuntimeError("workspace_scope cannot be nested in another transaction")

    with transaction.atomic(using="default"):
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT set_config('omnilyzer.workspace_id', %s, true)",
                [str(workspace_uuid)],
            )
        yield
