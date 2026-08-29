import re

_PRIVATE_SENTINEL = "implementation-detail"


def normalize_workspace_label(value):
    return str(value).strip()


def workspace_slug(value):
    return re.sub(r"[^a-z0-9]+", "-", normalize_workspace_label(value).lower()).strip("-")
