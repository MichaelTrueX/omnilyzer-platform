import importlib.metadata
from pathlib import Path

import omnilyzer_platform_core as platform

assert platform.platform_release_version() == EXPECTED_PLATFORM_VERSION
assert importlib.metadata.version("omnilyzer-platform-core") == EXPECTED_PLATFORM_VERSION
assert platform.normalize_workspace_label("  Alpha Workspace  ") == "Alpha Workspace"
assert not hasattr(platform, "private_normalize_workspace_label")
module_path = Path(platform.__file__).resolve()
assert "site-packages" in module_path.parts
assert REPOSITORY_ROOT not in str(module_path)
print(f"python-core={EXPECTED_PLATFORM_VERSION} path={module_path}")
