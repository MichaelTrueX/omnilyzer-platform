import json
import re
from pathlib import Path

from common import require_immutable, run


def start_registry(lock, name="omnilyzer-task007-registry"):
    image = lock["registry"]
    run(["docker", "run", "-d", "--name", name, "-p", "127.0.0.1:15007:5000", image])
    return name


def build_releases(root, source_revision):
    lock = json.loads((root / "images.lock.json").read_text())
    artifacts = {}
    for release in ("1.0.0", "1.1.0"):
        tag = f"localhost:15007/omnilyzer-task007:{release}"
        run([
            "docker", "buildx", "build", "--load", "--pull=false",
            "--build-arg", f"PYTHON_IMAGE={lock['python']}",
            "--build-arg", f"RELEASE={release}",
            "--build-arg", f"SOURCE_REVISION={source_revision}",
            "--tag", tag, "--file", str(root / "image/Dockerfile"), str(root),
        ], capture=False)
        output = run(["docker", "push", tag]).stdout
        match = re.search(r"digest: (sha256:[0-9a-f]{64})", output)
        if not match:
            raise RuntimeError(f"could not resolve pushed digest for {release}: {output}")
        reference = require_immutable(f"localhost:15007/omnilyzer-task007@{match.group(1)}")
        run(["docker", "pull", reference])
        artifacts[release] = {
            "tag": tag, "digest": match.group(1), "reference": reference,
            "image_id": run(["docker", "image", "inspect", reference, "--format", "{{.Id}}"]).stdout.strip(),
        }
    return artifacts
