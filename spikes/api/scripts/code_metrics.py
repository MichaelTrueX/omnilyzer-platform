"""spikes/api/scripts/code_metrics.py: Measure framework-specific spike code size.

Related modules: drf_api, ninja_api, and spikes/api/results/comparison.md.
"""
from pathlib import Path
import json

SPIKE_ROOT = Path(__file__).resolve().parents[1]


def measure(directory: str) -> dict[str, object]:
    """Count Python files and nonblank, non-comment physical lines."""
    files = sorted((SPIKE_ROOT / directory).glob("*.py"))
    lines = 0
    for path in files:
        lines += sum(
            1
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    return {
        "files": [str(path.relative_to(SPIKE_ROOT)) for path in files],
        "file_count": len(files),
        "nonblank_noncomment_physical_lines": lines,
    }


def main() -> None:
    """Persist reproducible DRF and Ninja framework-specific code metrics."""
    document = {
        "method": "Python files and nonblank, non-comment physical lines; docstrings count.",
        "drf": {
            **measure("drf_api"),
            "direct_framework_dependencies": 2,
            "custom_hooks": [
                "authentication adapter",
                "exception handler",
                "permission adapter",
                "unknown-field validation mixin",
                "drf-spectacular schema annotations",
            ],
        },
        "django_ninja": {
            **measure("ninja_api"),
            "direct_framework_dependencies": 1,
            "custom_hooks": [
                "authentication adapter",
                "five exception handlers",
                "strict Ninja Schema base",
            ],
        },
    }
    output = SPIKE_ROOT / "results" / "code-metrics.json"
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps(document, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
