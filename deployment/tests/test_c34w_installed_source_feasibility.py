"""File: deployment/tests/test_c34w_installed_source_feasibility.py

Purpose: Evaluate whether the EXISTING root-owned Omnilyzer DEV application
layout could contain the reviewed 73-source C34O recovery import closure
without installing, importing, updating or executing any privileged sources.
Also model a closed future loader environment and Python -I/-S compatibility.
Related: deployment/c34p_dependency_source_closure.py,
deployment/tests/test_c34v_privileged_import_seal.py,
deployment/host_service_layout.py,
docs/operations/task014-c34w-installed-source-feasibility.md,
.github/workflows/task014-c34d-review.yml.

Ordinary CI tests use only synthetic content and immutable Git blobs.
OMNILYZER_C34W_HOST_READONLY=1 opts into a nonprivileged, descriptor-based,
read-only installed-tree audit. All approvals remain FALSE even if every file
were to match; only an independent protected-main/root authority can approve.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import unittest

from deployment import c34p_dependency_source_closure as c34p
from deployment import host_service_layout as host_layout
from deployment.tests import test_c34v_privileged_import_seal as c34v


# Section 1: Existing host layout, limits and non-authorizing receipt.
_ERROR = "C34W installed source feasibility is unavailable"
_SOURCE_ROOT = Path("/opt/omnilyzer/deployment/app")
_INSTALL = Path("/opt/omnilyzer/deployment")
_VENV = _INSTALL / "venv"
_PACKAGE = _SOURCE_ROOT / "deployment"
_PYTHON = _VENV / "bin/python"
_EXPECTED_SOURCES = 73
_CURRENT_INSTALLED_SOURCES = 38
_EXPECTED_SHARED = 19
_EXPECTED_MISSING = 54
_EXPECTED_CONFLICTS = 1
_EXPECTED_SURPLUS = 19
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_LOCAL_PY = re.compile(r"deployment/(?:__init__|[a-z][a-z0-9_]*)\.py\Z")
_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_HOST_AUDIT = "OMNILYZER_C34W_HOST_READONLY"

# These are future proposed minimum prohibitions, not current unit settings.
_FORBIDDEN_PREFIXES = ("LD_", "PYTHON", "OPENSSL_", "NSS_")
_FORBIDDEN_EXACT = frozenset((
    "BASH_ENV", "ENV", "GCONV_PATH", "IFS", "LOCPATH",
))
_MINIMUM_LAUNCH_ENVIRONMENT = frozenset(("LANG", "LC_ALL", "PATH", "TZ"))


class InstalledSourceReviewHold(Exception):
    """Fixed error; does not disclose host paths, contents or secret values."""


@dataclass(frozen=True, slots=True)
class InstalledSourceComparison:
    """Pure nonauthoritative installed/desired relative Git path comparison."""

    expected_count: int
    installed_count: int
    matching_paths: tuple[str, ...]
    missing_paths: tuple[str, ...]
    conflicting_paths: tuple[str, ...]
    surplus_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        """Ensure the sets form a valid closed two-inventory comparison."""
        parts = (
            self.matching_paths, self.missing_paths,
            self.conflicting_paths, self.surplus_paths,
        )
        if (
            type(self.expected_count) is not int
            or type(self.installed_count) is not int
            or not all(type(group) is tuple for group in parts)
            or any(
                group != tuple(sorted(set(group)))
                or any(_LOCAL_PY.fullmatch(p) is None for p in group)
                for group in parts
            )
            or len(set().union(*map(set, parts))) != sum(map(len, parts))
            or self.expected_count != (
                len(self.matching_paths) + len(self.missing_paths)
                + len(self.conflicting_paths)
            )
            or self.installed_count != (
                len(self.matching_paths) + len(self.conflicting_paths)
                + len(self.surplus_paths)
            )
        ):
            raise ValueError(_ERROR)

    @property
    def ready_for_immutable_package_approval(self) -> bool:
        """Report only source-set equality, never root execution authorization."""
        return not (
            self.missing_paths or self.conflicting_paths or self.surplus_paths
        )


@dataclass(frozen=True, slots=True)
class C34WInstalledFeasibilityReceipt:
    """Observed C34W host gap facts; four hard-coded unapproved gates."""

    candidate_sha: str
    expected_python_sources: int
    installed_python_sources: int
    required_missing: int
    differing_shared: int
    installed_other_sources: int
    root_owned_directory_chain_observed: bool
    python_isolated_locates_crypto: bool
    python_isolated_no_site_locates_crypto: bool
    installed_source_complete: bool = False
    privileged_runtime_loader_sealed: bool = False
    protected_main_approved: bool = False
    root_execution_approved: bool = False

    def __post_init__(self) -> None:
        """Deny forged claims and changes to exact assessed host scope."""
        if (
            type(self.candidate_sha) is not str
            or re.fullmatch(r"[a-f0-9]{40}", self.candidate_sha) is None
            or self.expected_python_sources != _EXPECTED_SOURCES
            or self.installed_python_sources != _CURRENT_INSTALLED_SOURCES
            or self.required_missing != _EXPECTED_MISSING
            or self.differing_shared != _EXPECTED_CONFLICTS
            or self.installed_other_sources != _EXPECTED_SURPLUS
            or self.root_owned_directory_chain_observed is not True
            or self.python_isolated_locates_crypto is not True
            or self.python_isolated_no_site_locates_crypto is not False
            or self.installed_source_complete is not False
            or self.privileged_runtime_loader_sealed is not False
            or self.protected_main_approved is not False
            or self.root_execution_approved is not False
        ):
            raise ValueError(_ERROR)


# Section 2: Pure source equality and future loader-environment checks.
def compare_sources(
    expected: dict[str, str], installed: dict[str, str],
) -> InstalledSourceComparison:
    """Compare complete relative source path/hash inventories, not file names."""
    def valid(values: object) -> bool:
        """Reject unbounded or malformed fake manifests."""
        return (
            type(values) is dict and not len(values) > 192
            and all(
                type(path) is str and _LOCAL_PY.fullmatch(path) is not None
                and type(digest) is str and _SHA.fullmatch(digest) is not None
                for path, digest in values.items()
            )
        )
    if not valid(expected) or not valid(installed) or not expected:
        raise ValueError(_ERROR)
    shared = set(expected) & set(installed)
    same = tuple(sorted(p for p in shared if expected[p] == installed[p]))
    conflict = tuple(sorted(p for p in shared if expected[p] != installed[p]))
    result = InstalledSourceComparison(
        len(expected), len(installed), same,
        tuple(sorted(set(expected) - shared)), conflict,
        tuple(sorted(set(installed) - shared)),
    )
    InstalledSourceComparison.__post_init__(result)
    return result


def proposed_privileged_environment_is_closed(
    keys: tuple[str, ...],
) -> bool:
    """Evaluate a future minimal environment policy WITHOUT changing process env."""
    if (
        type(keys) is not tuple
        or any(type(k) is not str or not k.isascii() or
               re.fullmatch(r"[A-Z][A-Z0-9_]*", k) is None for k in keys)
        or tuple(sorted(set(keys))) != keys
    ):
        return False
    if any(k in _FORBIDDEN_EXACT or k.startswith(_FORBIDDEN_PREFIXES)
           for k in keys):
        return False
    return all(key in _MINIMUM_LAUNCH_ENVIRONMENT for key in keys)


# Section 3: Unprivileged descriptor-based inspection of the existing app.
def _require_root_directory(path: Path) -> None:
    """Read owner/mode only for a pinned directory, reject symlinks and writes."""
    s = path.lstat()
    if (
        not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_gid != 0
        or stat.S_IMODE(s.st_mode) != 0o755
    ):
        raise ValueError(_ERROR)


def _sha256_root_source(path: Path) -> str:
    """Hash an installed root-owned regular .py without following a symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        first = os.fstat(fd)
        named = path.lstat()
        def sig(s: os.stat_result) -> tuple[int, ...]:
            """Bind path identity to FD and detect size/time/owner mutations."""
            return (
                s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
                s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink,
            )
        if (
            sig(first) != sig(named)
            or not stat.S_ISREG(first.st_mode)
            or first.st_uid != 0 or first.st_gid != 0
            or stat.S_IMODE(first.st_mode) != 0o644
            or first.st_nlink != 1 or not 0 < first.st_size <= 1024 * 1024
        ):
            raise ValueError(_ERROR)
        remaining = first.st_size
        h = hashlib.sha256()
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                raise ValueError(_ERROR)
            h.update(part)
            remaining -= len(part)
        if (
            os.read(fd, 1)
            or sig(first) != sig(os.fstat(fd))
            or sig(first) != sig(path.lstat())
        ):
            raise ValueError(_ERROR)
        return h.hexdigest()
    finally:
        os.close(fd)


def _installed_python_sources() -> dict[str, str]:
    """Observe the current root-owned flat package without importing it."""
    for d in (
        Path("/opt"), Path("/opt/omnilyzer"), _INSTALL, _SOURCE_ROOT, _PACKAGE,
        _VENV, _VENV / "lib", _VENV / "lib/python3.12",
        _VENV / "lib/python3.12/site-packages",
    ):
        _require_root_directory(d)
    installed: dict[str, str] = {}
    for name in sorted(os.listdir(_PACKAGE)):
        if not name.endswith(".py"):
            continue
        if re.fullmatch(r"(?:__init__|[a-z][a-z0-9_]*)\.py", name) is None:
            raise ValueError(_ERROR)
        rel = "deployment/" + name
        installed[rel] = _sha256_root_source(_PACKAGE / name)
    if not installed or len(installed) > 192:
        raise ValueError(_ERROR)
    return installed


def _crypto_spec_observed(*, flags: tuple[str, ...]) -> bool:
    """Read spec availability using the existing interpreter; do NOT import wheel."""
    if flags not in (("-I",), ("-I", "-S")):
        raise ValueError(_ERROR)
    command = (
        str(_PYTHON), *flags, "-c",
        "import importlib.util; print(importlib.util.find_spec('cryptography') is not None)",
    )
    completed = subprocess.run(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, shell=False, timeout=10, check=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    if completed.stdout not in (b"True\n", b"False\n"):
        raise ValueError(_ERROR)
    return completed.stdout == b"True\n"


# Section 4: Exact candidate Git evidence + read-only real-host assessment.
def _git_candidate_review() -> tuple[str, dict[str, str]]:
    """Recompute the C34P candidate from Git objects with lazy fetch disabled."""
    repo = Path(__file__).resolve().parents[2]
    common_env = dict(os.environ, GIT_NO_LAZY_FETCH="1")
    sha = subprocess.run(
        ("git", "rev-parse", "HEAD"), cwd=repo, capture_output=True,
        check=True, timeout=10, text=True, env=common_env,
    ).stdout.strip()

    def blob(path: str) -> bytes:
        """Read one exact immutable candidate blob without checking out files."""
        return subprocess.run(
            ("git", "cat-file", "blob", sha + ":" + path),
            cwd=repo, capture_output=True, check=True,
            timeout=10, env=common_env,
        ).stdout

    closure = c34p.inspect_c34p_git_blob_closure(
        candidate_sha=sha, blob_reader=blob,
    )
    if (
        closure.local_module_count != _EXPECTED_SOURCES
        or closure.unresolved_third_party != ("cryptography",)
        or closure.root_execution_approved is not False
    ):
        raise ValueError(_ERROR)
    return sha, dict(closure.local_source_blobs)


def observe_readonly_c34w_installed_gap() -> C34WInstalledFeasibilityReceipt:
    """Read only existing source bytes and interpreter flags; ALWAYS keep HOLD."""
    try:
        service = host_layout.DevHostServiceLayout()
        host_layout.DevHostServiceLayout.__post_init__(service)
        if (
            service.application_root != str(_SOURCE_ROOT)
            or service.python_executable != str(_PYTHON)
            or service.virtualenv_root != str(_VENV)
        ):
            raise ValueError
        sha, expected = _git_candidate_review()
        installed = _installed_python_sources()
        gap = compare_sources(expected, installed)
        if (
            gap.expected_count != _EXPECTED_SOURCES
            or gap.installed_count != _CURRENT_INSTALLED_SOURCES
            or len(gap.matching_paths) != _EXPECTED_SHARED - _EXPECTED_CONFLICTS
            or len(gap.missing_paths) != _EXPECTED_MISSING
            or gap.conflicting_paths != ("deployment/broker.py",)
            or len(gap.surplus_paths) != _EXPECTED_SURPLUS
        ):
            raise ValueError
        result = C34WInstalledFeasibilityReceipt(
            candidate_sha=sha,
            expected_python_sources=gap.expected_count,
            installed_python_sources=gap.installed_count,
            required_missing=len(gap.missing_paths),
            differing_shared=len(gap.conflicting_paths),
            installed_other_sources=len(gap.surplus_paths),
            root_owned_directory_chain_observed=True,
            python_isolated_locates_crypto=_crypto_spec_observed(flags=("-I",)),
            python_isolated_no_site_locates_crypto=_crypto_spec_observed(
                flags=("-I", "-S"),
            ),
        )
        C34WInstalledFeasibilityReceipt.__post_init__(result)
        return result
    except _CONTROL:
        raise
    except Exception:
        raise InstalledSourceReviewHold(_ERROR) from None


# Section 5: Offline synthetic negative regressions, no installed app access.
class C34WReviewOnlyUnitTests(unittest.TestCase):
    """Guard source substitution, unsafe loader env and forged root approval."""

    def test_a_equal_sources_are_not_root_authorization(self) -> None:
        """Byte equality is necessary, never sufficient for privileged import."""
        expected = {"deployment/alpha.py": "a" * 64}
        compared = compare_sources(expected, dict(expected))
        self.assertTrue(compared.ready_for_immutable_package_approval)
        self.assertEqual(compared.expected_count, 1)

    def test_b_missing_extra_conflicting_sources_distinguished(self) -> None:
        """Never treat an arbitrary root app union as a sealed 73-source package."""
        expected = {"deployment/a.py": "a" * 64,
                    "deployment/b.py": "b" * 64,
                    "deployment/c.py": "c" * 64}
        observed = {"deployment/a.py": "a" * 64,
                    "deployment/b.py": "d" * 64,
                    "deployment/d.py": "d" * 64}
        compared = compare_sources(expected, observed)
        self.assertEqual(
            (len(compared.matching_paths), len(compared.missing_paths),
             len(compared.conflicting_paths), len(compared.surplus_paths)),
            (1, 1, 1, 1),
        )
        self.assertFalse(compared.ready_for_immutable_package_approval)

    def test_c_unsafe_paths_hashes_and_mutable_overlays_rejected(self) -> None:
        """Path traversal and false hashes cannot be accepted as exact sources."""
        for bad in (
            {"../tmp/a.py": "a" * 64},
            {"deployment/a.py": "x" * 64},
            {"deployment/a.py": "a" * 63},
            {"deployment/sub/a.py": "a" * 64},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                compare_sources({"deployment/a.py": "a" * 64}, bad)

    def test_d_future_env_denylist_catches_loader_overrides(self) -> None:
        """Future root process cannot inherit even subtle PYTHON/LD injection."""
        self.assertTrue(proposed_privileged_environment_is_closed(
            ("LANG", "PATH"),
        ))
        for key in (
            "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "PYTHONPATH",
            "PYTHONHOME", "PYTHONINSPECT", "OPENSSL_CONF", "OPENSSL_MODULES",
            "NSS_MODULES", "GCONV_PATH", "LOCPATH", "BASH_ENV", "IFS",
            "UNREVIEWED_RUNTIME_CONFIG",
        ):
            with self.subTest(key=key):
                self.assertFalse(proposed_privileged_environment_is_closed(
                    ("LANG", key, "PATH") if "LANG" < key < "PATH" else
                    tuple(sorted(("LANG", "PATH", key))),
                ))

    def test_e_source_mismatch_cannot_forge_approved_receipt(self) -> None:
        """No result from the nonroot audit can claim sealed source or root."""
        original = C34WInstalledFeasibilityReceipt(
            candidate_sha="a" * 40,
            expected_python_sources=73, installed_python_sources=38,
            required_missing=54, differing_shared=1,
            installed_other_sources=19,
            root_owned_directory_chain_observed=True,
            python_isolated_locates_crypto=True,
            python_isolated_no_site_locates_crypto=False,
        )
        for flag in (
            "installed_source_complete", "privileged_runtime_loader_sealed",
            "protected_main_approved", "root_execution_approved",
        ):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                replace(original, **{flag: True})
        with self.assertRaises(ValueError):
            replace(original, required_missing=0)

    def test_f_source_inventory_cannot_follow_symlink(self) -> None:
        """Root source inspection opens with O_NOFOLLOW, not a symlink chase."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp, "actual.py")
            source.write_bytes(b"x=1\n")
            shortcut = Path(tmp, "symbolic.py")
            shortcut.symlink_to(source)
            with self.assertRaises(OSError):
                _sha256_root_source(shortcut)


# Section 6: Actual installed host is checked only with explicit opt-in.
@unittest.skipUnless(
    os.environ.get(_HOST_AUDIT) == "1",
    "no installed root-owned source audit requested",
)
class C34WActualHostReview(unittest.TestCase):
    """Describe the existing immutable-source gap, never authorize execution."""

    def test_existing_root_app_does_not_have_c34o_import_seal(self) -> None:
        """Expected real-host result is intentional HOLD, not deployment GO."""
        receipt = observe_readonly_c34w_installed_gap()
        self.assertFalse(receipt.installed_source_complete)
        self.assertFalse(receipt.root_execution_approved)
        print(
            "C34W_INSTALLED_HOLD candidate=73 installed=38 shared=19 "
            "missing=54 differing=1 surplus=19 "
            "isolated_crypto=true isolated_no_site_crypto=false "
            "root_approved=false"
        )


if __name__ == "__main__":
    unittest.main()
