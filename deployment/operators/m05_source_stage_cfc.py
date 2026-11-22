#!/usr/bin/python3 -I
"""File: /usr/local/libexec/omnilyzer-m05-ordinary-source-stage-cfc.py

Purpose: Stage precisely one new immutable 76-file Task014 Analytics DEV source
         generation from an independently reviewed installed root baseline.
Related: PR316 HEAD 17972bff312a3df7c6e5e4f3d83b239b9b11aba1,
         existing analytics_isolated_source_install.py root importer,
         .m05-ordinary-dev-review-handoff-330f-20261121/manifest.json,
         .m05-ordinary-dev-cutover-330f-20261121.py.
Sections: fixed pins; trusted bytes; closed root import graph; reviewed handoff; root stage; CLI.
This script never changes systemd, active OCI, Task014 replay, Docker or PROD.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import sys

# Section 1: exact audited source targets and pinned user-owned review bytes.
BASE = "330f3255f0067b9ddbe30d50466830bd71a55a11"
COMMIT = "17972bff312a3df7c6e5e4f3d83b239b9b11aba1"
PARENT = Path("/opt/omnilyzer/deployment")
ROOT = PARENT / ("analytics-app-release-" + BASE)
DEST = PARENT / ("analytics-app-release-" + COMMIT)
OPERATOR = Path("/usr/local/libexec/omnilyzer-m05-ordinary-source-stage-cfc.py")
SCRATCH = PARENT / ".m05-ordinary-reviewed-source-f4a69fc9a3afa361255365ed6d19419bcb58c1c8"
HANDOFF = Path("/home/omnigpt/repos/omnilyzer-platform/.delivery/m05-pr316-source-stage-17972-20261122")
MANIFEST = HANDOFF / "manifest.json"
MANIFEST_SHA = "1d57383e82b7f0efe9f6b28a6d7168ad3736c9dd2a2f75d59b54b8ac1cbb8f5a"
# Owner-root verified after the broker SHA rebinding; this root-installed
# importer must remain bit-for-bit identical, not merely root-owned.
INSTALLER_SHA = "cc7dfd7fb022a01772bb2f18fd1705f6e4f15e706903e4b47c8833b7d7f9ac5b"
INSTALLER = SCRATCH / "deployment/analytics_isolated_source_install.py"
REPLACEMENTS_SHA = {
    "deployment/analytics_executor.py":
        "34de557ca2d5e63adb6cc5c18c827dd5f266040e699525670d21c9667b84f5ff",
    "deployment/analytics_route_journal.py":
        "b4029a2a1f152ac7848ff2b9e73e9fb8a6ce40101b58cb301d57fb82730171cc",
}
# Section: fixed import-time and deferred import closure of the protected root installer.
# Only 330f root runtime files or the 16 separately Git-pinned private
# installer files may be imported. Historical SCRATCH runtime copies are
# intentionally bypassed, regardless of their unproven SHA256.
EXTRA_IMPORT_SOURCE_SHA = {
    "deployment/analytics_isolated_source_install.py": "cc7dfd7fb022a01772bb2f18fd1705f6e4f15e706903e4b47c8833b7d7f9ac5b",
    "deployment/analytics_source_archive.py": "7685c41b67b0ae3d8ffc92b18ab6318b89a2c64dd4bae3639b237df6aa693d4a",
    "deployment/analytics_source_handoff.py": "9c5183e29e26bfc53791ad3eb1e665d055a5ebef68f5e067a3192729c405bc20",
    "deployment/application_manifest.py": "99d2bddb45d341b46e24c77987c5c5f527b5fee28ad3fd6583b77ae6f23be669",
    "deployment/application_source_set.py": "2b6cffbbb54bcc995757bebd9253eee4efb02130b06b6bae0f8831d560b40720",
    "deployment/dev_host_provisioning_mechanics.py": "33ff3ef0346e5b75d4c5796d9af3ad6d4e8814e5c2b316cff1073f263c156df4",
    "deployment/dev_host_qualification.py": "8aaa651a1bacd905f0a4b78928a300af07935ff6e288ff228bedb763ef0dfb8b",
    "deployment/host_provisioning_contract.py": "2100e1dc69e7c9b135bafeaa0829041876ce3bc5a6722a78f076a394a6da15b0",
    "deployment/host_service_layout.py": "fb323635bf2ece8e520bb5a8bf8b8716ad625a25fd123237bb4481ccbf333a0b",
    "deployment/installation_integrity_contract.py": "4aa29a26815d3dd499c00ea4ab445a26e411f001e52f9c926ab29849a2249722",
    "deployment/pip_installer_provenance.py": "4dab87dcfd40f8666b25e56c97eb6bf680146c022a63a4de65820082a760d1e1",
    "deployment/pip_installer_qualification.py": "72dc38ab09ddd04f62d08c3e59b05f90a683c1c3e50a30193fe29bc740a33631",
    "deployment/python_environment_qualification.py": "9f9df741ac2fa2a192a034e0bab191d75e1ae410071082835bcef92bccc74b29",
    "deployment/python_interpreter_provenance.py": "6ab29c26380d6459cc1505bb2c2b0a85a0bd4acc151378f8c0c81c034634f35b",
    "deployment/wheelhouse_qualification.py": "1ad9c7692a0d1d714b2a118dddaf87917366c15f187564ef130a89ca62a8374b",
    "release/__init__.py": "330c2df95d9706ec9582877c4723f0284319365b5debe44ed5c8a1a2914fb325",
}
REQUIRED_IMPORT_SOURCE_PATHS = frozenset({
    "deployment/__init__.py",
    "deployment/analytics_active_state_review.py",
    "deployment/analytics_dev_release_review.py",
    "deployment/analytics_execution.py",
    "deployment/analytics_executor.py",
    "deployment/analytics_executor_service_config.py",
    "deployment/analytics_first_install.py",
    "deployment/analytics_isolated_source_install.py",
    "deployment/analytics_loopback_guard.py",
    "deployment/analytics_private_registry.py",
    "deployment/analytics_route_journal.py",
    "deployment/analytics_signed_release_consumer.py",
    "deployment/analytics_signed_source_pin.py",
    "deployment/analytics_source_archive.py",
    "deployment/analytics_source_handoff.py",
    "deployment/analytics_unix_boundary.py",
    "deployment/application_manifest.py",
    "deployment/application_source_set.py",
    "deployment/audit.py",
    "deployment/blob_verifier.py",
    "deployment/broker.py",
    "deployment/broker_service_config.py",
    "deployment/controller.py",
    "deployment/dev_host_provisioning_mechanics.py",
    "deployment/dev_host_qualification.py",
    "deployment/docker_runtime.py",
    "deployment/execution.py",
    "deployment/executor.py",
    "deployment/executor_listener.py",
    "deployment/executor_server.py",
    "deployment/executor_service_config.py",
    "deployment/executor_service_config_loader.py",
    "deployment/host_provisioning_contract.py",
    "deployment/host_service_layout.py",
    "deployment/identity.py",
    "deployment/installation_contract.py",
    "deployment/installation_integrity_contract.py",
    "deployment/jwks.py",
    "deployment/oci_verifier.py",
    "deployment/oidc_verifier.py",
    "deployment/pip_installer_provenance.py",
    "deployment/pip_installer_qualification.py",
    "deployment/policy.py",
    "deployment/private_registry_fd.py",
    "deployment/private_registry_pull.py",
    "deployment/promotion.py",
    "deployment/python_environment_qualification.py",
    "deployment/python_interpreter_provenance.py",
    "deployment/registry_oidc_credentials.py",
    "deployment/release_consumer.py",
    "deployment/replay_sqlite.py",
    "deployment/rootless_docker_authority.py",
    "deployment/saas_product_contract.py",
    "deployment/saas_product_runtime.py",
    "deployment/sigstore_authority_provenance.py",
    "deployment/state.py",
    "deployment/state_store.py",
    "deployment/unix_transport.py",
    "deployment/wheelhouse_qualification.py",
    "release/__init__.py",
    "release/analytics_owner_source_selection.py",
})

ERROR = "M05_ORDINARY_CFC_SOURCE_STAGE_HOLD"


# Section 2: accept root-owned old source only under closed, immutable ancestry.
def trusted_root_file(path: Path, mode: int | None) -> bytes:
    """Read a stable root:root single-link regular file, rejecting symlinks."""
    current = Path("/")
    for name in path.parts[1:-1]:
        current /= name
        item = current.lstat()
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022:
            raise ValueError("untrusted root-owned directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or before.st_uid != 0 or before.st_gid != 0
                or before.st_nlink != 1
                or (
                    mode is not None and stat.S_IMODE(before.st_mode) != mode
                )
                or (
                    mode is None and stat.S_IMODE(before.st_mode) & 0o022
                )
                or not 0 < before.st_size <= 1048576):
            raise ValueError("untrusted root-owned source file")
        data = bytearray()
        while len(data) <= 1048576:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (len(data) != before.st_size or len(data) > 1048576
                or any(getattr(before, key) != getattr(after, key) for key in fields)):
            raise ValueError("unstable root-owned file")
        return bytes(data)
    finally:
        os.close(fd)


# Section 3: user handoff files are untrusted until exact hash-verified.
def user_handoff_file(path: Path, expected_sha: str, limit: int) -> bytes:
    """Bind restricted UID1005 input to a reviewed immutable SHA256."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode)
                or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode), before.st_nlink)
                != (1005, 1005, 0o400, 1)
                or not 0 < before.st_size <= limit):
            raise ValueError("untrusted handoff file")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (len(data) != before.st_size or len(data) > limit
                or any(getattr(before, key) != getattr(after, key) for key in fields)
                or hashlib.sha256(data).hexdigest() != expected_sha):
            raise ValueError("handoff SHA256/metadata mismatch")
        return bytes(data)
    finally:
        os.close(fd)


# Section 4: exact 76-file audited root baseline; TWO reviewed replacements.
def reviewed_source() -> tuple[object, tuple[tuple[str, bytes], ...]]:
    """Check every old root-owned file and new source hash without executing it."""
    from collections import Counter

    raw = user_handoff_file(MANIFEST, MANIFEST_SHA, 16384)
    manifest = json.loads(raw)
    if (type(manifest) is not dict
            or set(manifest) != {"baseline_commit", "target_commit",
                                "baseline_files_sha256",
                                "replacement_sha256", "root_directories"}
            or manifest["baseline_commit"] != BASE
            or manifest["target_commit"] != COMMIT
            or manifest["replacement_sha256"] != REPLACEMENTS_SHA
            or type(manifest["baseline_files_sha256"]) is not dict
            or len(manifest["baseline_files_sha256"]) != 76
            or type(manifest["root_directories"]) is not list
            or len(manifest["root_directories"]) != 9):
        raise ValueError("unreviewed source inventory")
    # Exactly TWO reviewed previous-commit module replacements, no arbitrary paths.
    replacements = {
        path: user_handoff_file(
            HANDOFF / "payload" / path, digest, 1048576,
        )
        for path, digest in sorted(REPLACEMENTS_SHA.items())
    }
    oldstat = ROOT.lstat()
    if (not stat.S_ISDIR(oldstat.st_mode)
            or (oldstat.st_uid, oldstat.st_gid, stat.S_IMODE(oldstat.st_mode))
            != (0, 0, 0o755)):
        raise ValueError("untrusted installed baseline")
    actual_dirs, actual_files = [], []
    for current, dirs, files in os.walk(ROOT, followlinks=False):
        for name in dirs:
            path = Path(current, name)
            meta = path.lstat()
            if (not stat.S_ISDIR(meta.st_mode)
                    or (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode))
                    != (0, 0, 0o755)):
                raise ValueError("unexpected source directory")
            actual_dirs.append(str(path.relative_to(ROOT)))
        for name in files:
            actual_files.append(str(Path(current, name).relative_to(ROOT)))
    mapping = manifest["baseline_files_sha256"]
    if not set(REPLACEMENTS_SHA).issubset(set(mapping)):
        raise ValueError("unreviewed source replacement path")
    if (sorted(actual_dirs) != manifest["root_directories"]
            or sorted(actual_files) != sorted(mapping)):
        raise ValueError("source file/directory count or identity changed")
    combined = []
    for relative, expected in sorted(mapping.items()):
        if (type(relative) is not str or relative.startswith("/")
                or any(part in ("", ".", "..") for part in relative.split("/"))
                or type(expected) is not str
                or len(expected) != 64
                or any(char not in "0123456789abcdef" for char in expected)):
            raise ValueError("invalid reviewed source member")
        old = trusted_root_file(ROOT / relative, 0o644)
        if hashlib.sha256(old).hexdigest() != expected:
            raise ValueError("baseline source mutated")
        combined.append((relative, replacements.get(relative, old)))

    # The source installer is not in the 76-file application runtime.
    # Owner-root SHA256 evidence binds this exact pre-existing private
    # importer. Checking only root ownership would execute changed code
    # with root privileges if a prior installer was silently replaced.
    importer_bytes = trusted_root_file(INSTALLER, 0o400)
    if hashlib.sha256(importer_bytes).hexdigest() != INSTALLER_SHA:
        raise ValueError("root-only source installer SHA is not approved")
    # A previously imported deployment package could shadow the pinned
    # SCRATCH modules even after sys.path insertion. Deny instead of
    # borrowing an unverified module from an unrelated Python environment.
    if any(k in ("deployment", "release") or k.startswith(("deployment.", "release."))
           for k in sys.modules):
        raise ValueError("deployment Python modules already loaded")
    # Verify a split-origin import closure BEFORE executing privileged code:
    # 45 historical runtime modules come from the already SHA-qualified
    # immutable ROOT (330f), NOT the unqualified historical SCRATCH copies.
    # The 16 installer-only modules absent from ROOT are supplied by the
    # SHA-pinned SCRATCH files and verified against the reviewed Git source.
    if (
        len(REQUIRED_IMPORT_SOURCE_PATHS) != 61
        or len(EXTRA_IMPORT_SOURCE_SHA) != 16
        or set(EXTRA_IMPORT_SOURCE_SHA) != REQUIRED_IMPORT_SOURCE_PATHS - set(mapping)
        or EXTRA_IMPORT_SOURCE_SHA.get("deployment/analytics_isolated_source_install.py") != INSTALLER_SHA
    ):
        raise ValueError("unreviewed root importer source closure")
    for relative in sorted(REQUIRED_IMPORT_SOURCE_PATHS):
        if relative in mapping:
            # The installed 330f runtime is byte-checked and root-owned.
            origin, expected, mode = ROOT / relative, mapping[relative], 0o644
        else:
            origin = SCRATCH / relative
            expected = EXTRA_IMPORT_SOURCE_SHA[relative]
            mode = 0o400 if relative == "deployment/analytics_isolated_source_install.py" else None
        source_bytes = trusted_root_file(origin, mode)
        if hashlib.sha256(source_bytes).hexdigest() != expected:
            raise ValueError("root importer dependency SHA is not approved")
    # Import deployment itself from immutable ROOT. Extend its package search
    # path only for the pinned installer-only modules not present in ROOT.
    # The package objects below are verified before any private importer runs.
    sys.path.insert(0, str(ROOT))
    sys.path.insert(1, str(SCRATCH))
    sys.dont_write_bytecode = True
    # Do not read any unqualified __pycache__ or legacy .pyc from either
    # source tree. This impossible cache directory forces source loading.
    sys.pycache_prefix = "/dev/null/omnilyzer-m05-no-bytecode-cache"
    import deployment
    if (not isinstance(getattr(deployment, "__file__", None), str)
            or os.path.abspath(deployment.__file__) != str(ROOT / "deployment/__init__.py")):
        raise ValueError("deployment package import origin changed")
    deployment.__path__ = [str(ROOT / "deployment"), str(SCRATCH / "deployment")]
    import release
    if (not isinstance(getattr(release, "__file__", None), str)
            or os.path.abspath(release.__file__) != str(SCRATCH / "release/__init__.py")):
        raise ValueError("release package import origin changed")
    release.__path__ = [str(ROOT / "release"), str(SCRATCH / "release")]
    from deployment import analytics_isolated_source_install as installer
    if (not isinstance(getattr(installer, "__file__", None), str)
            or os.path.abspath(installer.__file__) != str(INSTALLER)):
        raise ValueError("pinned root source installer import origin changed")
    if len(combined) != 76:
        raise ValueError("invalid successor file count")
    return installer, tuple(combined)


# Section 5: publish one SHA-named source only if absent. No live service touch.
def stage_once(installer: object, combined: tuple[tuple[str, bytes], ...]) -> None:
    """Use the original restricted stage+atomic-rename logic unchanged."""
    opened: list[int] = []
    try:
        fd = installer._open_checked_root(str(PARENT), opened, 0, 0)
        for name in (DEST.name, installer._STAGING):
            try:
                os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("source stage destination already exists")
        installer._stage_new_generation(fd, combined, uid=0, gid=0, successor_source=True)
        try:
            os.rename(installer._STAGING, DEST.name, src_dir_fd=fd, dst_dir_fd=fd)
        except OSError:
            installer._remove_verified_stage(fd, combined, uid=0, gid=0)
            raise
        os.fsync(fd)
    finally:
        installer._original._finish_close(opened)


# Section 6: fixed root-only --check or --stage. Fail closed without traceback.
def main(argv: list[str]) -> None:
    """Require exact operator filename root:root mode0500 and unused dest."""
    if argv not in (["--check"], ["--stage"]):
        raise ValueError("invalid operation")
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
        raise PermissionError("only root may stage")
    if Path(__file__) != OPERATOR:
        raise PermissionError("untrusted installed operator path")
    trusted_root_file(OPERATOR, 0o500)
    if DEST.exists() or DEST.is_symlink():
        raise ValueError("source already staged")
    installer, combined = reviewed_source()
    if argv == ["--check"]:
        print("M05_CFC_ROOT_SOURCE_PREFLIGHT_PASS", COMMIT, len(combined))
        return
    stage_once(installer, combined)
    print("M05_CFC_ROOT_SOURCE_STAGED", COMMIT)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception:
        print(ERROR, file=sys.stderr)
        raise SystemExit(1)
