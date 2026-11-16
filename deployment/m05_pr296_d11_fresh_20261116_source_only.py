#!/usr/bin/env python3
"""File: deployment/m05_pr296_d11_fresh_20261116_source_only.py

Purpose: Fresh once-only Analytics Task014 source-only recovery after
         consumed old PR296 installers, using the signed release 0.16 path.
         It revalidates the installed 766e state without rerunning the
         previously consumed original 766e root-readonly OAT operator.
Related: approved owner_rebind_766e_recovery.py (pinned older source installer),
         m05_296_source_delta_manifest.json (76 exact source SHA hashes),
         six exact M04-approved source blobs (PR #296), and GitHub Issue #281.

Sections: new exact 766e source/receipt attestation; approved 76-source
          assembly; fresh one-way source-only receipt and recovery backup;
          root-owned snapshot requirement; UID991/blue/route/replay postcheck.
SECURITY: SOURCE REVIEW CANDIDATE ONLY. NOT approved for root execution until
independent M04 install-boundary SOURCE/SECURITY PASS on exact bytes and SHA.
Do not retry any previous source-only command or signed Task014 run/JTI.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
from types import SimpleNamespace

REVIEW = Path("/home/trust/m05-pr296-source-install-review")
PRIOR = Path("/home/trust/m05-766e-recovery-source-review/owner_rebind_766e_recovery.py")
PRIOR_SIZE = 34643
PRIOR_SHA = "42416beba2f862d69d1d7471651c47273a211b97b6b781d07b7472d3fd2fdb64"
MANIFEST = REVIEW / "m05_296_source_delta_manifest.json"
MANIFEST_SIZE = 16574
MANIFEST_SHA = "989e87539847261cc5b0a955284947df724ec415cc9a0f14a2808bfb05e1224f"
OLD_MAIN = "766e4763f04b0d2dc57b3981374ddc29c6893183"
NEW_MAIN = "d11ce821715b3e1eca2689701065b0e3e2a19e50"
NEW_TREE = "9c8b902074359dd3c908fbea658fc21819f86ed3"
DELTA = (
    "deployment/analytics_broker_router.py",
    "deployment/analytics_executor.py",
    "deployment/analytics_promotion_broker.py",
    "deployment/analytics_registry_review_composition.py",
    "deployment/analytics_signed_release_consumer.py",
    "deployment/analytics_unix_boundary.py",
)
BASE = Path("/opt/omnilyzer/deployment")
CANDIDATE = BASE / "analytics-app-candidate"
STAGE = BASE / ".analytics-app-reviewed-staging"  # Original approved exact staging boundary.
BACKUP = BASE / ".m05-analytics016-d11-fresh-prior-766e"
RECEIPT = Path("/var/lib/omnilyzer/deployment/.m05-analytics016-d11-fresh-before")
MARKER = RECEIPT / "source-pr296-d11-fresh-installed-no-signed-dispatch"
MARKER_BYTES = b"M05_ANALYTICS016_D11_FRESH_SOURCE_ONLY_NO_SIGNED_DISPATCH\n"
# Previously consumed exact PR296 operator targets remain forbidden.
_OLD_PR296_BACKUP = BASE / ".m05-pr296-d11-prior-766e"
_OLD_PR296_RECEIPT = Path("/var/lib/omnilyzer/deployment/.m05-pr296-d11-source-before")
ROUTE = Path("/var/lib/omnilyzer/deployment/analytics-route")
BROKER = "omnilyzer-deployment-broker.service"
SOCKET = "omnilyzer-deployment-analytics-executor.socket"
EXECUTOR = "omnilyzer-deployment-analytics-executor.service"
BLUE = "omnilyzer-analytics-loopback.service"
CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)


class Hold(Exception):
    """Fixed, secret-free source/replay/authority rejection."""


def require(condition: bool, phase: str) -> None:
    """Reject any unexpected precondition without exposing protected bytes."""
    if condition is not True:
        raise Hold(phase)


def sha(raw: bytes) -> str:
    """Hash bounded exact source; never print the computed digest at root."""
    return hashlib.sha256(raw).hexdigest()


def unique(pairs: list[tuple[str, object]]) -> dict:
    """Fail closed on duplicate keys in all root-controlled JSON records."""
    result = {}
    for key, value in pairs:
        require(type(key) is str and key not in result, "DUPLICATE_JSON")
        result[key] = value
    return result


def canonical(model: dict) -> bytes:
    """Canonical ASCII one-record schema, preserving original root config."""
    return (json.dumps(model, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def original() -> SimpleNamespace:
    """Load prior independently approved root operator by frozen SHA only."""
    for directory in (REVIEW, PRIOR.parent):
        meta = os.lstat(directory)
        require(stat.S_ISDIR(meta.st_mode) and
                (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode))
                == (1001, 1001, 0o700), "REVIEW_CUSTODY")
    meta = os.lstat(PRIOR)
    require(stat.S_ISREG(meta.st_mode) and meta.st_size == PRIOR_SIZE,
            "PRIOR_SOURCE_SIZE")
    fd = os.open(PRIOR, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        named = os.stat(PRIOR, follow_symlinks=False)
        require((before.st_dev, before.st_ino) ==
                (named.st_dev, named.st_ino), "PRIOR_SOURCE_PATH")
        blocks = bytearray()
        while len(blocks) < PRIOR_SIZE:
            chunk = os.read(fd, min(65536, PRIOR_SIZE - len(blocks)))
            require(bool(chunk), "PRIOR_SOURCE_SHORT")
            blocks.extend(chunk)
        raw = bytes(blocks)
        after = os.fstat(fd)
        require(len(raw) == PRIOR_SIZE and sha(raw) == PRIOR_SHA
                and (before.st_uid, before.st_gid,
                     stat.S_IMODE(before.st_mode), before.st_nlink)
                    == (1001, 1001, 0o600, 1)
                and (before.st_dev, before.st_ino, before.st_size,
                     before.st_mtime_ns, before.st_ctime_ns)
                    == (after.st_dev, after.st_ino, after.st_size,
                        after.st_mtime_ns, after.st_ctime_ns),
                "PRIOR_SOURCE_PIN")
    finally:
        os.close(fd)
    ns = {"__name__": "m05_pr296_frozen_prior_operator", "__file__": str(PRIOR)}
    exec(compile(raw, str(PRIOR), "exec"), ns)
    prior = SimpleNamespace(**ns)
    require(prior.NEXT_COMMIT == OLD_MAIN and
            prior.NEXT_RECEIPT ==
                Path("/var/lib/omnilyzer/deployment/.m05-766e-post433-before")
            and prior.CANDIDATE == CANDIDATE and prior.STAGE == STAGE,
            "PRIOR_SOURCE_IDENTITY")
    return prior


def manifest(prior: SimpleNamespace) -> tuple[dict[str, str], dict[str, str]]:
    """Pin complete old and new 76-source identities to reviewed Git tree."""
    raw = prior.pinned(MANIFEST, 1001, 1001, 0o600,
                       MANIFEST_SIZE, MANIFEST_SHA)
    model = json.loads(raw, object_pairs_hook=unique)
    require(canonical(model) == raw and type(model) is dict and
            set(model) == {
                "schema_version", "source_repository", "previous_commit",
                "next_commit", "next_git_tree", "source_file_count",
                "changed_file_count", "previous_source_sha256",
                "next_source_sha256",
            } and model["schema_version"] == 1 and
            model["source_repository"] == "MichaelTrueX/omnilyzer-platform" and
            model["previous_commit"] == OLD_MAIN and
            model["next_commit"] == NEW_MAIN and
            model["next_git_tree"] == NEW_TREE and
            model["source_file_count"] == 76 and
            model["changed_file_count"] == 6, "MANIFEST_AUTHORITY")
    previous = model["previous_source_sha256"]
    target = model["next_source_sha256"]
    require(type(previous) is dict and type(target) is dict and
            len(previous) == len(target) == 76 and
            set(previous) == set(target) and
            {path for path in previous if previous[path] != target[path]}
                == set(DELTA), "MANIFEST_SIX_SOURCE_DELTA")
    for path, digest in target.items():
        require(type(path) is str and path.startswith(("deployment/", "release/"))
                and not any(part in ("", ".", "..") for part in path.split("/"))
                and type(digest) is str and len(digest) == 64
                and all(c in "0123456789abcdef" for c in digest)
                and type(previous[path]) is str and len(previous[path]) == 64,
                "MANIFEST_SOURCE_ENTRY")
    return previous, target


def verify_tree(root: Path, expected: dict[str, str]) -> None:
    """Verify all 76 root-owned files, directories, permissions and SHA."""
    require(root in (CANDIDATE, STAGE, BACKUP) and len(expected) == 76,
            "SOURCE_ROOT_SCOPE")
    found = set()
    for dirname, dirs, files in os.walk(root, followlinks=False):
        folder = Path(dirname)
        meta = os.lstat(folder)
        require(stat.S_ISDIR(meta.st_mode) and
                (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode))
                == (0, 0, 0o755), "SOURCE_DIRECTORY")
        for name in dirs:
            md = os.lstat(folder / name)
            require(stat.S_ISDIR(md.st_mode) and
                    (md.st_uid, md.st_gid, stat.S_IMODE(md.st_mode))
                    == (0, 0, 0o755), "SOURCE_CHILD_DIRECTORY")
        for name in files:
            path = folder / name
            rel = path.relative_to(root).as_posix()
            require(rel in expected and rel not in found, "SOURCE_EXTRA")
            md = os.lstat(path)
            require(stat.S_ISREG(md.st_mode) and md.st_nlink == 1 and
                    (md.st_uid, md.st_gid, stat.S_IMODE(md.st_mode))
                    == (0, 0, 0o644) and 0 < md.st_size <= 1024 * 1024,
                    "SOURCE_METADATA")
            # Preserve the source-consumption security of the reviewed helper.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                start = os.fstat(fd)
                raw = bytearray()
                while len(raw) < start.st_size:
                    piece = os.read(fd, min(65536, start.st_size - len(raw)))
                    require(bool(piece), "SOURCE_SHORT")
                    raw.extend(piece)
                end = os.fstat(fd)
                require(sha(raw) == expected[rel] and
                        (start.st_dev, start.st_ino, start.st_size,
                         start.st_ctime_ns, start.st_mtime_ns)
                        == (end.st_dev, end.st_ino, end.st_size,
                            end.st_ctime_ns, end.st_mtime_ns),
                        "SOURCE_CHANGED")
            finally:
                os.close(fd)
            found.add(rel)
    require(found == set(expected), "SOURCE_SET")


def updated_configs(prior: SimpleNamespace, helper: object,
                    before: dict, old: dict[str, str],
                    target: dict[str, str]) -> dict:
    """Change only reviewed generation/workflow and six source hash pins."""
    require(set(before) == {path for path, _ in prior.CONFIG_PATHS}
            and before[prior.CONFIG_PATHS[1][0]] ==
                before[prior.CONFIG_PATHS[2][0]],
            "CONFIG_SET")
    issuer = json.loads(before[prior.CONFIG_PATHS[0][0]],
                        object_pairs_hook=unique)
    model = json.loads(before[prior.CONFIG_PATHS[1][0]],
                       object_pairs_hook=unique)
    require(canonical(issuer) == before[prior.CONFIG_PATHS[0][0]]
            and canonical(model) == before[prior.CONFIG_PATHS[1][0]]
            and issuer["expected_workflow_sha"] == OLD_MAIN
            and model["expected_workflow_sha"] == OLD_MAIN
            and model["reviewed_installed_commit"] == OLD_MAIN
            and model["schema_version"] == 3
            and model["owner_authorized_first_successor"] is True
            and type(model["source_sha256"]) is dict
            and len(model["source_sha256"]) == 26
            and set(DELTA) <= set(model["source_sha256"]),
            "PRIOR_CONFIG")
    for name in DELTA:
        require(model["source_sha256"][name] == old[name],
                "PRIOR_SOURCE_PIN")
    next_model = dict(model)
    next_model["source_sha256"] = dict(model["source_sha256"])
    for name in DELTA:
        next_model["source_sha256"][name] = target[name]
    next_model["reviewed_installed_commit"] = NEW_MAIN
    next_model["expected_workflow_sha"] = NEW_MAIN
    wanted = {
        prior.CONFIG_PATHS[0][0]:
            canonical(dict(issuer, expected_workflow_sha=NEW_MAIN)),
        prior.CONFIG_PATHS[1][0]: canonical(next_model),
        prior.CONFIG_PATHS[2][0]: canonical(next_model),
    }
    require(all(0 < len(wanted[path]) <= 4096 and wanted[path] != before[path]
                for path, _ in prior.CONFIG_PATHS),
            "NEW_CONFIG_SCOPE")
    return wanted


def uid991_source_preflight() -> None:
    """Run reviewed actual UID991 loader and signed blue readback, no deploy."""
    code = (
        "import sys;"
        "sys.path.insert(0,'/opt/omnilyzer/deployment/analytics-app-candidate');"
        "from deployment.analytics_executor_service_config import "
        "load_analytics_executor_service_config;"
        "from deployment.analytics_active_state_review import "
        "inspect_analytics_active_state,verify_empty_analytics_successor_slot;"
        "from deployment.analytics_signed_release_consumer import PINNED_DIGEST,PINNED_IMAGE;"
        "source,ids=load_analytics_executor_service_config(require_successor=True);"
        "state=inspect_analytics_active_state();"
        "verify_empty_analytics_successor_slot();"
        f"assert source['reviewed_installed_commit']=='{NEW_MAIN}';"
        f"assert ids['expected_workflow_sha']=='{NEW_MAIN}';"
        "assert ids['owner_authorized_first_successor'] is True;"
        "assert ids['expected_executor_uid']==991 and ids['expected_executor_gid']==991;"
        "assert state.active_slot=='blue' and state.active_digest==PINNED_DIGEST;"
        "assert state.active_image==PINNED_IMAGE and state.candidate_probe_present is False;"
        "print('M05_016_FRESH_UID991_SOURCE_BLUE_PASS')"
    )
    result = subprocess.run([
        "/usr/bin/setpriv", "--reuid", "991", "--regid", "991",
        "--groups", "992", "--no-new-privs",
        "/opt/omnilyzer/deployment/venv/bin/python",
        "-I", "-B", "-c", code,
    ], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
       stderr=subprocess.DEVNULL, timeout=45, cwd=str(CANDIDATE),
       env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1", "HOME": "/nonexistent"},
       check=False)
    require(result.returncode == 0 and
            result.stdout == b"M05_016_FRESH_UID991_SOURCE_BLUE_PASS\n",
            "UID991_SOURCE")


def attest_prior_766_readonly(prior: SimpleNamespace) -> None:
    """Revalidate all 766e source, receipts, seals, configs and UID991.

    This is a NEW read-only attestation for the fresh source-only operation.
    It uses frozen first-party read-only primitives but NEVER calls the
    previously consumed prior.post_install_readonly() composite or one-shot
    operator. Failure occurs before any new receipt, stage or service action.
    """
    prior.root_environment()
    require(not os.path.lexists(prior.STAGE), "PRIOR_STAGE_OCCUPIED")
    previous, _oat, diagnostic = prior.approved_helpers()
    manifest = prior.reviewed_manifest()
    helper = previous.original()
    folder = os.lstat(prior.NEXT_RECEIPT)
    require(stat.S_ISDIR(folder.st_mode)
            and (folder.st_uid, folder.st_gid, stat.S_IMODE(folder.st_mode))
            == (0, 0, 0o700), "PRIOR_RECEIPT_DIRECTORY")
    receipt = prior.NEXT_RECEIPT / "receipt.json"
    meta = os.lstat(receipt)
    raw = prior.pinned(receipt, 0, 0, 0o600, meta.st_size,
                       prior.sha(prior._bounded_read_only(receipt, 4096)))
    model = json.loads(raw, object_pairs_hook=unique)
    require(raw == prior.canonical(model)
            and set(model) == {
                "schema_version", "previous_installed_commit",
                "next_installed_commit", "previous_oneway_seal",
                "consumed_failed_task014_run", "historical_failed_runs_nonreplayable",
                "source_manifest_sha256", "previous_executor_sha256",
                "next_executor_sha256", "source_only", "new_task014_dispatched",
                "replay_sha256_before", "prior_root_source_backup",
            }
            and model["schema_version"] == 1
            and model["previous_installed_commit"] == prior.PREVIOUS_COMMIT
            and model["next_installed_commit"] == OLD_MAIN
            and model["previous_oneway_seal"] ==
                str(prior.PREVIOUS_RECEIPT / "promotion-armed")
            and model["consumed_failed_task014_run"] == 43387587420
            and model["historical_failed_runs_nonreplayable"] is True
            and model["source_manifest_sha256"] == prior.MANIFEST_SHA
            and model["previous_executor_sha256"] == prior.PREVIOUS_EXECUTOR_SHA
            and model["next_executor_sha256"] == prior.NEXT_EXECUTOR_SHA
            and model["source_only"] is True
            and model["new_task014_dispatched"] is False
            and model["prior_root_source_backup"] == str(prior.NEXT_BACKUP)
            and type(model["replay_sha256_before"]) is str
            and len(model["replay_sha256_before"]) == 64,
            "PRIOR_SIGNED_NONREPLAY_RECEIPT")
    original = {}
    for index, (path, _gid) in enumerate(prior.CONFIG_PATHS, 1):
        preimage = prior.NEXT_RECEIPT / f"config_{index:02d}.before"
        meta = os.lstat(preimage)
        original[path] = prior.pinned(
            preimage, 0, 0, 0o600, meta.st_size,
            prior.sha(prior._bounded_read_only(preimage, 4096)),
        )
    expected = prior.next_configs(
        original,
        json.loads(original[prior.CONFIG_PATHS[1][0]],
                   object_pairs_hook=unique),
    )
    for path, gid in prior.CONFIG_PATHS:
        require(helper.read_config(path, gid) == expected[path],
                "PRIOR_CONFIG_IDENTITY")
    prior.pinned(
        prior.NEXT_RECEIPT / prior.NEXT_MARKER_FILE,
        0, 0, 0o600, len(prior.NEXT_MARKER_BYTES),
        prior.sha(prior.NEXT_MARKER_BYTES),
    )
    prior.pinned(
        prior.PREVIOUS_RECEIPT / "promotion-armed",
        0, 0, 0o600, len(diagnostic["SEAL_BYTES"]),
        prior.sha(diagnostic["SEAL_BYTES"]),
    )
    prior.pinned(
        prior.PREVIOUS_RECEIPT / "source-installed-after-consumed-43138291400",
        0, 0, 0o600, len(previous.NEW_MARKER),
        prior.sha(previous.NEW_MARKER),
    )
    wanted = dict(manifest)
    wanted[prior.REL_EXECUTOR] = prior.NEXT_EXECUTOR_SHA
    prior.source_tree(CANDIDATE, wanted)
    prior.source_tree(prior.NEXT_BACKUP, manifest)
    # Fresh, read-only installed UID991 predicate. Not a repeat of the
    # consumed root OAT command or the owner one-time fixed-output classifier.
    prior.uid991_next_source()
    require(helper.service_state(BROKER) == "active"
            and helper.service_state(SOCKET) == "active"
            and helper.service_state(EXECUTOR) == "failed"
            and helper.service_state(BLUE) == "active",
            "PRIOR_SERVICE_STATE")
    helper.healthy()
    diagnostic["active_state_stable"]()
    require(prior.replay_snapshot(diagnostic) == model["replay_sha256_before"]
            and not any(ROUTE.iterdir()),
            "PRIOR_REPLAY_AND_ROUTE_STABLE")


def _require_root_snapshot() -> None:
    """Permit root execution only from an exact private root-owned copy."""
    file = Path(__file__)
    parent = file.parent
    require(
        str(parent).startswith("/run/m05-analytics016-d11-fresh-launch.")
        and not file.is_symlink() and not parent.is_symlink(),
        "ROOT_SNAPSHOT_PATH",
    )
    p = os.lstat(parent)
    f = os.lstat(file)
    require(
        stat.S_ISDIR(p.st_mode) and p.st_uid == p.st_gid == 0
        and stat.S_IMODE(p.st_mode) == 0o700
        and stat.S_ISREG(f.st_mode) and f.st_uid == f.st_gid == 0
        and stat.S_IMODE(f.st_mode) == 0o400 and f.st_nlink == 1,
        "ROOT_SNAPSHOT_CUSTODY",
    )


def root_preflight() -> tuple:
    """Verify previous sealed 766e installation and all next reviewed bytes."""
    require((os.getuid(), os.geteuid(), os.getgid(), os.getegid()) ==
            (0, 0, 0, 0) and socket.gethostname() == "omnilyzerdev",
            "ROOT_HOST")
    os.umask(0o077)
    require(not any(os.path.lexists(p) for p in (
        RECEIPT, BACKUP, STAGE, _OLD_PR296_BACKUP, _OLD_PR296_RECEIPT,
    )), "FRESH_ATTEMPT_NO_PREVIOUS_STAGE_OR_RECEIPT")
    fs = os.statvfs(str(BASE))
    require(fs.f_bavail * fs.f_frsize >= 8 * 1024 * 1024
            and fs.f_favail >= 300, "FREE_CAPACITY")
    prior = original()
    old, target = manifest(prior)
    # The already reviewed original OAT is reused, not replaced by our code.
    # It can HOLD if a previous replay/UID991 state has drifted after #436.
    try:
        attest_prior_766_readonly(prior)
    except CONTROL:
        raise
    except Exception:
        raise Hold("PRIOR_766_FRESH_READONLY_ATTESTATION") from None
    verify_tree(CANDIDATE, old)
    try:
        previous, _oat, diagnostic = prior.approved_helpers()
    except CONTROL:
        raise
    except Exception:
        raise Hold("PRIOR_HELPER_SOURCES") from None
    previous_helper = previous.original()
    config = {path: previous_helper.read_config(path, gid)
              for path, gid in prior.CONFIG_PATHS}
    target_config = updated_configs(prior, previous_helper, config, old, target)
    require(previous_helper.service_state(BROKER) == "active" and
            previous_helper.service_state(SOCKET) == "active" and
            previous_helper.service_state(EXECUTOR) == "failed" and
            previous_helper.service_state(BLUE) == "active", "PRIOR_SERVICES")
    replay = prior.replay_snapshot(diagnostic)
    require(not any(ROUTE.iterdir()), "ROUTE_NONEMPTY")
    bytes_by_path = {}
    for name in DELTA:
        rel = name.removeprefix("deployment/")
        file = REVIEW / rel
        meta = os.lstat(file)
        require(stat.S_ISREG(meta.st_mode) and
                0 < meta.st_size <= 1024 * 1024 and
                meta.st_uid == 1001 and meta.st_gid == 1001 and
                stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1,
                "SOURCE_DELTA_METADATA")
        bytes_by_path[name] = prior.pinned(
            file, 1001, 1001, 0o600, meta.st_size, target[name],
        )
    return (prior, previous, diagnostic, previous_helper,
            old, target, config, target_config, replay, bytes_by_path)


def receipt_model(prior: SimpleNamespace, replay: str) -> dict:
    """Give the protected write and post-readback one exact identity contract."""
    return {
        "schema_version": 1, "previous_commit": OLD_MAIN,
        "next_commit": NEW_MAIN, "source_manifest_sha256": MANIFEST_SHA,
        "previous_receipt": str(prior.NEXT_RECEIPT),
        "last_consumed_signed_run": 43686555264,
        "signed_run_not_replayed": True, "new_signed_dispatch": False,
        "previous_source_backup": str(BACKUP),
        "old_source_file_count": 76, "new_source_file_count": 76,
        "changed_source_count": 6, "replay_sha256_before": replay,
    }


def postcheck(prior: SimpleNamespace, previous: object, diagnostic: dict,
              helper: object, old: dict, target: dict,
              configs: dict, wanted: dict, replay: str) -> None:
    """Verify durable new receipt, root source trees, UID991 and 0.15 rollback."""
    require(not os.path.lexists(STAGE), "POST_STAGE_PRESENT")
    for path, gid in prior.CONFIG_PATHS:
        require(helper.read_config(path, gid) == wanted[path],
                "POST_CONFIG")
    verify_tree(CANDIDATE, target)
    verify_tree(BACKUP, old)
    expected_receipts = {
        "receipt.json": canonical(receipt_model(prior, replay)),
        **{f"config_{i:02d}.before": configs[path]
           for i, (path, _gid) in enumerate(prior.CONFIG_PATHS, 1)},
    }
    for name, expected_bytes in expected_receipts.items():
        path = RECEIPT / name
        prior.pinned(path, 0, 0, 0o600,
                     len(expected_bytes), sha(expected_bytes))
    marker = MARKER
    prior.pinned(marker, 0, 0, 0o600, len(MARKER_BYTES), sha(MARKER_BYTES))
    uid991_source_preflight()
    require(helper.service_state(BROKER) == "active" and
            helper.service_state(SOCKET) == "active" and
            helper.service_state(EXECUTOR) == "failed" and
            helper.service_state(BLUE) == "active", "POST_SERVICES")
    helper.healthy()
    diagnostic["active_state_stable"]()
    require(prior.replay_snapshot(diagnostic) == replay
            and not any(ROUTE.iterdir()), "POST_REPLAY_ROUTE")
    print("M05_016_FRESH_SOURCE_ONLY_POST_OAT_PASS_NO_NEW_DISPATCH", flush=True)


def apply_once() -> None:
    """One protected source generation exchange, never a signed promotion."""
    (prior, previous, diagnostic, helper,
     old, target, configs, wanted, replay, replacements) = root_preflight()
    print("M05_016_FRESH_PINNED_ROOT_PREFLIGHT_PASS", flush=True)
    original_manifest = prior.reviewed_manifest()
    old_executor = prior.pinned(
        prior.NEXT_EXECUTOR_FILE, 1001, 1001, 0o600,
        prior.NEXT_EXECUTOR_SIZE, prior.NEXT_EXECUTOR_SHA,
    )
    # Section: reconstruct CURRENT 766e generation, not PREVIOUS 2b0.
    # The old assembled_sources() requires the 2b0 executor in the live
    # tree; this is false after 766e was installed. Reuse the unchanged,
    # already-reviewed predecessor's exact original source composition
    # with approved 766e executor bytes instead. Bind both historical
    # manifests and the complete 76-member result before any root write.
    require(
        len(original_manifest) == 76
        and set(original_manifest) == set(old)
        and original_manifest["deployment/analytics_executor.py"]
            == prior.PREVIOUS_EXECUTOR_SHA
        and all(original_manifest[name] == old[name]
                for name in old if name != "deployment/analytics_executor.py"),
        "FROZEN_2B_TO_766_SOURCE_BINDING",
    )
    try:
        installer, temporary, _original_494, previous_bytes = (
            previous.selected_sources(helper, old_executor)
        )
    except CONTROL:
        raise
    except Exception:
        raise Hold("ORIGINAL_494_SOURCE_COMPOSITION") from None
    try:
        require(len(previous_bytes) == 76 and
                {name: sha(raw) for name, raw in previous_bytes} == old,
                "RECONSTRUCTED_OLD_SOURCE")
        updated = tuple((name, replacements.get(name, raw))
                        for name, raw in previous_bytes)
        require({name: sha(raw) for name, raw in updated} == target,
                "RECONSTRUCTED_NEW_SOURCE")
        holder = []
        try:
            base_fd = installer._open_checked_root(str(BASE), holder, 0, 0)
            installer._stage_new_generation(
                base_fd, updated, uid=0, gid=0, successor_source=True,
            )
        finally:
            installer._original._finish_close(holder)
        verify_tree(STAGE, target)
        print("M05_016_FRESH_NEW_STAGED_76_SOURCES_PASS", flush=True)

        RECEIPT.mkdir(mode=0o700)
        meta = os.lstat(RECEIPT)
        require(stat.S_ISDIR(meta.st_mode) and
                (meta.st_uid, meta.st_gid, stat.S_IMODE(meta.st_mode))
                == (0, 0, 0o700), "RECEIPT_CUSTODY")
        for i, (path, _gid) in enumerate(prior.CONFIG_PATHS, 1):
            helper.write_durable(
                RECEIPT / f"config_{i:02d}.before", configs[path],
                0, 0, 0o600,
            )
        helper.write_durable(
            RECEIPT / "receipt.json",
            canonical(receipt_model(prior, replay)), 0, 0, 0o600,
        )
        helper.fsync_directory(RECEIPT)
        helper.fsync_directory(RECEIPT.parent)
        attempted = False
        try:
            helper.service_action("stop", BROKER)
            helper.service_action("stop", SOCKET)
            prior.admission_closed(helper, diagnostic, replay)
            verify_tree(CANDIDATE, old)
            require(all(helper.read_config(path, gid) == configs[path]
                        for path, gid in prior.CONFIG_PATHS),
                    "PRE_SWITCH_CONFIG")
            prior.admission_closed(helper, diagnostic, replay)
            helper.exchange_directory(CANDIDATE, STAGE)
            require(not os.path.lexists(BACKUP), "BACKUP_EXISTS")
            os.rename(STAGE, BACKUP)
            helper.fsync_directory(BASE)
            verify_tree(CANDIDATE, target)
            verify_tree(BACKUP, old)
            prior.admission_closed(helper, diagnostic, replay)
            for path, gid in prior.CONFIG_PATHS:
                require(helper.read_config(path, gid) == configs[path],
                        "CONFIG_DRIFT")
                helper.atomic_config(path, wanted[path], gid)
                require(helper.read_config(path, gid) == wanted[path],
                        "CONFIG_READBACK")
                prior.admission_closed(helper, diagnostic, replay)
            uid991_source_preflight()
            prior.admission_closed(helper, diagnostic, replay)
            attempted = True
            helper.write_durable(MARKER, MARKER_BYTES, 0, 0, 0o600)
            helper.fsync_directory(RECEIPT)
            helper.service_action("start", SOCKET)
            helper.service_action("start", BROKER)
            postcheck(prior, previous, diagnostic, helper, old, target,
                      configs, wanted, replay)
        except CONTROL:
            raise
        except Exception:
            print(
                "M05_016_FRESH_PROTECTED_HOLD_AFTER_SOURCE_EXCHANGE_NO_RETRY"
                if attempted else "M05_016_FRESH_PROTECTED_HOLD_MANUAL_RECOVERY",
                flush=True,
            )
            raise
    finally:
        if str(temporary) in sys.path:
            sys.path.remove(str(temporary))
        shutil.rmtree(temporary)
    print("M05_016_FRESH_SOURCE_ONLY_INSTALLED_NOT_ANALYTICS_0_16_RELEASED_PASS",
          flush=True)


def main() -> int:
    """Require exact root-only one-way command; report fixed hold only."""
    try:
        require(sys.argv == [
            str(Path(__file__)), "--apply-approved-analytics016-d11-fresh-once",
        ], "OPERATION_MODE")
        _require_root_snapshot()
        apply_once()
        return 0
    except CONTROL:
        raise
    except Hold as exc:
        require(type(str(exc)) is str and len(str(exc)) < 100,
                "INTERNAL_HOLD_NAME")
        print("M05_016_FRESH_HOLD_AT_" + str(exc), flush=True)
    except Exception:
        print("M05_016_FRESH_HOLD_UNCLASSIFIED_NO_RETRY", flush=True)
    print("M05_016_FRESH_HARD_HOLD_NO_AUTORETRY", flush=True)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

