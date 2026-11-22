"""One-time root-attested legacy0.16.0 OAT completion migration, DEV ONLY.

NOT an Analytics deployment tool: no registry, request, OIDC refresh, replay
insertion, Docker write, RootlessKit switch, service restart or PROD action.
--preflight is read-only. --apply writes ONE exclusive root:991 mode0440
completion certificate under the preexisting UID991 route journal, after
checking original source+OIDC completion had already been accepted by the
owner's immutable final root SHA receipt, the exact independent OAT four
receipts, existing replay states and the real live signed0.16.0 route.
An unexpected file or inconsistent state is permanent HOLD, not auto-retry.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import subprocess
import sys

# This source is imported by unprivileged unit tests, but is EXECUTED
# only after a root-only, immutable, real on-host installation. Never make
# Python -I import executable deployment code from a user-writable checkout.
_ROOT_INSTALL_BASE = Path("/opt/omnilyzer/deployment")
_OPERATOR = Path("/usr/local/libexec/omnilyzer-m05-legacy-0160-migration.py")
_HEX = frozenset("0123456789abcdef")


def _review_root_installed_operator_path(filename: str, reviewed_commit: str) -> Path:
    """Accept only a separately approved root operator and SHA-named source.

    The ordinary application archive contains exactly 26 privileged imports;
    this one-shot operator MUST NOT be installed inside that immutable tree.
    A native root actor explicitly supplies the exact source commit reviewed
    with the signed 38-object source archive and the operator's own SHA256.
    No HTTP/OCI/JTI/request value can choose a source or a destination.
    """
    try:
        if ((os.getuid(), os.geteuid(), os.getgid(), os.getegid())
                != (0, 0, 0, 0)
                or type(reviewed_commit) is not str
                or len(reviewed_commit) != 40
                or any(c not in _HEX for c in reviewed_commit)
                or reviewed_commit == "0" * 40):
            raise ValueError("not root or unreviewed SHA")
        script = Path(os.path.abspath(filename))
        if script != _OPERATOR:
            raise ValueError("unreviewed operator path")
        source = _ROOT_INSTALL_BASE / ("analytics-app-release-" + reviewed_commit)
        for item in (
            Path("/usr"), Path("/usr/local"), _OPERATOR.parent,
            Path("/opt"), Path("/opt/omnilyzer"), _ROOT_INSTALL_BASE,
            source, source / "deployment",
        ):
            st = os.lstat(item)
            if (not stat.S_ISDIR(st.st_mode)
                    or st.st_uid != 0 or st.st_gid != 0
                    or stat.S_IMODE(st.st_mode) != 0o755):
                raise ValueError("unreviewed root directory")
        st = os.lstat(script)
        if (not stat.S_ISREG(st.st_mode)
                or (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode),
                    st.st_nlink) != (0, 0, 0o500, 1)):
            raise ValueError("unreviewed root-only script")
        for name in ("analytics_route_journal.py", "policy.py"):
            imported = os.lstat(source / "deployment" / name)
            if (not stat.S_ISREG(imported.st_mode)
                    or (imported.st_uid, imported.st_gid,
                        stat.S_IMODE(imported.st_mode), imported.st_nlink)
                    != (0, 0, 0o644, 1)):
                raise ValueError("unreviewed root source module")
        return source
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        raise ValueError("root operator source is not trusted") from None


if __name__ == "__main__":
    # A trusted native root command MUST supply the exact reviewed commit;
    # no default, mutable branch, self-derived SHA or arbitrary file path.
    if (len(sys.argv) != 3 or sys.argv[1] not in ("--preflight", "--apply")):
        print("M05_LEGACY_ROOT_SOURCE_HOLD", flush=True)
        raise SystemExit(3)
    try:
        _reviewed_source_root = _review_root_installed_operator_path(
            __file__, sys.argv[2],
        )
    except ValueError:
        print("M05_LEGACY_ROOT_SOURCE_HOLD", flush=True)
        raise SystemExit(3)
else:
    # This import path exists only for pure unprivileged source QA tests.
    # The CLI checks root source ancestry BEFORE importing any package.
    _reviewed_source_root = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(_reviewed_source_root))

from deployment.analytics_route_journal import (
    LEGACY_REQUEST, LEGACY_RUN, LEGACY_FINAL_SHA, LEGACY_GREEN, LEGACY_IMAGE,
    LEGACY_SOURCE, LEGACY_PLATFORM_SOURCE,
    CERTIFICATE_NAME, verify_root_legacy_certificate,
)
from deployment.policy import canonical_bytes

_CONTROL = (KeyboardInterrupt, SystemExit, GeneratorExit)
_DEV = "omnilyzerdev"
_BASE = Path("/var/lib/omnilyzer/deployment")
_OAT = _BASE / ".m05-analytics016-43838827603-recovery-oat"
_FINAL = _BASE / ".m05-analytics016-final-release-43838827603.json"
_ROUTE = _BASE / "analytics-route"
_TRANSACTION = _ROUTE / "transaction.json"
_REPLAY = _BASE / "authority/replay.sqlite3"
_EXECUTIONS = _ROUTE / "executions"
_PYTHON = "/opt/omnilyzer/deployment/venv/bin/python"
_SOURCE = "/opt/omnilyzer/deployment/analytics-app-release-330f3255f0067b9ddbe30d50466830bd71a55a11"
_OAT_NAMES = frozenset({"before.json", "restored015.json", "returned016.json", "result.json"})
_EXPECTED_OLD_CONTAINER = "227318fc3e8f4a9e2c6b6a6a269f4a2de4052c785ac05014d77a30c93fc4fb47"


def _fail() -> None:
    raise ValueError("M05_LEGACY_ATTESTATION_HOLD")


def _check_directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode):
        _fail()


def _read_file(path: Path, *, uid: int, gid: int, mode: int, limit: int) -> bytes:
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1
            or not 0 < info.st_size <= limit):
        _fail()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev,opened.st_ino,opened.st_uid,opened.st_gid,opened.st_mode,
                opened.st_size,opened.st_nlink) != (
                info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,
                info.st_size,info.st_nlink):
            _fail()
        data = os.read(fd, limit + 1)
        # A read may update atime. Compare only immutable security-relevant
        # identity/metadata, and the exact bounded content length.
        def stable_identity(st):
            return (
                st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode,
                st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
            )
        if (len(data) != info.st_size
                or stable_identity(os.fstat(fd)) != stable_identity(opened)):
            _fail()
        return data
    finally:
        os.close(fd)


def _json(data: bytes) -> dict[str, object]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _fail()
            result[key] = value
        return result
    document = json.loads(data.decode("ascii"), object_pairs_hook=unique)
    if type(document) is not dict:
        _fail()
    return document


def _validate_historical_documents(
    before: dict[str, object], restored: dict[str, object],
    returned: dict[str, object], result: dict[str, object],
    current: dict[str, object],
) -> None:
    """Strict old OAT vs current route relationship; no authority returned."""
    first = before.get("route")
    if type(first) is not dict:
        _fail()
    initial = first.get("journal")
    old = restored.get("journal")
    new = returned.get("journal")
    if not all(type(value) is dict for value in (initial,old,new,current)):
        _fail()
    for record in (initial,old,new,current):
        if record.get("request_sha256") != LEGACY_REQUEST:
            _fail()
    # The original switch and restore must identify the exact same immutable
    # blue/green endpoints as the final returned intent, not merely its run ID.
    endpoints = (
        "previous_slot", "previous_image", "previous_container_id",
        "next_slot", "next_image", "next_container_id",
    )
    if any(record.get(key) != current.get(key)
           for record in (initial, old) for key in endpoints):
        _fail()
    if (initial.get("generation") != 1 or initial.get("phase") != "switched"
            or old.get("generation") != 1 or old.get("phase") != "restored"
            or new.get("generation") != 2 or new.get("phase") != "switched"
            or current != new or current.get("next_slot") != "green"
            or current.get("next_image") != LEGACY_IMAGE
            or current.get("next_container_id") != LEGACY_GREEN
            or current.get("previous_slot") != "blue"
            or current.get("previous_container_id") != _EXPECTED_OLD_CONTAINER
            or set(result) != {"pass","replay_unchanged","database_unchanged"}
            or any(type(result[key]) is not bool or result[key] is not True
                   for key in result)):
        _fail()


@contextmanager
def _held_replay_evidence():
    """Pin both replay statuses with a real SQLite DELETE-mode read lock.

    The existing replay guard writes with BEGIN IMMEDIATE. A read transaction
    in DELETE journal mode blocks a competing writer from COMMIT until the
    certificate is durably published. WAL/SHM and alternate journal modes are
    forbidden, never silently read using SQLite immutable=1.
    """
    if any(os.path.lexists(str(_REPLAY) + suffix) for suffix in ("-wal", "-shm")):
        _fail()
    conn = sqlite3.connect(_REPLAY.as_uri() + "?mode=ro",
                           uri=True, timeout=0, isolation_level=None)
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        if conn.execute("PRAGMA journal_mode").fetchone() != ("delete",):
            _fail()
        conn.execute("BEGIN")
        former = conn.execute(
            "SELECT status FROM consumptions "
            "WHERE github_run_id=? AND github_run_attempt=1",
            (LEGACY_RUN,),
        ).fetchmany(2)
        failed = conn.execute(
            "SELECT status FROM consumptions "
            "WHERE github_run_id=? AND github_run_attempt=1",
            (44890393889,),
        ).fetchmany(2)
        if former not in ([], [("finished",)]) or failed != [("consumed",)]:
            _fail()
        # Do not release this SHARED lock before _apply publishes the cert.
        yield "absent" if not former else "finished"
    finally:
        conn.close()


def _check_replay() -> str:
    """Read exact replay state in preflight, without changing any JTI."""
    with _held_replay_evidence() as former:
        return former


def _live_uid991_route(source: Path) -> None:
    """Require genuine UID991 inspected immutable OCI and private 3141 route."""
    script = f"""import sys
sys.path.insert(0,{str(source)!r})
from deployment.analytics_route_journal import AnalyticsRouteJournal
from deployment.analytics_active_state_review import inspect_committed_analytics_route
j=AnalyticsRouteJournal()
v=inspect_committed_analytics_route(
    journal=j,
    reviewed_image={LEGACY_IMAGE!r}, reviewed_slot='green',
    reviewed_container_id={LEGACY_GREEN!r},
    reviewed_request_sha256={LEGACY_REQUEST!r},
)
assert v.active_slot=='green'
assert v.active_image=={LEGACY_IMAGE!r}
assert v.active_container_id=={LEGACY_GREEN!r}
print('M05_LEGACY_UID991_ACTIVE_IMAGE_ROUTE_PASS')
"""
    proc=subprocess.run(
        ["/usr/bin/setpriv", "--reuid","991","--regid","991","--groups","992",
         "--no-new-privs", _PYTHON,"-I","-B","-c",script],
        env={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","HOME":"/nonexistent",
             "ANALYTICS_REVIEWED_SUPERVISOR_V2":"1"},
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=35,
        check=False,
    )
    if proc.returncode != 0 or proc.stdout.strip() != "M05_LEGACY_UID991_ACTIVE_IMAGE_ROUTE_PASS":
        _fail()


def _preflight() -> tuple[dict[str, object], bytes]:
    if (os.getuid(),os.geteuid(),os.getgid(),os.getegid()) != (0,0,0,0):
        _fail()
    if socket.gethostname().split(".")[0] != _DEV:
        _fail()
    if hashlib.sha256(_read_file(
        _FINAL, uid=0,gid=0,mode=0o600,limit=65536,
    )).hexdigest() != LEGACY_FINAL_SHA:
        _fail()
    _check_directory(_OAT,uid=0,gid=0,mode=0o700)
    if set(os.listdir(_OAT)) != _OAT_NAMES:
        _fail()
    originals={
        name:_read_file(_OAT / name,uid=0,gid=0,mode=0o600,limit=1024*1024)
        for name in _OAT_NAMES
    }
    documents={name:_json(body) for name,body in originals.items()}
    _check_directory(_ROUTE,uid=991,gid=991,mode=0o700)
    # Existing, partial, or symlinked evidence means the one-time minting
    # transaction has already been attempted. Never report a fresh preflight
    # as PASS in that state and never erase/overwrite it.
    if os.path.lexists(_EXECUTIONS / CERTIFICATE_NAME):
        _fail()
    current_bytes=_read_file(_TRANSACTION,uid=991,gid=991,mode=0o600,limit=2048)
    current=_json(current_bytes)
    _validate_historical_documents(
        documents["before.json"],documents["restored015.json"],
        documents["returned016.json"],documents["result.json"],current,
    )
    _check_replay()
    _live_uid991_route(_reviewed_source_root)
    document={
        "schema_version":1,
        "kind":"owner_root_attested_legacy_0160_oat",
        "original_run_id":LEGACY_RUN,
        "request_sha256":LEGACY_REQUEST,
        "current_journal_sha256":hashlib.sha256(canonical_bytes(current)).hexdigest(),
        "final_release_receipt_sha256":LEGACY_FINAL_SHA,
        "oat_before_sha256":hashlib.sha256(originals["before.json"]).hexdigest(),
        "oat_restored_sha256":hashlib.sha256(originals["restored015.json"]).hexdigest(),
        "oat_returned_sha256":hashlib.sha256(originals["returned016.json"]).hexdigest(),
        "oat_result_sha256":hashlib.sha256(originals["result.json"]).hexdigest(),
        "image":LEGACY_IMAGE,"container_id":LEGACY_GREEN,
        "owner_approved_product_source":LEGACY_SOURCE,
        "owner_approved_platform_source":LEGACY_PLATFORM_SOURCE,
        "slot":"green","generation":2,
    }
    payload=canonical_bytes(document)
    if verify_root_legacy_certificate(
        payload,intent=current,file_uid=0,file_gid=991,
        file_mode=0o440,file_nlink=1,
    ) != document:
        _fail()
    return document,current_bytes


def _apply(document: dict[str, object], before: bytes) -> None:
    """Mint one durable certificate only while route and replay are locked.

    Root never chowns a pathname inside a UID991-owned directory. The staged
    root-only evidence is not authoritative; the exclusive final hardlink has
    nlink=2 (which the UID991 reader refuses) until the staged name is removed.
    Failed or interrupted writes never publish partial accepted evidence.
    """
    _check_directory(_ROUTE, uid=991, gid=991, mode=0o700)
    fd = os.open(_ROUTE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if _read_file(_TRANSACTION, uid=991, gid=991, mode=0o600, limit=2048) != before:
            _fail()
        # SQLite DELETE-mode shared lock excludes replay writer commits while
        # the one-time authoritative certificate becomes durable.
        with _held_replay_evidence():
            made = False
            try:
                os.mkdir("executions", mode=0o700, dir_fd=fd)
                made = True
            except FileExistsError:
                pass
            evidence = os.open("executions", os.O_RDONLY | os.O_DIRECTORY
                               | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                original = os.fstat(evidence)
                if not stat.S_ISDIR(original.st_mode):
                    _fail()
                if made:
                    if (original.st_uid, original.st_gid,
                            stat.S_IMODE(original.st_mode)) != (0, 0, 0o700):
                        _fail()
                    os.fchown(evidence, 991, 991)
                opened = os.fstat(evidence)
                named = os.stat("executions", dir_fd=fd, follow_symlinks=False)
                if (opened.st_uid, opened.st_gid, stat.S_IMODE(opened.st_mode)) != (991, 991, 0o700):
                    _fail()
                if not stat.S_ISDIR(named.st_mode) or (
                    opened.st_dev, opened.st_ino
                ) != (named.st_dev, named.st_ino):
                    _fail()
                os.fsync(fd)

                payload = canonical_bytes(document)
                # A preexisting non-authoritative pending file is evidence of
                # an interrupted prior root attempt: permanent HOLD, no cleanup.
                stage = "." + CERTIFICATE_NAME + ".pending"
                stage_fd = os.open(
                    stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                    os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=evidence,
                )
                try:
                    if os.write(stage_fd, payload) != len(payload):
                        _fail()
                    os.fchown(stage_fd, 0, 991)
                    os.fchmod(stage_fd, 0o440)
                    st = os.fstat(stage_fd)
                    if (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode),
                            st.st_nlink) != (0, 991, 0o440, 1):
                        _fail()
                    os.fsync(stage_fd)
                finally:
                    os.close(stage_fd)
                # Link publishes exclusively without replacing a named
                # certificate. While pending still exists its nlink=2 is
                # rejected by read_root_legacy_certificate.
                os.link(stage, CERTIFICATE_NAME, src_dir_fd=evidence,
                        dst_dir_fd=evidence, follow_symlinks=False)
                os.fsync(evidence)
                os.unlink(stage, dir_fd=evidence)
                os.fsync(evidence)
                os.fsync(fd)
                named = os.stat("executions", dir_fd=fd, follow_symlinks=False)
                current = os.fstat(evidence)
                if ((named.st_dev, named.st_ino) !=
                        (current.st_dev, current.st_ino)):
                    _fail()
            finally:
                os.close(evidence)
    finally:
        os.close(fd)


def main() -> int:
    if (len(sys.argv) != 3 or sys.argv[1] not in ("--preflight", "--apply")
            or type(sys.argv[2]) is not str
            or len(sys.argv[2]) != 40
            or any(c not in _HEX for c in sys.argv[2])):
        return 2
    try:
        # Never run a writable operator from an untrusted user-owned script.
        if sys.argv[1] == "--apply":
            if _review_root_installed_operator_path(__file__,sys.argv[2]) != \
                    _ROOT_INSTALL_BASE / ("analytics-app-release-" + sys.argv[2]):
                _fail()
        document,before=_preflight()
        print("M05_HISTORIC_ROOT_FINAL_AND_OAT_CERTIFICATE_PASS",flush=True)
        print("M05_UID991_SIGNED_ACTIVE0160_ROUTE_PASS",flush=True)
        print("M05_OLD_REPLAY_ABSENT_OR_FINISHED_NEW_RUN_CONSUMED_PASS",flush=True)
        if sys.argv[1] == "--apply":
            _apply(document,before)
            print("M05_LEGACY_ROOT_0440_COMPLETION_CERTIFICATE_CREATED",flush=True)
        else:
            print("M05_LEGACY_READONLY_PREFLIGHT_PASS",flush=True)
        print("M05_NO_REPLAY_RESET_NO_SERVICE_RESTART_NO_TASK014_NO_PROD",flush=True)
        return 0
    except _CONTROL:
        raise
    except Exception:
        print("M05_LEGACY_ATTESTATION_HOLD",flush=True)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
