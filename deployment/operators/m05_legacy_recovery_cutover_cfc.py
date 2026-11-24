#!/usr/bin/python3 -I
"""File: /usr/local/libexec/omnilyzer-m05-legacy-recovery-cutover-cfc.py
Purpose: Single-use fail-closed DEV source recovery switch to approved
         cfc274 source only after root-attested legacy0.16.0 OAT certificate.
Related: PR316 fcd56406e350b9b20ba107f357d18c0dfb7e6985, Issue #281,
         deployment/analytics_executor_service_config.py, Task014 broker/socket.
Sections: fixed inputs; source verification; rollback backup; atomic install;
          service cutover; automatic rollback and durable one-use receipt.
Does not deploy a container, bypass Task014 OIDC/signature checks, change
Nginx Compose, mutate Docker/Postgres or authorize PROD.
Source-only DRAFT, not independently approved or installed for root use.
"""
from __future__ import annotations

import hashlib
import http.client
import sqlite3
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

# Section: immutable expected source and two config/two service destinations.
SHA = "fcd56406e350b9b20ba107f357d18c0dfb7e6985"
SOURCE = Path("/opt/omnilyzer/deployment/analytics-app-release-" + SHA)
OPERATOR = Path("/usr/local/libexec/omnilyzer-m05-legacy-recovery-cutover-cfc.py")
REVIEW = Path("/home/omnigpt/repos/omnilyzer-platform/.delivery/m05-pr316-recovery-cutover-fcd564-20261124/payload")
JOURNAL = Path("/opt/omnilyzer/deployment/.m05-ordinary-cutover-" + SHA)
OLD_ROOT = "/opt/omnilyzer/deployment/analytics-app-release-330f3255f0067b9ddbe30d50466830bd71a55a11"
NEW_ROOT = str(SOURCE)
PLAN = (
    ("/etc/omnilyzer/deployment/broker/analytics.json",
     "416fc9c2b6e7d902b8bb6d3eff8e14eaa6f9e526b4632e90ecfac2f4169ba2b4", 0o640, 990),
    ("/etc/omnilyzer/deployment/dev/analytics-executor.json",
     "416fc9c2b6e7d902b8bb6d3eff8e14eaa6f9e526b4632e90ecfac2f4169ba2b4", 0o640, 991),
    ("/etc/systemd/system/omnilyzer-deployment-broker.service.d/analytics-v2-source.conf",
     "ea274b9e6655e23494cf8a9d61f47f53e572bc2dfd8f2a7d94eeff17150575d2", 0o644, 0),
    ("/etc/systemd/system/omnilyzer-deployment-analytics-executor.service.d/analytics-v2-source.conf",
     "26094c49bf29373324d76219fc436a185426a50fd9d9c70224c52cf0ded7ffce", 0o644, 0),
)
BROKER = "omnilyzer-deployment-broker.service"
EXECUTOR = "omnilyzer-deployment-analytics-executor.service"
SOCKET = "omnilyzer-deployment-analytics-executor.socket"
ERROR = "M05_CFC_LEGACY_RECOVERY_CUTOVER_HOLD"


# Section: require exact now-confirmed 330f protected config preimage bytes.
# No pre-rebind hashes from the d4a generation may be used.
ORIGINAL_SOURCE = "330f3255f0067b9ddbe30d50466830bd71a55a11"
EXPECTED_OLD = {
    "/etc/omnilyzer/deployment/broker/analytics.json":
        "de054fbc2f54c35835ed53d91aa2caa5da965d4a619db3e9f6c909c94598d4cc",
    "/etc/omnilyzer/deployment/dev/analytics-executor.json":
        "de054fbc2f54c35835ed53d91aa2caa5da965d4a619db3e9f6c909c94598d4cc",
    "/etc/systemd/system/omnilyzer-deployment-broker.service.d/analytics-v2-source.conf":
        "43bcd3234c8428cedd5d4bda06db3a0b4144c1275ca2121230046affe4f89342",
    "/etc/systemd/system/omnilyzer-deployment-analytics-executor.service.d/analytics-v2-source.conf":
        "fa635a6d8321cf202487aca19abafaf20f62af38f9f9fb5d55892b7b82511ea6",
}

# Section: descriptor-based reads, untrusted review artifact hash validation.
def checked_read(path: Path, *, uid: int, gid: int, mode: int, maximum: int = 16384) -> bytes:
    """Read exact regular single-link file, deny symlinks and mutable content."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        a = os.fstat(fd)
        if (
            not stat.S_ISREG(a.st_mode) or a.st_nlink != 1
            or (a.st_uid, a.st_gid, stat.S_IMODE(a.st_mode)) != (uid, gid, mode)
            or not 0 < a.st_size <= maximum
        ):
            raise ValueError("untrusted file metadata")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, 32768)
            if not chunk:
                break
            data.extend(chunk)
        b = os.fstat(fd)
        keys = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(data) != a.st_size or any(getattr(a, x) != getattr(b, x) for x in keys):
            raise ValueError("unstable file")
        return bytes(data)
    finally:
        os.close(fd)


def parent_trusted(path: Path) -> None:
    """Require root-owned, non-group-writable, nonsymlink destination ancestors."""
    p = Path("/")
    for piece in path.parts[1:-1]:
        p /= piece
        x = p.lstat()
        if not stat.S_ISDIR(x.st_mode) or x.st_uid != 0 or (x.st_mode & 0o022):
            raise ValueError("untrusted destination ancestor")


def sha(raw: bytes) -> str:
    """Return SHA256 hex digest."""
    return hashlib.sha256(raw).hexdigest()


def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON properties."""
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result


def load_json(raw: bytes) -> dict[str, object]:
    """Read strict JSON object with no duplicate or nonfinite values."""
    result = json.loads(raw.decode("ascii"), object_pairs_hook=unique_pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError))
    if type(result) is not dict:
        raise ValueError("invalid configuration")
    return result


# Section: verify all source hash claims against installed SHA root.
def verify_source_and_inputs() -> tuple[tuple[Path, bytes, bytes, int, int], ...]:
    """Reject a changed signed-source selection, review input or preexisting slot."""
    parent_trusted(SOURCE / "deployment/analytics_executor.py")
    st = SOURCE.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0o755:
        raise ValueError("untrusted installed source")
    originals = []
    for dest_str, expected, mode, gid in PLAN:
        dest = Path(dest_str)
        parent_trusted(dest)
        review_path = REVIEW / dest_str.lstrip("/")
        new = checked_read(review_path, uid=1005, gid=1005, mode=0o400)
        if sha(new) != expected:
            raise ValueError("review artifact hash mismatched")
        old = checked_read(dest, uid=0, gid=gid, mode=mode)
        if sha(old) != EXPECTED_OLD[dest_str]:
            raise ValueError("existing protected predecessor bytes changed")
        if dest_str.endswith(".json"):
            cfg = load_json(old)
            if (
                cfg.get("product_id") != "analytics" or cfg.get("stage") != "dev"
                or type(cfg.get("schema_version")) is not int
                or cfg["schema_version"] != 4
                or cfg.get("reviewed_installed_commit") != ORIGINAL_SOURCE
                or cfg.get("owner_authorized_ordinary_successor") is not True
            ):
                raise ValueError("untrusted existing source config generation")
            desired = load_json(new)
            if (
                set(desired) != set(cfg)
                or {key for key in desired if cfg.get(key) != desired[key]}
                    != {"reviewed_installed_commit", "source_sha256"}
                or set(desired.get("source_sha256", {}))
                    != set(cfg["source_sha256"])
                or any(
                    (desired["source_sha256"][name] != cfg["source_sha256"][name])
                    != (name in (
                        "deployment/analytics_executor.py",
                        "deployment/analytics_route_journal.py",
                    ))
                    for name in cfg["source_sha256"]
                )
            ):
                raise ValueError("config changed unrelated trust controls")
            if (
                desired.get("product_id") != "analytics"
                or desired.get("stage") != "dev"
                or desired.get("schema_version") != 4
                or desired.get("reviewed_installed_commit") != SHA
                or desired.get("owner_authorized_ordinary_successor") is not True
                or desired.get("expected_workflow_sha") != "630db1ae5a05a691493764637e066e487f52f599"
            ):
                raise ValueError("unapproved generation4 config")
            # Every advertised source byte must match the immutable installed root.
            entries = desired.get("source_sha256")
            if type(entries) is not dict or len(entries) != 26:
                raise ValueError("wrong source inventory")
            for relative, expected_hash in entries.items():
                if (
                    type(relative) is not str
                    or (
                        not relative.startswith("deployment/")
                        and relative != "release/analytics_owner_source_selection.py"
                    )
                    or ".." in relative.split("/")
                    or relative.startswith("/")
                    or "//" in relative
                    or "\x00" in relative
                ):
                    raise ValueError("unsafe source member")
                blob = checked_read(SOURCE / relative, uid=0, gid=0, mode=0o644, maximum=1_048_576)
                if sha(blob) != expected_hash:
                    raise ValueError("source hash mismatch")
        else:
            if new != old.replace(OLD_ROOT.encode(), NEW_ROOT.encode()):
                raise ValueError("unexpected current drop-in or new override")
            if old.count(OLD_ROOT.encode()) != 1:
                raise ValueError("unexpected current working directory")
        originals.append((dest, old, new, mode, gid))
    if originals[0][2] != originals[1][2]:
        raise ValueError("broker and executor generation disagree")
    return tuple(originals)


# Section: fail-closed historical completion, root continuity and source closure.
LEGACY_SHA = "73071f42dffcce2dc7eaa2cf494335b6cc7e85eb7346c074529065f4fb079004"
LEGACY_RUN = 43838827603
FAILED_RUN = 44890393889
LEGACY_IMAGE = ("oci-dev.omnilyzer.ai/omnilyzer/analytics@sha256:"
                "a0ce1e63dd379c939a2e558b04307b129fa79128da1362"
                "caa90d963d8bb3f6a1")
LEGACY_CONTAINER = "c160029c449cbdf37f35515dd25e5e2235cdeb08f3eebe6525fee17d2d839432"
LEGACY_FINAL_RECEIPT_SHA = "e1efe4109156c6c0116a806dc287f7edbd6e828973db77f2fe4f6d2ceaa5d341"
LEGACY_FINAL_RECEIPT = Path(
    "/var/lib/omnilyzer/deployment/.m05-analytics016-final-release-43838827603.json"
)
OAT = Path("/var/lib/omnilyzer/deployment/.m05-analytics016-43838827603-recovery-oat")
ROUTE = Path("/var/lib/omnilyzer/deployment/analytics-route/transaction.json")
CERT = Path("/var/lib/omnilyzer/deployment/analytics-route/executions/legacy-completion-" + LEGACY_SHA + ".json")
REPLAY = Path("/var/lib/omnilyzer/deployment/authority/replay.sqlite3")
MANIFEST = Path(
    "/home/omnigpt/repos/omnilyzer-platform/.delivery/m05-pr316-source-stage-fcd564-20261124/manifest.json"
)
MANIFEST_SHA = "dded55ab8a8773c74ba5ac909628cf266849b1e09c66bcc9ee6c75710494d645"
BASE_SHA = "330f3255f0067b9ddbe30d50466830bd71a55a11"


def stable_legacy_state() -> None:
    """Do not start anything when a root-attested maintenance receipt is absent."""
    if sha(checked_read(
        LEGACY_FINAL_RECEIPT, uid=0, gid=0, mode=0o600, maximum=65536,
    )) != LEGACY_FINAL_RECEIPT_SHA:
        raise ValueError("root final release receipt changed")
    original = load_json(checked_read(ROUTE, uid=991, gid=991, mode=0o600))
    if (
        original.get("generation") != 2
        or original.get("phase") != "switched"
        or original.get("next_slot") != "green"
        or original.get("request_sha256") != LEGACY_SHA
        or original.get("next_image") != LEGACY_IMAGE
        or original.get("next_container_id") != LEGACY_CONTAINER
    ):
        raise ValueError("unexpected current signed active route")

    if sha(checked_read(MANIFEST, uid=1005, gid=1005, mode=0o400)) != MANIFEST_SHA:
        raise ValueError("unreviewed source inventory")
    manifest = load_json(checked_read(MANIFEST, uid=1005, gid=1005, mode=0o400))
    if (manifest.get("baseline_commit") != BASE_SHA
            or manifest.get("target_commit") != SHA
            or type(manifest.get("baseline_files_sha256")) is not dict
            or len(manifest["baseline_files_sha256"]) != 76
            or type(manifest.get("replacement_sha256")) is not dict
            or set(manifest["replacement_sha256"]) != {
                "deployment/analytics_executor.py",
                "deployment/analytics_route_journal.py",
            }):
        raise ValueError("unreviewed source file inventory")
    expected = {**manifest["baseline_files_sha256"], **manifest["replacement_sha256"]}
    names = set()
    for directory, foldernames, filenames in os.walk(SOURCE, followlinks=False):
        for folder in foldernames:
            info = (Path(directory)/folder).lstat()
            if (not stat.S_ISDIR(info.st_mode)
                    or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)) !=
                    (0,0,0o755)):
                raise ValueError("unexpected source subdirectory")
        for name in filenames:
            path = Path(directory)/name
            member = path.relative_to(SOURCE).as_posix()
            if member not in expected:
                raise ValueError("unknown installed source member")
            blob = checked_read(path, uid=0, gid=0, mode=0o644, maximum=1_048_576)
            if sha(blob) != expected[member]:
                raise ValueError("immutable source member SHA mismatch")
            names.add(member)
    if names != set(expected):
        raise ValueError("installed source member count or paths differ")

    statdir = OAT.lstat()
    if (not stat.S_ISDIR(statdir.st_mode)
            or (statdir.st_uid,statdir.st_gid,stat.S_IMODE(statdir.st_mode)) !=
            (0,0,0o700)
            or set(os.listdir(OAT)) != {
                "before.json", "restored015.json", "returned016.json", "result.json",
            }):
        raise ValueError("unreviewed root OAT receipt directory")
    originals = {
        name:checked_read(OAT/name,uid=0,gid=0,mode=0o600,maximum=1_048_576)
        for name in ("before.json","restored015.json","returned016.json","result.json")
    }
    docs = {name:load_json(data) for name,data in originals.items()}
    before = docs["before.json"]["route"]["journal"]
    restored = docs["restored015.json"]["journal"]
    returned = docs["returned016.json"]["journal"]
    result = docs["result.json"]
    if (
        before.get("generation") != 1 or before.get("phase") != "switched"
        or restored.get("generation") != 1 or restored.get("phase") != "restored"
        or returned != original
        or returned.get("generation") != 2 or returned.get("phase") != "switched"
        or any(x.get("request_sha256") != LEGACY_SHA for x in (before,restored,returned))
        or not all(type(result.get(k)) is bool and result[k] is True
                   for k in ("pass","replay_unchanged","database_unchanged"))
    ):
        raise ValueError("historical maintenance OAT mismatch")

    # This is an owner-root 0440 bridge, not UID991-mintable evidence or a
    # new Token/Task014 approval. Its pure parser is in the SHA-checked cfc
    # journal module, imported only AFTER verifying the entire source tree.
    # Never allow an inherited user path to select deployment modules.
    # The reviewed root source directory and all 76 source file digests
    # were checked above, before this first import from that generation.
    if "deployment" in sys.modules:
        module = sys.modules["deployment"]
        pkg_path = getattr(module, "__file__", "")
        if (type(pkg_path) is not str
                or not pkg_path.startswith(str(SOURCE) + "/deployment/")):
            raise ValueError("unexpected deployment module loaded before pinning")
    else:
        sys.path.insert(0, str(SOURCE))
    from deployment.analytics_route_journal import verify_root_legacy_certificate
    from deployment.policy import canonical_bytes
    st = CERT.lstat()
    if (
        not stat.S_ISREG(st.st_mode)
        or (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_nlink) != (0,991,0o440,1)
    ):
        raise ValueError("historical certificate missing or untrusted")
    raw = checked_read(CERT, uid=0, gid=991, mode=0o440, maximum=1250)
    cert = verify_root_legacy_certificate(
        raw, intent=original, file_uid=0,file_gid=991,
        file_mode=0o440,file_nlink=1,
    )
    if (
        cert["current_journal_sha256"] != sha(canonical_bytes(original))
        or cert["final_release_receipt_sha256"] != LEGACY_FINAL_RECEIPT_SHA
        or any(cert["oat_" + key + "_sha256"] != sha(originals[name])
               for key,name in (("before","before.json"),
                                ("restored","restored015.json"),
                                ("returned","returned016.json"),
                                ("result","result.json")))
    ):
        raise ValueError("root legacy certificate does not bind original signed OAT")

    if any(os.path.lexists(str(REPLAY)+suffix) for suffix in ("-wal","-shm")):
        raise ValueError("live replay WAL is unsafe for immutable snapshot")
    conn = sqlite3.connect(REPLAY.as_uri()+"?mode=ro&immutable=1",uri=True)
    try:
        conn.execute("PRAGMA query_only=ON")
        a=conn.execute(
            "SELECT status FROM consumptions WHERE github_run_id=? AND github_run_attempt=1",
            (LEGACY_RUN,),
        ).fetchmany(2)
        b=conn.execute(
            "SELECT status FROM consumptions WHERE github_run_id=? AND github_run_attempt=1",
            (FAILED_RUN,),
        ).fetchmany(2)
        if a not in ([],[("finished",)]) or b != [("consumed",)]:
            raise ValueError("replay status changed or failed run reused")
    finally:
        conn.close()
    verify_actual_uid991_signed_0160_route()


def verify_actual_uid991_signed_0160_route() -> None:
    """Read-only independent RootlessKit OCI/container and route verification.

    A healthy HTTP endpoint and a signed journal are NOT sufficient: the
    existing private UID991 Docker/RootlessKit route must actually show
    signed0.16.0 digest and the exact original green container.
    """
    script = (
        "import sys;sys.path.insert(0," + repr(str(SOURCE)) + ");"
        "from deployment.analytics_route_journal import AnalyticsRouteJournal;"
        "from deployment.analytics_active_state_review import inspect_committed_analytics_route;"
        "journal=AnalyticsRouteJournal();"
        "state=inspect_committed_analytics_route("
        "journal=journal,reviewed_image=" + repr(LEGACY_IMAGE) + ","
        "reviewed_slot='green',reviewed_container_id="
        + repr(LEGACY_CONTAINER) + ",reviewed_request_sha256="
        + repr(LEGACY_SHA) + ");"
        "assert state.active_slot=='green';"
        "assert state.active_image==" + repr(LEGACY_IMAGE) + ";"
        "assert state.active_container_id==" + repr(LEGACY_CONTAINER) + ";"
        "print('M05_SIGNED_0160_ROOTLESS_ROUTE_VERIFIED')"
    )
    result = subprocess.run(
        ("/usr/bin/setpriv","--reuid","991","--regid","991",
         "--groups","992","--no-new-privs",
         "/opt/omnilyzer/deployment/venv/bin/python","-I","-B","-c",script),
        env={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8","HOME":"/nonexistent",
             "ANALYTICS_REVIEWED_SUPERVISOR_V2":"1"},
        check=False,capture_output=True,text=True,timeout=35,
        stdin=subprocess.DEVNULL,
    )
    if (
        result.returncode != 0
        or result.stdout.strip() != "M05_SIGNED_0160_ROOTLESS_ROUTE_VERIFIED"
    ):
        raise ValueError("UID991 live signed OCI route verification failed")


def existing_failed_executor_boundary() -> None:
    """The known incident is a failed socket: never assume it is healthy."""
    def show(unit: str, prop: str) -> str:
        result=subprocess.run(
            ("/usr/bin/systemctl","show",unit,"-p",prop,"--value"),
            check=True,timeout=10,capture_output=True,text=True,
        )
        return result.stdout.strip()
    if (
        not active(BROKER)
        or not active("omnilyzer-analytics-loopback.service")
        or active(SOCKET)
        or active(EXECUTOR)
        or show(SOCKET,"ActiveState") != "failed"
        or show(SOCKET,"Result") != "service-start-limit-hit"
        or show(EXECUTOR,"ActiveState") != "failed"
        or show(EXECUTOR,"Result") != "exit-code"
    ):
        raise ValueError("incident state unexpectedly changed; do not switch")

# Section: tightly bounded systemd controls.
def systemctl(*args: str) -> None:
    """Invoke fixed systemctl actions and fail on errors."""
    subprocess.run(("/usr/bin/systemctl", *args), check=True, timeout=50,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def active(unit: str) -> bool:
    """Check named service health without inventing other units."""
    return subprocess.run(("/usr/bin/systemctl", "is-active", "--quiet", unit),
                          check=False, timeout=10,
                          stdin=subprocess.DEVNULL).returncode == 0


# Section: runtime service and real health observation before/after switch.
def verify_service_selection(expected_root: str) -> None:
    """Require exact selected source in both units and live private readiness."""
    from http.client import HTTPConnection
    for unit in (BROKER, EXECUTOR):
        result = subprocess.run(
            ("/usr/bin/systemctl", "show", unit, "-p", "WorkingDirectory", "--value"),
            check=True, timeout=10, stdin=subprocess.DEVNULL,
            capture_output=True, text=True,
        )
        if result.stdout.strip() != expected_root:
            raise ValueError("systemd selected different source")
    connection = HTTPConnection("127.0.0.1", 3141, timeout=3)
    try:
        connection.request("GET", "/readyz", headers={"Cache-Control": "no-store"})
        response = connection.getresponse()
        response.read(2049)
        if response.status != 200:
            raise ValueError("private Analytics no longer ready")
    finally:
        connection.close()

# Section: rollback custody and atomic root file writes.
def write_exclusive(path: Path, data: bytes, *, gid: int, mode: int) -> None:
    """Create one protected snapshot with O_EXCL and durable sync."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchown(fd, 0, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    except Exception:
        raise


def atomic_replace(path: Path, data: bytes, *, gid: int, mode: int) -> None:
    """Replace only a predetermined regular file from root-owned protected temp."""
    temporary = path.with_name(path.name + ".m05-new-" + SHA)
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("existing temporary file")
    try:
        write_exclusive(temporary, data, gid=gid, mode=mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        # Never let an incomplete temporary prevent the exact rollback.
        # Parent is root-owned and fixed; refuse unlinking unexpected objects.
        try:
            status = temporary.lstat()
        except FileNotFoundError:
            pass
        else:
            if (
                not stat.S_ISREG(status.st_mode)
                or (status.st_uid, status.st_gid) != (0, gid)
                or status.st_nlink != 1
                or stat.S_IMODE(status.st_mode) != mode
            ):
                raise ValueError("unexpected temporary; retain for inspection")
            temporary.unlink()
        raise


def fsync_rollback_custody() -> None:
    """Persist directory metadata of root-only rollback evidence.

    Fsync'ing preimage file data alone is insufficient: parent directory
    entry creation also needs durability before any protected file changes.
    """
    for path in (JOURNAL, JOURNAL.parent):
        fd = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def journal(originals: tuple[tuple[Path, bytes, bytes, int, int], ...]) -> None:
    """Make single-use root-only rollback storage before touching service files."""
    # Check the existing trusted parent before creating this one-use journal.
    # JOURNAL itself must not be required to exist until os.mkdir succeeds.
    parent_trusted(JOURNAL)
    os.mkdir(JOURNAL, 0o700)
    for idx, (_, old, _, mode, gid) in enumerate(originals):
        write_exclusive(JOURNAL / f"preimage-{idx}", old, gid=0, mode=0o600)
    write_exclusive(JOURNAL / "manifest.json", json.dumps({
        "commit": SHA, "status": "snapshot-complete",
        "targets": [{"path": str(path), "old_sha256": sha(old),
                     "new_sha256": sha(new), "gid": gid, "mode": mode}
                    for path, old, new, mode, gid in originals],
    }, sort_keys=True).encode(), gid=0, mode=0o600)
    # Commit all four preimages and their names BEFORE stopping broker.
    fsync_rollback_custody()


# Section: atomic source selection, bounded service outage and automatic rollback.
def cutover(originals: tuple[tuple[Path, bytes, bytes, int, int], ...]) -> None:
    """Switch four files only after ROOT legacy attestation; fail closed."""
    existing_failed_executor_boundary()
    stable_legacy_state()
    journal(originals)
    try:
        systemctl("stop", BROKER)
        if active(EXECUTOR):
            systemctl("stop", EXECUTOR)
        systemctl("stop", SOCKET)
        for path, _, new, mode, gid in originals:
            atomic_replace(path, new, gid=gid, mode=mode)
        systemctl("daemon-reload")
        # This reset is permissible only after the exact root-certificate
        # and full owner/OAT/replay/source checks. Never reset an unknown
        # failure or re-consume a previous Task014 JTI.
        systemctl("reset-failed", EXECUTOR)
        systemctl("reset-failed", SOCKET)
        systemctl("start", SOCKET)
        systemctl("start", BROKER)
        if not (active(SOCKET) and active(BROKER) and active("omnilyzer-analytics-loopback.service")):
            raise RuntimeError("service not ready after cutover")
        verify_service_selection(NEW_ROOT)
        write_exclusive(JOURNAL / "SOURCE_SWITCH_COMPLETE", SHA.encode(), gid=0, mode=0o600)
        fsync_rollback_custody()
    except BaseException:
        rollback_incomplete = None
        try:
            systemctl("stop", BROKER)
            if active(EXECUTOR):
                systemctl("stop", EXECUTOR)
            systemctl("stop", SOCKET)
            for path, old, _, mode, gid in originals:
                atomic_replace(path, old, gid=gid, mode=mode)
            systemctl("daemon-reload")
            # Verify every restored byte, owner, mode, and bound path BEFORE
            # attempting to restart the original signed0.16 broker. An
            # interrupted replace or wrong protected file must not be
            # misreported as successful rollback.
            for path, old, _, mode, gid in originals:
                if checked_read(path,uid=0,gid=gid,mode=mode) != old:
                    raise ValueError("old protected configuration not restored")
            if active(SOCKET) or active(EXECUTOR):
                raise ValueError("previously failed socket/executor not fail-closed")
            systemctl("start", BROKER)
            verify_service_selection(OLD_ROOT)
            write_exclusive(JOURNAL / "ROLLBACK_TO_330F_FAILCLOSED",
                            SHA.encode(), gid=0, mode=0o600)
            fsync_rollback_custody()
        except BaseException as failure:
            rollback_incomplete = failure
            # Best-effort durable RED evidence. If storage itself failed,
            # the original preimages are retained and external read-only
            # root inspection is still required. Never auto-retry.
            try:
                write_exclusive(JOURNAL / "ROLLBACK_UNVERIFIED_HOLD",
                                SHA.encode(), gid=0, mode=0o600)
                fsync_rollback_custody()
            except BaseException:
                pass
        if rollback_incomplete is not None:
            raise RuntimeError("M05_CFC_ROLLBACK_UNVERIFIED_HOLD") from rollback_incomplete
        raise


def main(argv: list[str]) -> None:
    """Allow only root preflight and one irreversible tracked source cutover."""
    if argv not in (["--preflight"], ["--switch"]):
        raise ValueError("unsupported operation")
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
        raise PermissionError("root required")
    own = OPERATOR.lstat()
    if (
        Path(__file__) != OPERATOR or not stat.S_ISREG(own.st_mode)
        or (own.st_uid, own.st_gid, stat.S_IMODE(own.st_mode), own.st_nlink)
        != (0, 0, 0o500, 1)
    ):
        raise PermissionError("not root-installed reviewed operator")
    if JOURNAL.exists() or JOURNAL.is_symlink():
        raise ValueError("previous transaction exists")
    originals = verify_source_and_inputs()
    verify_service_selection(OLD_ROOT)
    existing_failed_executor_boundary()
    stable_legacy_state()
    if argv == ["--preflight"]:
        print("M05_CFC_LEGACY_RECOVERY_CUTOVER_PREFLIGHT_PASS", SHA)
        return
    cutover(originals)
    print("M05_CFC_LEGACY_RECOVERY_CUTOVER_PASS", SHA, "signed_application_version_unchanged")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except Exception:
        print(ERROR, file=sys.stderr)
        raise SystemExit(1)
