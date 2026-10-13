#!/usr/bin/env bash
# File (reviewed delivery): .task014-c34a-reviewed-source-preparation.sh
# File (execution host): /root/task014-c34a-reviewed-source-preparation.sh
# Purpose: Materialize an immutable, root-owned C34A source checkout for the
#   exact merged Omnilyzer Task 014 consumer identity authorization update.
# Linked locations:
#   /home/omnigpt/repos/omnilyzer-platform/.task014-c34a-merged-main-*.bundle
#   /opt/omnilyzer/deployment/app/ (read-only predecessor inspection)
#   /etc/omnilyzer/deployment/dev/executor.json (read-only)
#   /etc/omnilyzer/deployment/broker/dev.json (read-only)
#   /opt/omnilyzer/deployment/reviewed-source-*-c34a (new source only)
# Security: No service activation, live application/configuration replacement,
#   registry writes, Docker command, promotion request, or automatic retry.
set -euo pipefail
umask 077

# 1. Immutable reviewed identity and expected source/configuration digests.
readonly HOST="omnilyzerdev"
readonly BASE="f2ece4257b84090b1a6fff5d1aa7f0b6047765cd"
readonly TARGET="176ed3a31ffcf23346639ef22ac9bcab3794f0df"
readonly TARGET_TREE="c35c59c607c04b3d08875329fe1d18944187d24b"
readonly BUNDLE="/home/omnigpt/repos/omnilyzer-platform/.task014-c34a-merged-main-${TARGET}.bundle"
readonly BUNDLE_SHA="7a3ba394ee94c737c7a9c53ac2dd3379e6608034962d3eeb335d8ccbd0fe2adb"
readonly OLD_IDENTITY="5c8a7519eff4293b9f057a2d27400967ff4d054c19e1e09b3ea33a90c217beeb"
readonly NEW_IDENTITY="475ac95faf25fe832cc3a6e68e68ddb3340782f8e3a93d12da1c9a98584b2cbf"
readonly EXECUTOR_SHA="b954895b5c95ed55ae254390a2f396167323f650f663daaad62928714f1748b9"
readonly BROKER_SHA="58c265133741c404ac67496aae62a83583032f369c4cc0b26d0cbf4b6f5368b9"
readonly APP="/opt/omnilyzer/deployment/app"
readonly SRC="/opt/omnilyzer/deployment/reviewed-source-${TARGET}-c34a"
readonly STAGE="${SRC}.tmp"
readonly EXECUTOR_CONFIG="/etc/omnilyzer/deployment/dev/executor.json"
readonly BROKER_CONFIG="/etc/omnilyzer/deployment/broker/dev.json"
readonly PYTHON="/opt/omnilyzer/deployment/venv/bin/python"

# 2. Helper functions are read-only and fail closed on unexpected input.
file_sha() {
    # Hash the exact bytes of a required regular file; never follow a symlink.
    local path="$1"
    test -f "$path" && test ! -L "$path"
    sha256sum -- "$path" | awk '{print $1}'
}

unit_state() {
    # Inspect a bounded systemd unit without activating it.
    local unit="$1"
    systemctl show "$unit" \
        --property=LoadState,ActiveState,SubState,MainPID,UnitFileState \
        --no-pager | LC_ALL=C sort
}

verify_live_predecessor() {
    # Require unchanged live files, service lifecycle and private Docker socket.
    test "$(file_sha "$APP/deployment/identity.py")" = "$OLD_IDENTITY"
    test "$(file_sha "$EXECUTOR_CONFIG")" = "$EXECUTOR_SHA"
    test "$(file_sha "$BROKER_CONFIG")" = "$BROKER_SHA"
    test "$(systemctl show omnilyzer-deployment-broker.service -p ActiveState --value)" = active
    test "$(systemctl show omnilyzer-deployment-executor.socket -p ActiveState --value)" = active
    test "$(systemctl show omnilyzer-deployment-executor.service -p ActiveState --value)" = inactive
    test -S /run/user/991/docker.sock
    test "$(stat -Lc '%a:%u:%g' /run/user/991/docker.sock)" = "1660:991:991"
}

# 3. Preflight before any filesystem mutation.
echo '================================================'
echo 'OMNILYZER TASK 014 / C34A SOURCE PREPARATION'
echo 'NO LIVE APPLICATION OR SERVICE MUTATION'
echo '================================================'
test "$(hostname)" = "$HOST"
test "$(id -u):$(id -g)" = "0:0"
test -x "$PYTHON"
test -d "$APP" && test ! -L "$APP"
test ! -e "$SRC" && test ! -L "$SRC"
test ! -e "$STAGE" && test ! -L "$STAGE"
test -f "$BUNDLE" && test ! -L "$BUNDLE"
test "$(file_sha "$BUNDLE")" = "$BUNDLE_SHA"
verify_live_predecessor

# Keep a compact snapshot to detect any concurrent service lifecycle changes.
BEFORE_SERVICES="$(
    for unit in \
        omnilyzer-deployment-broker.service \
        omnilyzer-deployment-executor.socket \
        omnilyzer-deployment-executor.service; do
        printf '[%s]\n' "$unit"
        unit_state "$unit"
    done
)"
echo 'PREFLIGHT=PASS'

# 4. Copy the immutable bundle into a root-private path before Git reads it.
# A trap removes only this temporary copy, never the reviewed source/staging
# directory: failed staging is intentionally retained for inspection.
PRIVATE_BUNDLE="$(mktemp /root/.task014-c34a-bundle.XXXXXXXX)"
cleanup_private_bundle() {
    # Remove only the bounded temporary copy, irrespective of success/failure.
    rm -f -- "$PRIVATE_BUNDLE"
}
trap cleanup_private_bundle EXIT
cp -- "$BUNDLE" "$PRIVATE_BUNDLE"
chmod 0600 "$PRIVATE_BUNDLE"
test "$(file_sha "$PRIVATE_BUNDLE")" = "$BUNDLE_SHA"

autostage_marker='C34A_STAGE_CREATED'
install -d -o root -g root -m 0700 -- "$STAGE"
echo "$autostage_marker"

# 5. Materialize and qualify the exact merged Git commit without checkout
# against the dirty /home/omnigpt working repository.
git -C "$STAGE" init --quiet
git -C "$STAGE" bundle verify "$PRIVATE_BUNDLE"
git -C "$STAGE" fetch --quiet --no-tags "$PRIVATE_BUNDLE" HEAD
git -C "$STAGE" checkout --quiet --detach FETCH_HEAD

test "$(git -C "$STAGE" rev-parse HEAD)" = "$TARGET"
test "$(git -C "$STAGE" rev-parse 'HEAD^{tree}')" = "$TARGET_TREE"
git -C "$STAGE" cat-file -e "${BASE}^{commit}"
git -C "$STAGE" fsck --full --strict
test -z "$(git -C "$STAGE" status --porcelain=v1 --untracked-files=all)"
test -z "$(git -C "$STAGE" clean -ndx)"
test -z "$(find "$STAGE" -xdev -type l -print -quit)"
test -z "$(find "$STAGE" -xdev \( ! -user root -o -perm /022 \) -print -quit)"
test "$(file_sha "$STAGE/deployment/identity.py")" = "$NEW_IDENTITY"
echo 'REVIEWED_GIT_OBJECTS=PASS'

# 6. Python verification reads every one of the 41 selected application blobs
# and constructs the exact canonical manifest using the existing platform model.
REVIEWED_SOURCE="$STAGE" INSTALLED_APP="$APP" \
PREDECESSOR="$BASE" TARGET="$TARGET" \
"$PYTHON" -I -B - <<'PY'
"""C34A read-only application generation verification.

Linked modules: deployment.application_source_set, deployment.application_manifest.
Proof: 41 exact installed predecessor blobs, one reviewed identity delta,
canonical target manifest, unchanged runtime and ingress inputs.
"""
from pathlib import Path
import hashlib
import os
import subprocess
import sys

source = Path(os.environ["REVIEWED_SOURCE"])
installed = Path(os.environ["INSTALLED_APP"])
predecessor = os.environ["PREDECESSOR"]
target = os.environ["TARGET"]
sys.path.insert(0, str(source))

from deployment.application_source_set import DevApplicationSourceSet
from deployment.application_manifest import (
    ApplicationManifestEntry,
    DevApplicationManifest,
)


def git_blob(commit: str, path: str) -> bytes:
    """Read exact closed Git blob bytes without altering the repository."""
    return subprocess.check_output(
        ("/usr/bin/git", "-C", str(source), "show", f"{commit}:{path}"),
        stderr=subprocess.DEVNULL,
        timeout=15,
    )


paths = tuple(item.repository_path for item in DevApplicationSourceSet().files)
if len(paths) != 41:
    raise SystemExit("REJECTED: unexpected source path count")
if hashlib.sha256(("\n".join(paths) + "\n").encode()).hexdigest() != (
    "c846e3d863f8c651ffc2de4d3671c9b8c0631c72366a360637d9cc45f98b60ab"
):
    raise SystemExit("REJECTED: unexpected source path list")

changed = []
entries = []
for path in paths:
    live = installed / path
    reviewed = source / path
    if live.is_symlink() or reviewed.is_symlink():
        raise SystemExit("REJECTED: application symlink: " + path)
    previous_bytes = git_blob(predecessor, path)
    target_bytes = git_blob(target, path)
    if not live.is_file() or live.read_bytes() != previous_bytes:
        raise SystemExit("REJECTED: installed predecessor mismatch: " + path)
    if not reviewed.is_file() or reviewed.read_bytes() != target_bytes:
        raise SystemExit("REJECTED: reviewed blob mismatch: " + path)
    if previous_bytes != target_bytes:
        changed.append(path)
    entries.append(
        ApplicationManifestEntry(
            path, hashlib.sha256(target_bytes).hexdigest(), "0644"
        )
    )

if changed != ["deployment/identity.py"]:
    raise SystemExit("REJECTED: changed application paths: " + repr(changed))
manifest = DevApplicationManifest(
    "canonical-relative-file-set-v1", "sha256", target, tuple(entries)
)
manifest_sha = hashlib.sha256(manifest.canonical_bytes()).hexdigest()
if manifest_sha != (
    "384f5b4e4ca9849da62ab17b624137a52b9292fd3e03d03fefcbabed3bc0ee4b"
):
    raise SystemExit("REJECTED: canonical target manifest mismatch")

runtime_inputs = {
    "deployment/runtime/dev/canary-runtime.json":
        "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f",
    "deployment/runtime/dev/compose.yaml":
        "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
    "deployment/runtime/dev/host-nginx.conf":
        "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
    "deployment/runtime/dev/nginx/nginx.conf":
        "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
}
for path, expected in runtime_inputs.items():
    if hashlib.sha256((source / path).read_bytes()).hexdigest() != expected:
        raise SystemExit("REJECTED: runtime or ingress mismatch: " + path)
print("APPLICATION_FILES=41")
print("CHANGED_FILES=deployment/identity.py")
print("TARGET_MANIFEST_SHA256=" + manifest_sha)
print("RUNTIME_AND_INGRESS=UNCHANGED")
print("APPLICATION_GENERATION=PASS")
PY

# 7. Re-verify installed state has not changed while staging was prepared.
verify_live_predecessor
AFTER_SERVICES="$(
    for unit in \
        omnilyzer-deployment-broker.service \
        omnilyzer-deployment-executor.socket \
        omnilyzer-deployment-executor.service; do
        printf '[%s]\n' "$unit"
        unit_state "$unit"
    done
)"
test "$AFTER_SERVICES" = "$BEFORE_SERVICES"
echo 'LIVE_SERVICES_AND_CONFIGURATION_UNCHANGED=PASS'

# 8. Publish ONLY the already-verified root-owned reviewed-source directory.
# No deployed application/configuration path is replaced in this phase.
mv -T -- "$STAGE" "$SRC"
test -d "$SRC" && test ! -L "$SRC"
test "$(stat -c '%u:%g:%a' "$SRC")" = '0:0:700'
test "$(git -C "$SRC" rev-parse HEAD)" = "$TARGET"
test "$(git -C "$SRC" rev-parse 'HEAD^{tree}')" = "$TARGET_TREE"
echo "REVIEWED_SOURCE=$SRC"
echo 'C34A_SOURCE_PREPARATION=PASS'
echo 'NO_LIVE_APPLICATION_CHANGE=PASS'
echo 'NO_LIVE_CONFIGURATION_CHANGE=PASS'
echo 'NO_SERVICE_CHANGE=PASS'
echo 'NO_DEPLOYMENT_EXECUTED=PASS'
