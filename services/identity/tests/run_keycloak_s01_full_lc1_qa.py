"""Source-pinned QA ONLY: genuine Keycloak -> S01 Chromium LC1 full lesson.

Requirements: disposable localhost Keycloak26 SAN TLS test fixture running;
S03 and S01 exact draft Git worktrees under /tmp, their QA node deps and
compiled S01 private BFF bundle. Never run on the production host.
Reuses the ORIGINAL S03 self-cleaning PostgreSQL Native QA shell and
instrumented browser runner: no new engine, API, IdP or production GRANT.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

S03_SHA="d038f085d84db085055432c03cf99e4bad12d828"
S01_SHA="5730b9edbf7adce3d2e920f2f20a65d29baeae1c"
mode=sys.argv[1] if len(sys.argv)>1 else "fresh"
assert mode in ("fresh","reused")
assert os.uname().nodename.split(".")[0]!="truexmainserver"
platform=Path(__file__).resolve().parents[3]
s03=Path(os.environ["S03_QA_S03_ROOT"]).resolve()
s01=Path(os.environ["S03_QA_S01_ROOT"]).resolve()
assert str(s03).startswith("/tmp/") and str(s01).startswith("/tmp/")
def git_head(p):
    return subprocess.check_output(["git","-C",str(p),"rev-parse","HEAD"],text=True).strip()
assert git_head(s03)==S03_SHA, "S03 source drift: re-review before QA"
assert git_head(s01)==S01_SHA, "S01 source drift: re-review before QA"
app=s01/"apps/sumlaude-learner"
build=app/"dist-private-bff-candidate"
playwright=app/"node_modules/playwright"
assert (build/"index.html").is_file() and (playwright/"package.json").is_file()
subprocess.run(["node","-e","require.resolve('pg',{paths:[process.argv[1]]})",
                str(s03/"backend")],check=True,stdout=subprocess.DEVNULL)
assert (platform/"services/identity/tests/qa_keycloak_native_bridge.py").is_file()
node=platform/"services/identity/tests/qa_keycloak_s01_full_lc1.cjs"
assert node.is_file()
original=s03/"scripts/qa/s03-str012-real-pg16-disposable.sh"
script=original.read_text()
anchor='ROOT="$(cd "$(dirname "$0")/../.." && pwd)"'
assert script.count(anchor)==1
script=script.replace(anchor,'ROOT="'+str(s03)+'"')
needle='  node "$ROOT/scripts/qa/s03-str012-lc1-real-chromium-bff-qa.cjs"'
assert script.count(needle)==1
instrument=(
    '  export S03_QA_REAL_IDENTITY_BUNDLE="$TEMP/keycloak-native-bridge.json"\n'
    '  "$S03_QA_PLATFORM_PYTHON" "$S03_QA_PLATFORM_BRIDGE" bootstrap\n'
    '  node "$S03_QA_PLATFORM_CHROMIUM"'
)
script=script.replace(needle,instrument)
env=dict(os.environ)
env.update({
    "S03_QA_S03_ROOT":str(s03),
    "S03_QA_S01_SOURCE_ROOT":str(app/"src"),
    "S03_QA_S01_BFF_BUILD_ROOT":str(build),
    "S03_QA_PLAYWRIGHT_MODULE":str(playwright),
    "S03_QA_PLATFORM_PYTHON":str(platform/".venv/bin/python"),
    "S03_QA_PLATFORM_BRIDGE":str(platform/"services/identity/tests/qa_keycloak_native_bridge.py"),
    "S03_QA_PLATFORM_CHROMIUM":str(node),
})
# Self-cleaning original S03 script owns network-disabled PG16 container,
# ephemeral Keycloak browser and all synthetic account/session rows.
with tempfile.TemporaryDirectory(prefix="platform-keycloak-native-",dir="/tmp") as folder:
    runner=Path(folder)/"reviewed-s03-qa-copy.sh"
    runner.write_text(script)
    runner.chmod(0o700)
    subprocess.run(["bash",str(runner),mode],env=env,check=True)
print("PLATFORM_REAL_KEYCLOAK_S01_FULL_LC1_JOINED_QA_PASS",mode)
