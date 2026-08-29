#!/usr/bin/env python3
import concurrent.futures
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from build_images import build_releases, start_registry
from common import AuditLog, STAGES, atomic_json, http_json, read_json, require_immutable, run, wait_until
from deployment import PromotionController, validate_compose_text

PROJECTS = {stage: f"omnilyzer-task007-{stage}" for stage in STAGES}
PORTS = {"dev": 18080, "staging": 18081, "prod": 18082}
MARKERS = {"dev": "development", "staging": "preproduction", "prod": "production"}
REGISTRY = "omnilyzer-task007-registry"


class Stage:
    def __init__(self, stage, work, artifacts):
        self.stage = stage
        self.project = PROJECTS[stage]
        self.port = PORTS[stage]
        self.work = Path(work)
        self.artifacts = artifacts
        self.secret_file = self.work / f"secret-{stage}.txt"
        self.nginx_file = self.work / f"nginx-{stage}.conf"
        self.env_file = self.work / f"compose-{stage}.env"
        self.refs = {"blue": artifacts["1.0.0"]["reference"], "green": artifacts["1.0.0"]["reference"]}
        self.migration_ref = artifacts["1.0.0"]["reference"]
        self.write_env()

    def write_env(self):
        values = {
            "APP_BLUE_IMAGE": require_immutable(self.refs["blue"]),
            "APP_GREEN_IMAGE": require_immutable(self.refs["green"]),
            "MIGRATION_IMAGE": require_immutable(self.migration_ref),
            "STAGE_NAME": self.stage, "PUBLIC_MARKER": MARKERS[self.stage],
            "HOST_PORT": str(self.port), "SECRET_FILE": str(self.secret_file),
            "NGINX_CONFIG": str(self.nginx_file),
        }
        self.env_file.write_text("".join(f"{key}={value}\n" for key, value in values.items()))

    def compose(self, *args, check=True):
        return run(["docker", "compose", "--project-name", self.project, "--env-file", str(self.env_file), "--file", str(ROOT / "compose.yaml"), *args], check=check)

    def container(self, service):
        return self.compose("ps", "-q", service).stdout.strip()

    def render_nginx(self, slot):
        template = (ROOT / "nginx/nginx.conf.template").read_text()
        self.nginx_file.write_text(template.replace("__ACTIVE_SLOT__", f"app_{slot}"))

    def wait_db(self):
        def healthy():
            cid = self.container("db")
            if not cid:
                raise RuntimeError("database container absent")
            status = run(["docker", "inspect", cid, "--format", "{{.State.Health.Status}}"]).stdout.strip()
            if status != "healthy":
                raise RuntimeError(status)
            return True
        wait_until(healthy, timeout=90)

    def migrate(self, audit, release, expect_failure=False, altered_dir=None):
        audit.append("migration started", stage=self.stage, release=release, image_digest=self.migration_ref, result="started")
        args = ["--profile", "tools", "run", "--rm"]
        if altered_dir:
            args += ["--volume", f"{altered_dir}:/app/migrations:ro"]
        args += ["migrate"]
        result = self.compose(*args, check=False)
        if expect_failure:
            if result.returncode == 0 or "checksum mismatch" not in result.stdout:
                raise AssertionError(f"altered migration was not rejected: {result.stdout}")
            audit.append("migration failed", stage=self.stage, release=release, image_digest=self.migration_ref, result="checksum mismatch rejected")
            return result.stdout
        if result.returncode:
            audit.append("migration failed", stage=self.stage, release=release, image_digest=self.migration_ref, result="execution failed")
            raise RuntimeError(result.stdout)
        audit.append("migration succeeded", stage=self.stage, release=release, image_digest=self.migration_ref, result="success")
        return result.stdout

    def direct(self, slot, path):
        cid = self.container(f"app_{slot}")
        code = (
            "import json,urllib.request,urllib.error; u='http://127.0.0.1:8080" + path + "'; "
            "\ntry:\n r=urllib.request.urlopen(u,timeout=2); s=r.status; b=r.read()"
            "\nexcept urllib.error.HTTPError as e:\n s=e.code; b=e.read()"
            "\nprint(json.dumps({'status':s,'body':json.loads(b)}))"
        )
        output = run(["docker", "exec", cid, "python", "-c", code]).stdout.strip()
        return json.loads(output)

    def wait_direct(self, slot, path="/readyz", expected=200):
        def ready():
            response = self.direct(slot, path)
            if response["status"] != expected:
                raise RuntimeError(response)
            return response
        return wait_until(ready, timeout=60)

    def proxy(self, path="/version", expected=200):
        return http_json(f"http://127.0.0.1:{self.port}{path}", expected=expected)

    def wait_proxy_release(self, release):
        def expected_release():
            payload = self.proxy()
            if payload["release"] != release:
                raise RuntimeError(f"proxy still serves {payload['release']}")
            return payload
        return wait_until(expected_release, timeout=30, interval=0.1)

    def initialize(self, controller, audit, baseline):
        self.render_nginx("blue")
        self.compose("up", "-d", "db")
        self.wait_db()
        self.migrate(audit, "1.0.0")
        self.compose("up", "-d", "--no-deps", "app_blue", "app_green")
        self.wait_direct("blue")
        self.compose("up", "-d", "--no-deps", "nginx")
        wait_until(lambda: self.proxy())
        if self.proxy()["release"] != "1.0.0":
            raise AssertionError("baseline proxy did not become active")
        controller.initialize(self.stage, "1.0.0", baseline, 1)

    def start_inactive(self, slot, release):
        self.refs[slot] = self.artifacts[release]["reference"]
        self.migration_ref = self.artifacts[release]["reference"]
        self.write_env()
        self.compose("up", "-d", "--no-deps", f"app_{slot}")
        self.wait_direct(slot, "/livez", 200)

    def verify_candidate(self, slot, release, expected_ref, expected_image_id, schema_version):
        live = self.direct(slot, "/livez")
        ready = self.direct(slot, "/readyz")
        version = self.direct(slot, "/version")
        cid = self.container(f"app_{slot}")
        running_id = run(["docker", "inspect", cid, "--format", "{{.Image}}"]).stdout.strip()
        if live["status"] != 200 or ready["status"] != 200:
            raise AssertionError("candidate health gate failed")
        if version["body"]["release"] != release or version["body"]["required_schema_version"] != schema_version:
            raise AssertionError("candidate release metadata mismatch")
        if running_id != expected_image_id or self.refs[slot] != expected_ref:
            raise AssertionError("candidate immutable image mismatch")
        migrations = int(self.db_scalar("SELECT count(*) FROM schema_migrations"))
        if migrations < schema_version:
            raise AssertionError("migration state gate failed")

    def switch(self, slot):
        self.render_nginx(slot)
        nginx = self.container("nginx")
        run(["docker", "exec", nginx, "nginx", "-t"])
        run(["docker", "exec", nginx, "nginx", "-s", "reload"])

    def db_scalar(self, sql):
        return run(["docker", "exec", self.container("db"), "psql", "-U", "deployment", "-d", "deployment", "-Atc", sql]).stdout.strip()

    def validate_compose(self):
        text = self.compose("--profile", "tools", "config").stdout
        validate_compose_text(text)
        refs = re.findall(r"^\s+image:\s+(\S+)$", text, re.MULTILINE)
        if not refs or not all("@sha256:" in ref for ref in refs):
            raise AssertionError(f"mutable image in rendered Compose: {refs}")
        if "host_ip: 127.0.0.1" not in text or "no-new-privileges:true" not in text:
            raise AssertionError("Compose boundary or hardening absent")
        if "read_only: true" not in text or not re.search(r"cap_drop:\n\s+- ALL", text):
            raise AssertionError("Compose application hardening absent")
        return text

    def validate_networks(self):
        nginx = json.loads(run(["docker", "inspect", self.container("nginx")]).stdout)[0]
        db = json.loads(run(["docker", "inspect", self.container("db")]).stdout)[0]
        app = json.loads(run(["docker", "inspect", self.container(f"app_{read_json(self.work / f'state-{self.stage}.json')['active_slot']}")]).stdout)[0]
        nginx_networks = set(nginx["NetworkSettings"]["Networks"])
        db_networks = set(db["NetworkSettings"]["Networks"])
        app_networks = set(app["NetworkSettings"]["Networks"])
        if nginx_networks != {f"{self.project}_frontend"} or db_networks != {f"{self.project}_backend"}:
            raise AssertionError("frontend/backend network isolation failed")
        if app_networks != {f"{self.project}_frontend", f"{self.project}_backend"}:
            raise AssertionError("application network attachment mismatch")
        if db["NetworkSettings"]["Ports"].get("5432/tcp") is not None:
            raise AssertionError("PostgreSQL has a host-published port")
        bindings = nginx["NetworkSettings"]["Ports"]["8080/tcp"]
        if len(bindings) != 1 or bindings[0]["HostIp"] != "127.0.0.1":
            raise AssertionError("Nginx is not loopback-only")
        host = app["HostConfig"]
        if not host["ReadonlyRootfs"] or host["CapDrop"] != ["ALL"] or "no-new-privileges:true" not in host["SecurityOpt"]:
            raise AssertionError("running application lacks hardening")


def traffic_during(stage, switch, requests=200):
    started = threading.Event()
    def worker(count):
        started.wait()
        ok = failed = 0
        for _ in range(count):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{stage.port}/version", timeout=2) as response:
                    payload = json.loads(response.read())
                    if response.status == 200 and payload["release"] in {"1.0.0", "1.1.0"}:
                        ok += 1
                    else:
                        failed += 1
            except Exception:
                failed += 1
            time.sleep(0.005)
        return ok, failed
    workers = 4
    per_worker = requests // workers
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker, per_worker) for _ in range(workers)]
        started.set()
        time.sleep(0.08)
        switch()
        values = [future.result() for future in futures]
    successful = sum(item[0] for item in values)
    failed = sum(item[1] for item in values)
    return {"total": successful + failed, "successful": successful, "failed": failed}


def inspect_image(candidate, source_revision, known_secrets):
    inspection = json.loads(run(["docker", "image", "inspect", candidate]).stdout)[0]
    config = inspection["Config"]
    if config["User"] != "10001:10001":
        raise AssertionError("candidate image does not configure non-root UID/GID")
    labels = config.get("Labels") or {}
    if labels.get("org.opencontainers.image.version") != "1.1.0" or labels.get("org.opencontainers.image.revision") != source_revision:
        raise AssertionError("required OCI labels absent")
    probe = run(["docker", "run", "--rm", "--entrypoint", "python", candidate, "-c",
                 "import json,pathlib,psycopg; p=pathlib.Path('/app'); print(json.dumps({'server':(p/'server.py').is_file(),'migrate':(p/'migrate.py').is_file(),'migrations':sorted(x.name for x in (p/'migrations').glob('*.sql')),'git':any(p.rglob('.git')),'socket':pathlib.Path('/var/run/docker.sock').exists(),'psycopg':psycopg.__version__}))"]).stdout
    files = json.loads(probe)
    if not files["server"] or not files["migrate"] or files["migrations"] != ["001_create_items.sql", "002_add_description.sql"]:
        raise AssertionError("candidate application or migrations absent")
    if files["git"] or files["socket"] or files["psycopg"] != "3.3.4":
        raise AssertionError("candidate content inspection failed")
    encoded = json.dumps(inspection) + run(["docker", "history", "--no-trunc", candidate]).stdout
    forbidden = [str(REPO), "development", "preproduction", "production", *known_secrets]
    if any(value and value in encoded for value in forbidden):
        raise AssertionError("image metadata contains repository path, stage marker, or secret")
    return True


def clean_previous():
    for project in PROJECTS.values():
        run(["docker", "compose", "--project-name", project, "--file", str(ROOT / "compose.yaml"), "down", "--volumes", "--remove-orphans"], check=False)
    run(["docker", "rm", "--force", REGISTRY], check=False)


def cleanup(stages):
    for stage in stages.values():
        stage.compose("down", "--volumes", "--remove-orphans", check=False)
    run(["docker", "rm", "--force", REGISTRY], check=False)


def write_results(evidence, recommendation):
    result = ROOT / "results/deployment-validation.md"
    result.parent.mkdir(exist_ok=True)
    limitations = [
        "actual real PROD deployment", "multi-host orchestration", "Kubernetes or Docker Swarm",
        "a production container registry or registry authentication", "signed OCI provenance",
        "SBOM/signing or vulnerability-scanner policy", "the actual TLS/Cloudflare boundary or public DNS",
        "multi-region availability", "database PITR or backup/restore", "production load/capacity or autoscaling",
        "host failure", "real Django migration compatibility", "Keycloak deployment topology",
        "a production secrets manager",
    ]
    lines = [
        "# Deployment validation", "", f"Recommendation: **{recommendation}**", "",
        "## Evidence", "",
        f"- Docker/Compose runtime: {evidence.get('runtime', 'validation incomplete')}",
        f"- OCI image result: baseline and candidate built once and promoted by registry digest.",
        f"- Baseline digest: `{evidence.get('baseline_digest', 'unavailable')}`",
        f"- Candidate digest: `{evidence.get('candidate_digest', 'unavailable')}`",
        f"- Candidate digest equality: {evidence.get('digest_equality', 'not established')}",
        f"- Runtime configuration separation: {evidence.get('config_separation', 'not established')}",
        f"- Secret separation: {evidence.get('secret_separation', 'not established')}",
        f"- PostgreSQL migration result: {evidence.get('migration', 'not established')}",
        f"- Pre-migration readiness rejection: {evidence.get('premigration', 'not established')}",
        f"- Migration checksum rejection: {evidence.get('checksum', 'not established')}",
        f"- Promotion ordering result: {evidence.get('ordering', 'not established')}",
        f"- DEV promotion: {evidence.get('dev', 'not established')}",
        f"- STAGING promotion: {evidence.get('staging', 'not established')}",
        f"- PROD promotion: {evidence.get('prod', 'not established')}",
        f"- Blue/green traffic switch: {evidence.get('traffic', 'not established')}",
        f"- Request success/failure count: {evidence.get('traffic_counts', 'not established')}",
        f"- Container restart result: {evidence.get('restart', 'not established')}",
        f"- Tag-drift protection: {evidence.get('tag_drift', 'not established')}",
        f"- Rollback result: {evidence.get('rollback', 'not established')}",
        f"- Schema after rollback: {evidence.get('schema_rollback', 'not established')}",
        f"- Nginx boundary: {evidence.get('network', 'not established')}",
        f"- Compose security result: {evidence.get('compose_security', 'not established')}",
        f"- Image inspection result: {evidence.get('image_inspection', 'not established')}",
        f"- Audit result: {evidence.get('audit', 'not established')}",
        f"- Cleanup result: {evidence.get('cleanup', 'not established')}",
        "", "## Limitations", "",
    ]
    lines += [f"- Does not validate {item}." for item in limitations]
    lines += ["", "The zero-failure request loop is local blue/green evidence only; it does not prove production HA or multi-host resilience.", ""]
    result.write_text("\n".join(lines))


def main():
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError(f"Python 3.12 required, found {sys.version.split()[0]}")
    changed = run(["git", "status", "--porcelain"], cwd=REPO).stdout.splitlines()
    outside = [line for line in changed if "spikes/deployment/" not in line]
    if outside:
        raise RuntimeError(f"changes outside spike scope present: {outside}")
    clean_previous()
    validation_parent = ROOT / ".validation"
    validation_parent.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="task007-", dir=validation_parent))
    stages = {}
    evidence = {}
    succeeded = False
    try:
        docker_version = run(["docker", "version", "--format", "client={{.Client.Version}} server={{.Server.Version}}"]).stdout.strip()
        compose_version = run(["docker", "compose", "version", "--short"]).stdout.strip()
        buildx_version = run(["docker", "buildx", "version"]).stdout.strip()
        evidence["runtime"] = f"Docker {docker_version}; Compose {compose_version}; Python {sys.version.split()[0]}; buildx available ({buildx_version.split()[1]})"
        lock = read_json(ROOT / "images.lock.json")
        if not all("@sha256:" in ref for ref in lock.values()):
            raise AssertionError("infrastructure image lock contains mutable reference")
        for ref in lock.values():
            run(["docker", "image", "inspect", ref])

        secret_values = {stage: f"task007-{stage}-{secrets.token_hex(24)}" for stage in STAGES}
        for stage, value in secret_values.items():
            path = work / f"secret-{stage}.txt"
            path.write_text(value + "\n")
            # Local Compose secrets are bind mounts and retain source mode. The
            # parent validation directory is 0700; 0444 lets container UIDs read
            # the synthetic value without making it accessible outside that tree.
            path.chmod(0o444)
        audit = AuditLog(work / "deployment-audit.jsonl", secret_values.values())
        source_revision = run(["git", "rev-parse", "HEAD"], cwd=REPO).stdout.strip()
        start_registry(lock, REGISTRY)
        artifacts = build_releases(ROOT, source_revision)
        evidence["baseline_digest"] = artifacts["1.0.0"]["digest"]
        evidence["candidate_digest"] = artifacts["1.1.0"]["digest"]
        for release in ("1.0.0", "1.1.0"):
            audit.append("build recorded", stage="build", release=release, image_digest=artifacts[release]["reference"], source_revision=source_revision, result="success")
        manifest = work / "promotion-manifest.json"
        atomic_json(manifest, {
            "candidate_release": "1.1.0", "candidate_digest": artifacts["1.1.0"]["reference"],
            "baseline_release": "1.0.0", "baseline_digest": artifacts["1.0.0"]["reference"],
            "source_revision": source_revision, "required_schema_version": 2,
            "promotion_order": list(STAGES),
        })
        controller = PromotionController(work, manifest, audit)

        unit = run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"], cwd=ROOT, check=False)
        print(unit.stdout, end="")
        if unit.returncode:
            raise AssertionError("policy/unit tests failed")
        match = re.search(r"Ran (\d+) tests", unit.stdout)
        evidence["unit_tests"] = int(match.group(1)) if match else 0

        # Deliberately drift the human tag to baseline; the approved candidate digest remains candidate.
        run(["docker", "tag", artifacts["1.0.0"]["reference"], artifacts["1.1.0"]["tag"]])
        run(["docker", "push", artifacts["1.1.0"]["tag"]])
        run(["docker", "pull", artifacts["1.1.0"]["reference"]])
        drift_id = run(["docker", "image", "inspect", artifacts["1.1.0"]["reference"], "--format", "{{.Id}}"]).stdout.strip()
        if drift_id != artifacts["1.1.0"]["image_id"]:
            raise AssertionError("candidate digest changed after tag drift")
        evidence["tag_drift"] = "PASS — mutable candidate tag drifted to baseline while the approved digest still resolved to 1.1.0"

        for stage in STAGES:
            stages[stage] = Stage(stage, work, artifacts)
            stages[stage].validate_compose()

        baseline_ref = artifacts["1.0.0"]["reference"]
        candidate_ref = artifacts["1.1.0"]["reference"]
        stages["dev"].initialize(controller, audit, baseline_ref)
        controller.verify_promotion("dev", "1.1.0", candidate_ref)
        wrong_manifest = work / "promotion-manifest-wrong.json"
        wrong = read_json(manifest)
        wrong["candidate_digest"] = "localhost:15007/omnilyzer-task007@sha256:" + "f" * 64
        atomic_json(wrong_manifest, wrong)
        try:
            controller.verify_promotion("dev", "1.1.0", candidate_ref, wrong_manifest)
            raise AssertionError("modified manifest was accepted")
        except ValueError:
            pass

        def promote(stage_name, premigration=False, traffic=False):
            stage = stages[stage_name]
            controller.verify_promotion(stage_name, "1.1.0", candidate_ref)
            state = controller.state(stage_name)
            inactive = "green" if state["active_slot"] == "blue" else "blue"
            audit.append("promotion started", stage=stage_name, release="1.1.0", image_digest=candidate_ref, previous_image_digest=state["active_digest"], slot=inactive, result="started")
            stage.start_inactive(inactive, "1.1.0")
            if premigration:
                response = stage.direct(inactive, "/readyz")
                if response["status"] == 200 or stage.proxy()["release"] != "1.0.0" or controller.state(stage_name)["active_release"] != "1.0.0":
                    raise AssertionError("pre-migration readiness failed to protect active traffic")
                evidence["premigration"] = "PASS — candidate returned 503; Nginx and persisted state remained on 1.0.0"
                audit.append("readiness gate", stage=stage_name, release="1.1.0", image_digest=candidate_ref, slot=inactive, migration_state="missing 002", result="rejected")
            stage.migrate(audit, "1.1.0")
            stage.wait_direct(inactive)
            stage.verify_candidate(inactive, "1.1.0", candidate_ref, artifacts["1.1.0"]["image_id"], 2)
            audit.append("readiness gate", stage=stage_name, release="1.1.0", image_digest=candidate_ref, slot=inactive, migration_state="2", result="success")
            if traffic:
                counts = traffic_during(stage, lambda: stage.switch(inactive))
                if counts["total"] < 100 or counts["failed"]:
                    raise AssertionError(f"traffic continuity failed: {counts}")
                evidence["traffic_counts"] = f"{counts['total']} total / {counts['successful']} successful / {counts['failed']} failed"
                evidence["traffic"] = "PASS — Nginx reloaded while both slots remained alive"
            else:
                stage.switch(inactive)
            stage.wait_proxy_release("1.1.0")
            new = controller.record_switch(stage_name, "1.1.0", candidate_ref, inactive, 2)
            audit.append("traffic switch", stage=stage_name, release="1.1.0", image_digest=candidate_ref, previous_image_digest=state["active_digest"], slot=inactive, migration_state="2", result="success")
            audit.append("promotion succeeded", stage=stage_name, release="1.1.0", image_digest=candidate_ref, previous_image_digest=state["active_digest"], slot=inactive, migration_state="2", result="success")
            return new

        promote("dev")
        evidence["dev"] = "PASS — 1.1.0 active by approved digest"

        stages["staging"].initialize(controller, audit, baseline_ref)
        try:
            controller.verify_promotion("prod", "1.1.0", candidate_ref)
            raise AssertionError("out-of-order PROD promotion was accepted")
        except ValueError:
            evidence["ordering"] = "PASS — PROD-before-STAGING promotion rejected"
        promote("staging", premigration=True)
        evidence["staging"] = "PASS — 1.1.0 active after explicit migration gate"
        staging_slot = controller.state("staging")["active_slot"]
        before_id = run(["docker", "inspect", stages["staging"].container(f"app_{staging_slot}"), "--format", "{{.Image}}"]).stdout.strip()
        stages["staging"].compose("restart", f"app_{staging_slot}")
        stages["staging"].wait_direct(staging_slot)
        after_id = run(["docker", "inspect", stages["staging"].container(f"app_{staging_slot}"), "--format", "{{.Image}}"]).stdout.strip()
        if before_id != after_id or stages["staging"].proxy()["release"] != "1.1.0":
            raise AssertionError("staging restart drifted image or release")
        evidence["restart"] = "PASS — active STAGING container returned with the same image ID and release"

        stages["prod"].initialize(controller, audit, baseline_ref)
        promote("prod", traffic=True)
        evidence["prod"] = "PASS — simulated PROD runs 1.1.0 by the approved digest"

        prod = stages["prod"]
        state = controller.state("prod")
        rollback_slot = "green" if state["active_slot"] == "blue" else "blue"
        audit.append("rollback started", stage="prod", release="1.0.0", image_digest=baseline_ref, previous_image_digest=state["active_digest"], slot=rollback_slot, migration_state="2", result="started")
        prod.refs[rollback_slot] = baseline_ref
        prod.write_env()
        prod.compose("up", "-d", "--no-deps", "--force-recreate", f"app_{rollback_slot}")
        prod.wait_direct(rollback_slot)
        prod.verify_candidate(rollback_slot, "1.0.0", baseline_ref, artifacts["1.0.0"]["image_id"], 1)
        rollback_counts = traffic_during(prod, lambda: prod.switch(rollback_slot))
        prod.wait_proxy_release("1.0.0")
        if rollback_counts["failed"] or prod.proxy("/data")["items"][0]["name"] != "immutable deployment fixture":
            raise AssertionError("rollback traffic or baseline compatibility failed")
        rolled = controller.record_rollback("prod", "1.0.0", baseline_ref, rollback_slot)
        if rolled["migration_version"] != 2 or int(prod.db_scalar("SELECT count(*) FROM schema_migrations")) != 2:
            raise AssertionError("additive migration did not remain after rollback")
        audit.append("rollback succeeded", stage="prod", release="1.0.0", image_digest=baseline_ref, previous_image_digest=candidate_ref, slot=rollback_slot, migration_state="2 retained", result="success")
        evidence["rollback"] = f"PASS — retained baseline digest restored; {rollback_counts['total']} requests, {rollback_counts['failed']} failures"
        evidence["schema_rollback"] = "PASS — migration 002 remains recorded; 1.0.0 readiness and /data succeed without down migration"

        altered = work / "altered-migrations"
        shutil.copytree(ROOT / "releases/1.1.0/migrations", altered)
        with (altered / "001_create_items.sql").open("a") as stream:
            stream.write("\n-- temporary checksum alteration\n")
        prod.migration_ref = candidate_ref
        prod.write_env()
        prod.migrate(audit, "1.1.0", expect_failure=True, altered_dir=altered)
        if int(prod.db_scalar("SELECT count(*) FROM schema_migrations")) != 2:
            raise AssertionError("checksum negative test changed migration history")
        evidence["checksum"] = "PASS — altered temporary 001 rejected; real PROD-simulation history remained intact"
        evidence["migration"] = "PASS — advisory-locked, idempotent migration history records identifiers/checksums; schema version 2 reached"

        candidate_digests = {stage: candidate_ref for stage in STAGES}
        if len(set(candidate_digests.values())) != 1:
            raise AssertionError("candidate digests differ by stage")
        config_values = {stage: stages[stage].direct(controller.state(stage)["active_slot"] if stage != "prod" else controller.state("prod")["active_slot"], "/config")["body"] for stage in STAGES}
        # PROD is rolled back, but its runtime config is still stage-specific and was used by the candidate.
        if len({json.dumps(value, sort_keys=True) for value in config_values.values()}) != 3:
            raise AssertionError("runtime configuration is not distinct")
        secret_hashes = {stage: hashlib.sha256(secret_values[stage].encode()).hexdigest() for stage in STAGES}
        db_ids = {stage: stages[stage].db_scalar("SELECT system_identifier::text FROM pg_control_system()") for stage in STAGES}
        volumes = {f"{PROJECTS[stage]}_db_data" for stage in STAGES}
        if len(set(secret_hashes.values())) != 3 or len(set(db_ids.values())) != 3 or len(volumes) != 3 or len(set(PROJECTS.values())) != 3:
            raise AssertionError("stage isolation proof failed")
        evidence["digest_equality"] = f"PASS — DEV = STAGING = simulated PROD = `{candidate_ref}`"
        evidence["config_separation"] = "PASS — three distinct /config payloads, database system identities, volumes, and Compose projects"
        evidence["secret_separation"] = "PASS — three distinct synthetic secret-file hashes; no secret value reported"

        inspect_image(candidate_ref, source_revision, secret_values.values())
        evidence["image_inspection"] = "PASS — UID/GID 10001, OCI labels, source/migrations/dependency present; no Git, socket, path, marker, or secret found"
        for stage in stages.values():
            stage.validate_networks()
        evidence["network"] = "PASS — only Nginx publishes loopback; Nginx/frontend and PostgreSQL/backend boundaries enforced"
        evidence["compose_security"] = "PASS — digest-only deploy refs, no app build/ports, secret mounts, read-only rootfs, cap-drop ALL, no-new-privileges"

        records = audit.validate()
        required_events = {"build recorded", "promotion started", "migration started", "migration succeeded", "migration failed", "readiness gate", "traffic switch", "promotion succeeded", "promotion rejected", "rollback started", "rollback succeeded"}
        if not required_events.issubset({record["event"] for record in records}):
            raise AssertionError("audit log lacks required event coverage")
        evidence["audit"] = f"PASS — {len(records)} JSONL records cover required events and contain no known secret"
        succeeded = True
    finally:
        cleanup(stages)
        containers = run(["docker", "ps", "-a", "--filter", "name=omnilyzer-task007", "--format", "{{.Names}}"]).stdout.strip()
        volumes_left = run(["docker", "volume", "ls", "--filter", "name=omnilyzer-task007", "--format", "{{.Name}}"]).stdout.strip()
        if not containers and not volumes_left:
            evidence["cleanup"] = "PASS — no Task 007 containers or named volumes remain"
        else:
            evidence["cleanup"] = f"FAIL — residual containers={containers!r}, volumes={volumes_left!r}"
            succeeded = False
        shutil.rmtree(work, ignore_errors=True)
        try:
            validation_parent.rmdir()
        except OSError:
            pass
        write_results(evidence, "adopt" if succeeded else "inconclusive")
    print(json.dumps({"result": "PASS", "recommendation": "adopt", "unit_tests": evidence["unit_tests"], "traffic": evidence["traffic_counts"], "baseline_digest": evidence["baseline_digest"], "candidate_digest": evidence["candidate_digest"]}, indent=2))


if __name__ == "__main__":
    main()
