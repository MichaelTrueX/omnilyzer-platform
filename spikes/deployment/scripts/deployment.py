import json
from pathlib import Path

from common import STAGES, atomic_json, read_json, require_immutable


class PromotionController:
    def __init__(self, root, manifest, audit):
        self.root = Path(root)
        self.manifest = Path(manifest)
        self.audit = audit

    def state_path(self, stage):
        return self.root / f"state-{stage}.json"

    def state(self, stage):
        return read_json(self.state_path(stage))

    def initialize(self, stage, release, digest, migration_version=1):
        require_immutable(digest)
        state = {
            "active_slot": "blue", "active_release": release, "active_digest": digest,
            "previous_release": None, "previous_digest": None,
            "migration_version": migration_version, "promotion_succeeded": False,
        }
        atomic_json(self.state_path(stage), state)
        return state

    def verify_promotion(self, stage, release, digest, manifest_path=None):
        manifest = read_json(manifest_path or self.manifest)
        require_immutable(digest)
        if release != manifest["candidate_release"] or digest != manifest["candidate_digest"]:
            self.audit.append("promotion rejected", stage=stage, release=release, image_digest=digest, result="manifest mismatch")
            raise ValueError("candidate does not match promotion manifest")
        index = STAGES.index(stage)
        if index and not self.state(STAGES[index - 1])["promotion_succeeded"]:
            self.audit.append("promotion rejected", stage=stage, release=release, image_digest=digest, result="promotion order")
            raise ValueError(f"{stage} promotion requires successful {STAGES[index - 1]} promotion")
        return manifest

    def record_switch(self, stage, release, digest, slot, migration_version):
        old = self.state(stage)
        new = {
            "active_slot": slot, "active_release": release, "active_digest": digest,
            "previous_release": old["active_release"], "previous_digest": old["active_digest"],
            "migration_version": migration_version, "promotion_succeeded": True,
        }
        atomic_json(self.state_path(stage), new)
        return new

    def record_rollback(self, stage, release, digest, slot):
        old = self.state(stage)
        if digest != old["previous_digest"] or release != old["previous_release"]:
            raise ValueError("rollback artifact is not the persisted previous release")
        new = {
            "active_slot": slot, "active_release": release, "active_digest": digest,
            "previous_release": old["active_release"], "previous_digest": old["active_digest"],
            "migration_version": old["migration_version"], "promotion_succeeded": True,
        }
        atomic_json(self.state_path(stage), new)
        return new


def validate_compose_text(text):
    if "build:" in text:
        raise ValueError("deployment Compose configuration contains build directive")
    if "0.0.0.0" in text:
        raise ValueError("non-loopback listener present")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("image:") and ("app_" in line or "migrate" in line):
            require_immutable(stripped.split(None, 1)[1])
    return True

