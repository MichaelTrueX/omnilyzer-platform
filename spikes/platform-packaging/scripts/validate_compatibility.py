#!/usr/bin/env python3
from __future__ import annotations

from copy import deepcopy


def major(version):
    parts = version.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise AssertionError(f"not MAJOR.MINOR.PATCH: {version}")
    return int(parts[0])


def validate_contract_change(old_version, old_contract, new_version, new_contract):
    if major(old_version) != major(new_version):
        return True
    for field in ("publicApi", "commands"):
        removed = set(old_contract.get(field, ())) - set(new_contract.get(field, ()))
        if removed:
            raise AssertionError(f"same-major release removed {field}: {sorted(removed)}")
    if old_contract.get("governanceBaseline") != new_contract.get("governanceBaseline"):
        raise AssertionError("same-major governance baseline changed incompatibly")
    return True


def negative_contract_fixture(contract):
    broken = deepcopy(contract)
    broken["publicApi"] = broken["publicApi"][:-1]
    return broken
