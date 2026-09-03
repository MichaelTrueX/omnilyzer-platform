#!/usr/bin/env python3
"""Authoritative Task 008D publisher immutability probe; never executes images."""

from __future__ import annotations

import argparse
from pathlib import Path

from zot_oci_common import MANIFEST_TYPE, RegistryClient, digest, validate_handoff, verify_baseline


def row(summary: Path, name: str, value: str) -> None:
    with summary.open("a", encoding="utf-8") as stream:
        stream.write(f"| {name} | {value} |\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--handoff", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    record = validate_handoff(args.handoff, args.source_commit, args.tag)
    baseline, replacement = record["baseline"], record["replacement"]
    args.summary.write_text("## Task 008D zot publisher probe\n\n| Property | Result |\n|---|---|\n")
    client = RegistryClient(args.registry, args.token_file)
    client.request("GET", "/v2/", expected={200})
    row(args.summary, "GitHub OIDC authentication", "PASS")

    for item in (baseline,):
        client.ensure_blob(record["repository"], item["config_digest"], item["bytes"]["config"])
        client.ensure_blob(record["repository"], item["layer_digest"], item["bytes"]["layer"])
    row(args.summary, "Publisher create blobs", "PASS")
    status, _, headers = client.request(
        "PUT", f"/v2/{record['repository']}/manifests/{record['tag']}",
        body=baseline["bytes"]["manifest"], headers={"Content-Type": MANIFEST_TYPE}, expected={201},
    )
    returned = headers.get("Docker-Content-Digest")
    if returned is not None and returned != baseline["manifest_digest"]:
        raise RuntimeError("baseline registry digest disagrees with local digest")
    row(args.summary, "Baseline manifest PUT", f"PASS (HTTP {status})")
    row(args.summary, "Baseline digest A", baseline["manifest_digest"])
    verify_baseline(client, record)
    row(args.summary, "Publisher read by tag and digest", "PASS")

    for kind in ("config", "layer"):
        client.ensure_blob(record["repository"], replacement[f"{kind}_digest"], replacement["bytes"][kind])
    replace_status, _, _ = client.request(
        "PUT", f"/v2/{record['repository']}/manifests/{record['tag']}",
        body=replacement["bytes"]["manifest"], headers={"Content-Type": MANIFEST_TYPE},
    )
    row(args.summary, "Same-tag replacement HTTP", str(replace_status))
    tag_error = None
    try:
        tag_manifest, _ = client.manifest(record["repository"], record["tag"])
        if tag_manifest != baseline["bytes"]["manifest"] or digest(tag_manifest) != baseline["manifest_digest"]:
            raise RuntimeError("tag no longer resolves to baseline digest A")
    except RuntimeError as error:
        tag_error = error
    if replace_status == 403 and tag_error is None:
        tag_result = "PASS"
    elif replace_status == 201 or tag_error is not None:
        tag_result = "FAIL"
    else:
        tag_result = "INCONCLUSIVE"
    row(args.summary, "Same-tag update prohibition", tag_result)
    row(args.summary, "OCI tag immutability", tag_result)
    row(args.summary, "Tag still resolves to digest A", "PASS" if tag_error is None else "FAIL")

    integrity_error = None
    try:
        verify_baseline(client, record, by_tag=False)
    except RuntimeError as error:
        integrity_error = error
    original_result = "PASS" if integrity_error is None else "FAIL"
    row(args.summary, "Original digest retention", original_result)

    delete_results: list[str] = []
    for label, reference in (("digest", baseline["manifest_digest"]), ("tag", record["tag"])):
        delete_status, _, _ = client.request(
            "DELETE", f"/v2/{record['repository']}/manifests/{reference}"
        )
        classification = "PASS" if delete_status == 403 else (
            "FAIL" if 200 <= delete_status < 300 else "INCONCLUSIVE"
        )
        delete_results.append(classification)
        row(args.summary, f"Publisher DELETE {label}", f"{classification} (HTTP {delete_status})")
    delete_result = "PASS" if delete_results == ["PASS", "PASS"] else (
        "FAIL" if "FAIL" in delete_results else "INCONCLUSIVE"
    )
    row(args.summary, "Publisher DELETE prohibition", delete_result)

    post_error = None
    try:
        verify_baseline(client, record, by_tag=False)
    except RuntimeError as error:
        post_error = error
    post_result = "PASS" if post_error is None else "FAIL"
    row(args.summary, "Post-denial integrity", post_result)
    row(args.summary, "Exact-digest rollback readiness", post_result)
    if integrity_error is not None:
        raise RuntimeError(f"baseline changed after replacement attempt: {integrity_error}")
    if post_error is not None:
        raise RuntimeError(f"baseline changed after denial probes: {post_error}")
    if tag_result != "PASS" or delete_result != "PASS":
        raise RuntimeError("zot publisher authorization did not produce exact HTTP 403 denials")


if __name__ == "__main__":
    main()
