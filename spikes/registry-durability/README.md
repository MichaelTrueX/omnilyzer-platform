# Task 012A: zot Registry Durability and Fresh Restore

## Hypothesis

A cold, integrity-manifested backup of a synthetic, filesystem-backed zot `v2.1.20` registry can be restored into a fresh empty zot instance so that both a current OCI release and an approved rollback release remain retrievable by their exact original manifest digests with byte-identical manifest, config, and layer content. Corrupted, incomplete, unexpected, or unsafe backup content must be rejected before restored storage is trusted.

This spike validates durability and recovery only. It does not reopen the registry selection in ADR 0010 or the immutable exact-digest deployment requirement in ADR 0006.

## Acceptance criteria

`TASK 012A — PASS` requires all of the following:

- `/usr/local/bin/zot`, or `ZOT_BIN` when explicitly overridden, reports `v2.1.20` and hashes to `a32e42d042d1f17b5b1317e55cc1a415a744c873dcd05c25c56b665478258bcb`;
- both zot processes bind only a dynamically allocated `127.0.0.1` port and use fresh temporary filesystem storage with `gc=false`;
- CURRENT and ROLLBACK resolve by tag and original digest before backup, and all manifest/config/layer bytes match locally calculated digests;
- source zot stops cleanly before backup;
- the complete cold backup manifest and payload verify;
- the temporary original registry storage is removed after backup verification;
- restore installs only into a new empty storage root;
- a fresh zot process retrieves both releases by tag and exact original digest with byte-identical manifest/config/layer content;
- all mandatory corruption and unsafe-archive negatives fail closed; and
- no live registry or host service is accessed.

An actual content or recovery mismatch is `FAIL`. A binary, protocol, or tooling failure that prevents classification is `INCONCLUSIVE`; it is never converted to PASS.

## Security checks

The runtime configuration is generated beneath a `TemporaryDirectory`. It contains no OIDC, credentials, Nginx, TLS, external object storage, or external URL. Authentication is intentionally outside Task 012A because Task 008D already validated zot OIDC and least-privileged ACLs; mixing authentication into this test would not strengthen the storage-recovery claim. The client accepts only an exact `http://127.0.0.1:<dynamic-port>` origin and rejects redirects or cross-origin upload locations.

The backup directory is mode `0700`; `manifest.json`, `payload.tar`, and `payload.tar.sha256` are mode `0600`. The manifest records schema, UTC creation time, exact zot version and binary SHA-256, `backup_mode = cold`, synthetic-source classification, root mode, and sorted directory/regular-file metadata including normalized relative path, size, SHA-256, and mode. It contains no absolute source path or secret.

Backup input permits directories and regular files only. It rejects symlinks, FIFOs, sockets, devices, and other special objects. The archive verifier rejects absolute paths, traversal, non-normal paths, duplicates, symlinks, hard-link aliases, special members, unmanifested or missing files, directory-set changes, size/mode/digest mismatches, malformed metadata, unknown schema, wrong zot identity, and a corrupt payload.

Restore requires an existing new empty destination. It verifies the complete backup before writing, reconstructs into a separate private staging directory, verifies staged bytes, and atomically installs the staged tree. It never overwrites an existing registry. Negative restores must leave their target unchanged and are not reported as partially successful.

## Test approach

Run from the repository root:

```bash
python3 -m unittest discover -s spikes/registry-durability/tests -p 'test_*.py'
python3 spikes/registry-durability/validate_zot_recovery.py
python3 -m unittest discover -s spikes/registry-durability/tests -p 'test_evidence.py'
```

The validator performs this sequence:

1. verify exact zot version and binary SHA-256;
2. deterministically build harmless, non-executable CURRENT (`task012-current`) and ROLLBACK (`task012-rollback`) OCI fixtures;
3. start isolated instance A, publish both releases, and verify tag, exact digest, manifest, config, and layer bytes;
4. stop A cleanly, create and verify the cold backup, then remove only A's temporary storage;
5. prove rejection of a changed payload byte, missing file, unexpected file, truncated archive, non-empty target, traversal path, absolute path, duplicate path, and symlink member;
6. restore into fresh storage, start isolated instance B on another dynamic loopback port, and repeat all exact-byte checks; and
7. stop B and remove all subprocess/runtime temporary state on success or failure.

The synthetic fixture uses valid OCI image manifest/config/layer media types and contains one read-only text evidence file. It is never executed.

## Findings

**TASK 012A — PASS.** The machine-readable result is [`results/zot-recovery-validation.json`](results/zot-recovery-validation.json).

| Release | Tag | Manifest digest | Config digest | Layer digest |
|---|---|---|---|---|
| CURRENT | `task012-current` | `sha256:c7cb3abfa2e2f00d99acee6a9828dd76de0a74b2ad1b95abbd432828d5d563bb` | `sha256:69e1504c8918c4b0a745f15988fa6f522f000ce8cdf945c02de79264fbd3b5c2` | `sha256:6570c741c1a5c135a381936e57fcff5a7afaa840be283d8d96227a3a8786dd2c` |
| ROLLBACK | `task012-rollback` | `sha256:dea955007cc3c4212eb12179771094b2e1e2d066642f3ba85db4b697dda4ebcc` | `sha256:b84f8778476f448abc93cf2025cd38b99f026c497acc30e9b431c343e33c88b4` | `sha256:2b0f3a24df9ce504e0abb98572bf112c5b4f3e782dc77b37ad337a7985b83206` |

Both releases passed pre-backup and post-restore retrieval by tag and exact digest. Their exact manifest, config, and layer bytes survived. The original temporary source storage was removed before restore, so instance B could not depend on it. All nine mandatory negative backups/restores were rejected. This establishes **retained exact-digest recoverability after restore**; it does not establish application deployment rollback.

The recorded backup, restore, and verification durations describe this small local synthetic fixture only. They are suitability evidence, not production RTO or RPO measurements.

Task 012A proves only a tested cold-backup procedure. It does **not** prove:

- online backup consistency or continuous backup;
- production RPO or production RTO;
- off-host backup;
- backup encryption or key management;
- multi-host recovery, HA, or automated failover;
- production disaster recovery;
- object-storage durability;
- lifecycle or garbage-collection safety;
- Forgejo recovery;
- production capacity; or
- production operational ownership.

## Recommendation

Retain the accepted split-registry architecture and exact-digest deployment rules from ADRs 0010 and 0006. Use this cold procedure as narrow technical evidence that filesystem-backed zot data can be integrity-manifested and freshly restored. Before production reliance, separately design and validate encrypted off-host backup, scheduling, retention/lifecycle safety, monitoring, capacity, restore drills, operational ownership, and production recovery objectives. No new ADR is warranted by this spike alone.

## Task 012B: Forgejo Package Cold Backup and Fresh Restore

### Hypothesis and acceptance

A cold Forgejo-supported dump containing both package blobs and the SQLite metadata required to address them can be restored into a fresh isolated Forgejo instance so that previously published synthetic Generic, PyPI, and npm artifacts remain discoverable and byte-identical. Blob storage alone is not sufficient. Task 012B does not test OCI and does not reopen ADR 0010.

PASS requires all three formats to publish and retrieve before backup; a clean source shutdown; a verified dump containing database, package-storage, and configuration state; removal of the temporary source; restore into fresh empty state on a different loopback port; all three packages remaining addressable with identical SHA-256 values; and rejection of the six required damaged/incomplete backup cases.

### Security and test approach

The validator uses Forgejo `16.0.3+gitea-1.22.0`, executable `/app/gitea/gitea`, SHA-256 `6d29dca8c14a884cbca19a162fb55f06cb8b3181032cf6d175aa34b5eae2ea5b`, extracted without a network pull from the locally cached digest-pinned image `codeberg.org/forgejo/forgejo@sha256:214f4ae63ee78be1e445e58573c88dc7215e72091210852e0df94eaac1a25685`. `FORGEJO_BIN` or a host `forgejo` is preferred when present and its actual version/path/hash are recorded.

Both instances use temporary roots, package storage, repository directories, and SQLite databases on dynamic `127.0.0.1` ports. There is no OIDC, Nginx, TLS, external database/object storage, external registry, or real package data. One temporary package-scoped token is stored only in the temporary database and memory. Package payloads are deterministic, harmless, and never executed.

After exact pre-backup retrieval, Forgejo A stops cleanly. The harness invokes Forgejo's supported `dump --type tar`, then adds a small `manifest.json` and `forgejo-data.tar.sha256` integrity wrapper. Restore rejects checksum mismatch, corrupt tar data, traversal, absolute/unexpected paths, links/special members, non-empty targets, missing `forgejo-db.sql`, or missing `data/packages` content. The dump's SQL is imported into a new SQLite database; a small `unistr()` compatibility decoder bridges the newer SQLite dump syntax to Python's host SQLite. Forgejo B then serves all verification requests from restored state only.

Run:

```bash
PYTHONPATH=spikes/registry-durability python3 spikes/registry-durability/validate_forgejo_recovery.py
python3 -m unittest discover -s spikes/registry-durability/tests -p 'test_*.py'
```

### Findings

**TASK 012B — PASS.** Evidence is recorded in [`results/forgejo-recovery-validation.json`](results/forgejo-recovery-validation.json).

| Format | Artifact length | SHA-256 | Pre-backup | Post-restore |
|---|---:|---|---|---|
| Generic | 51 | `5aa2c2bd0dff40b9c8595d7e7d1059632628684b248545d1e06cff1953bfc7e4` | PASS | PASS |
| PyPI wheel | 1007 | `6dd21dfb724b49e05cd8224b8bb088188fddb6291d235dbc8eae8104a52cc5cf` | PASS | PASS |
| npm tarball | 279 | `00c345cb5bab96ed82f787c4a0f28e51bec1bd9339230c612cca4efa72360b67` | PASS | PASS |

The temporary source state was removed before restore. The restored PyPI Simple index and npm package/version metadata still addressed the exact artifacts, proving that package blobs and database metadata were recovered together. Removing either the database dump or package storage caused fail-closed rejection. Corrupt archive, checksum mismatch, traversal, and non-empty-destination negatives also passed.

This is only a synthetic local cold-backup result. It does not establish online backup, production RPO/RTO, off-host or encrypted backup, HA, disaster recovery, production capacity/ownership, Forgejo OCI recovery, or application execution safety.

### Recommendation

Retain ADR 0010 unchanged. Task 012B supplies narrow technical evidence for cold recovery of Forgejo's accepted Generic/PyPI/npm role. Production backup scheduling, encryption, off-host custody, retention, restore drills, capacity, monitoring, disaster recovery, and ownership remain separate work.
