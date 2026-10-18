#!/usr/bin/env python3
"""File: /home/omnigpt/repos/omnilyzer-platform/.task014-c34d-operator/c34g_installed_predecessor_preflight.py

Purpose: Root-only READ-ONLY preflight for the 41 protected Omnilyzer DEV
application files and both canonical DEV authority configurations.
Related: deployment/application_source_set.py, deployment/application_manifest.py,
deployment/broker_service_config.py, deployment/executor_service_config.py,
Task 014 C34F/C34G draft PR #190 and incident issue #182.

All expected digest values below were pinned from immutable Git objects at
176ed3a31ffcf23346639ef22ac9bcab3794f0df. No untrusted Git processes,
imports or paths are followed when running as root. No mutation, deployment,
log parsing, secret or config data output; only PASS/HOLD coarse statuses.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys

# Section 1: Closed manifest and authority constants.
EXPECTED = {
    "deployment/__init__.py": "4b3024a65dd7502693bf45012f52363aa2d00a0c9d8561dadbb4554a888c55c3",
    "deployment/audit.py": "cc7ffc1c8df7bb715b0a93fbed8264ee26d4e905b6d44e0fed50d692b6062d73",
    "deployment/blob_verifier.py": "9da8067a3a51ac9b5e3383f5a8e301a4310194b0a1209b612ea17d95ebb5bc23",
    "deployment/broker.py": "b7728fb25e0c314ad724cd63ac7edc5ec1d24e05a4737cb7af2c8310bc58c34d",
    "deployment/broker_https_ingress.py": "484b3378f27064a48393a76379249174e30780d4df39c9f4bf5554788f4dc925",
    "deployment/broker_integration.py": "8abdda62c81282c07f403bd924f4d41b35ff8d113d2bee6a66e2ff32e8339b13",
    "deployment/broker_loopback_listener.py": "ce1eb6945f25fd7e0e5fc50489b0813da57c94131a6d8100645a09a0ce13b48b",
    "deployment/broker_service_bootstrap.py": "f221e043e2daef38082627387dac1a5856de38a306716b1d2f3d4784aa872c27",
    "deployment/broker_service_config.py": "cb5aa6ebde6071a3276b218bc85759ddadc52a172bf5b6e57235429b5e1b7967",
    "deployment/broker_service_config_loader.py": "7e89e16d736fc83b1a27e1afad1bfcc923cd32d4b71ebd7b1899d3d7e50e49a5",
    "deployment/broker_service_entrypoint.py": "56e446b107ffbd67050f2612705053c0ba86f122cffefb9d622b10fd0d39c3e5",
    "deployment/controller.py": "f2c06d37b6b9fbe264c16677f699663594f62e503e0fe0072ec3eca3ce7b207f",
    "deployment/deployment_operation.py": "8042622acbad41968b736c9dcfeffe52faaf7b885ea6fa3268827ab4a3b2438a",
    "deployment/docker_runtime.py": "9bb162e1712a8ec76874c229ce1af1c8a88f527686d4a43376ca93a8b0d00b88",
    "deployment/execution.py": "1a9acb8cb85d9a271b3ec40cb6a071e734973b120e9f6061b9a1c8a3db60af4e",
    "deployment/executor.py": "55150dc7515772b322896e2c2a66d861f7d45918e6287d1cd7aadf990431a25c",
    "deployment/executor_composition.py": "65fff086559ae09d9aa244c60b17fc4bcbd585b36c58bb3c55db2fe928184005",
    "deployment/executor_listener.py": "c8644f198c0ce9362a7b01ab0b050c875237a78db610bae9c7727da6f6f47def",
    "deployment/executor_server.py": "fbeece91b8a9bab36dafcbdaaf16f76cfe248646c90ea8e8e5d4288a4952d232",
    "deployment/executor_service_bootstrap.py": "15a2e93f4d24720229f8a652b74379a81525fa9bb26223ada7a19dc8dc5713ea",
    "deployment/executor_service_config.py": "812f678e2a1a176c8aee89372d03c7d5d8ec16b6c0208331263bea3b0d210f44",
    "deployment/executor_service_config_loader.py": "48b7b0b9224b4adf5d3f1f508ea034785e05618943c4df046cefb6d4a618dcf3",
    "deployment/executor_service_entrypoint.py": "17a922f138b202ec3fb38e4c469bc404b11d997183eabe96e1b616960fad2daa",
    "deployment/identity.py": "475ac95faf25fe832cc3a6e68e68ddb3340782f8e3a93d12da1c9a98584b2cbf",
    "deployment/installation_contract.py": "79682d5f0521dc852a4fdaad76fc65894f0cc1db47342965d90d5e342633c0e1",
    "deployment/jwks.py": "3d8e8d253f31cde922eef0c662ea1ec7b84fa28d62800723d19846fdbd1ee933",
    "deployment/oci_verifier.py": "caf85eb39585ce35d5b3e5528401f78e7abe98cdcb470af55ee4dd6bdbbc30c2",
    "deployment/oidc_verifier.py": "76b0c94d9b7a415addcf4344229bdc749871eeb22bfae4d429aa3ceefdeb1feb",
    "deployment/policy.py": "be81b9836e31ec6303cfc837e41f92ac0301e67ecd4febe87be865c5d11678a5",
    "deployment/promotion.py": "dd5fdc5dfaf3734eb26bfc7dae293d0797480ab03930f3da165bed710c5cbea0",
    "deployment/registry_oidc_credentials.py": "2fcc3c86491c358b0606f0d695e6fbaaa77dc6ecf2518c99fb9c5f915b84eb80",
    "deployment/registry_promotion_composition.py": "032657e7c5cdcc07c6f241dcf446657f02fc4d8c21b60c3c738cc10421642322",
    "deployment/release_consumer.py": "82e5fee9ae837eccba02022ce7d135f39961ba004051fa0e553dd9de3c10d227",
    "deployment/replay_sqlite.py": "edac352a8730c0d7eddef06ee4e800bf750411e9114276f95b8c0c4d178823b5",
    "deployment/runtime/dev/canary-runtime.json": "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f",
    "deployment/runtime/dev/compose.yaml": "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
    "deployment/runtime/dev/nginx/nginx.conf": "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
    "deployment/state.py": "42406665fddd53e720c077e663fc9634f79e3815275883b4b6e0ec400e0b5f36",
    "deployment/state_store.py": "322de4edebd8c9f08f318c23660a1f92d8108d79b18e629352e79bd5d7fce683",
    "deployment/systemd_socket_activation.py": "25d20dddba58958d3f247d91e66b660033306bcdae72e56d5bb25174d0b0b630",
    "deployment/unix_transport.py": "db2a6b8c35bd483412d1d7fa8367cbca9aba4888b7aacc5a5fa83a7bda74d4da"
}
OLD = "176ed3a31ffcf23346639ef22ac9bcab3794f0df"
WORKFLOW = "57919c3b9aca0cb98e85bbb26460f6267d093fa9"
APP = "/opt/omnilyzer/deployment/app"
EXECUTOR = "/etc/omnilyzer/deployment/dev/executor.json"
BROKER = "/etc/omnilyzer/deployment/broker/dev.json"
MANIFEST_SHA256 = "384f5b4e4ca9849da62ab17b624137a52b9292fd3e03d03fefcbabed3bc0ee4b"
PATH_SET_SHA256 = "c846e3d863f8c651ffc2de4d3671c9b8c0631c72366a360637d9cc45f98b60ab"
DIRFLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILEFLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
SHARED = ("broker_uid", "broker_gid", "executor_uid", "executor_gid",
          "replay_group_gid", "socket_group_gid", "runtime_configuration_sha256",
          "ingress_file_sha256")
_EXECUTOR_FIELDS = frozenset({
    "schema_version", "stage", "broker_uid", "broker_gid", "executor_uid",
    "executor_gid", "replay_group_gid", "socket_group_gid", "canary_image",
    "reviewed_commit", "runtime_configuration_sha256", "ingress_file_sha256",
})
_BROKER_FIELDS = frozenset({
    "schema_version", "stage", "broker_uid", "broker_gid", "executor_uid",
    "executor_gid", "replay_group_gid", "socket_group_gid",
    "expected_workflow_sha", "cosign_version", "cosign_binary_sha256",
    "sigstore_trusted_root_sha256", "reviewed_commit",
    "runtime_configuration_sha256", "ingress_file_sha256",
})
_RUNTIME_SHA = "8978b0608a6ef434ad6818a4d654c804ecdba8cabf5dc5916658a8194e7d839f"
_INGRESS_HASHES = frozenset({
    "ac12c1958d5e65ab64a69ea58ca053d11cd664732edb20fb7dce39aabde6b3bc",
    "bfed4b9e0be612723ed545362bb80262d18dbf9f1895d974b5c295d35d4e08bb",
    "cbb696e51219bea9d6b337db0346cf93a807c5477143dad7f9baf23764fd476b",
})
MAX_FILE = 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_CONFIG = 4096


# Section 2: Canonical models; fail on duplicate keys and unexpected schemas.
def unique_pairs(pairs):
    """Reject duplicate JSON object members without printing their values."""
    found = {}
    for key, value in pairs:
        if key in found:
            raise ValueError
        found[key] = value
    return found


def canonical_object(raw):
    """Require exact, ASCII canonical JSON and exactly one final newline."""
    obj = json.loads(raw.decode("ascii"), object_pairs_hook=unique_pairs,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if type(obj) is not dict:
        raise ValueError
    expected = (json.dumps(obj, sort_keys=True, ensure_ascii=True,
                           separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    if raw != expected:
        raise ValueError
    return obj


# Section 3: Open only fixed absolute directories with no-follow traversal.
def fingerprint(s):
    """Compare stat identity/content metadata, ignoring read-only atime updates."""
    return (s.st_mode, s.st_ino, s.st_dev, s.st_nlink, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def open_abs_dir(path):
    """Open a root-anchored directory chain; forbid symlinks at every level."""
    if not path.startswith("/") or "//" in path:
        raise ValueError
    owned = []
    try:
        fd = os.open("/", DIRFLAGS)
        owned.append(fd)
        for component in path.strip("/").split("/"):
            if not component or component in (".", ".."):
                raise ValueError
            child = os.open(component, DIRFLAGS, dir_fd=fd)
            owned.append(child)
            s = os.fstat(child)
            if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
                raise ValueError
            fd = child
        return owned
    except Exception:
        for fd in reversed(owned):
            os.close(fd)
        raise


def read_regular(path, mode, limit):
    """Read a root-owned, single-link regular file through checked dirfd."""
    parent, name = path.rsplit("/", 1)
    owned = open_abs_dir(parent)
    try:
        directory = owned[-1]
        before = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != mode
                or not 0 < before.st_size <= limit):
            raise ValueError
        handle = os.open(name, FILEFLAGS, dir_fd=directory)
        try:
            opened = os.fstat(handle)
            if fingerprint(opened) != fingerprint(before):
                raise ValueError
            data = b""
            while len(data) < limit + 1:
                block = os.read(handle, min(65536, limit + 1 - len(data)))
                if not block:
                    break
                data += block
            after = os.fstat(handle)
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (len(data) != before.st_size
                    or fingerprint(after) != fingerprint(opened)
                    or fingerprint(named) != fingerprint(before)):
                raise ValueError
            return data, before
        finally:
            os.close(handle)
    finally:
        for fd in reversed(owned):
            os.close(fd)


# Section 4: Scan exact regular-file allowlist, no unknown files/directories.
def verify_source():
    """Verify each installed SHA256, directory topology, and canonical manifest."""
    names = tuple(sorted(EXPECTED))
    if len(names) != 41:
        raise ValueError
    pathset = hashlib.sha256(("\n".join(names) + "\n").encode()).hexdigest()
    if pathset != PATH_SET_SHA256:
        raise ValueError
    entries = [{"path": name, "sha256": EXPECTED[name], "mode": "0644"}
               for name in names]
    manifest = {"manifest_kind": "canonical-relative-file-set-v1",
                "digest_algorithm": "sha256", "reviewed_commit": OLD,
                "entries": entries}
    mbytes = (json.dumps(manifest, sort_keys=True, ensure_ascii=True,
                         separators=(",", ":"), allow_nan=False) + "\n").encode()
    if hashlib.sha256(mbytes).hexdigest() != MANIFEST_SHA256:
        raise ValueError

    dirs = set()
    for name in names:
        bits = name.split("/")
        for index in range(1, len(bits)):
            dirs.add("/".join(bits[:index]))
    seen_files = set()
    seen_dirs = set()
    total = [0]
    owned = open_abs_dir(APP)
    try:
        top = os.fstat(owned[-1])
        if (top.st_uid, top.st_gid, stat.S_IMODE(top.st_mode)) != (0, 0, 0o755):
            raise ValueError

        def scan(fd, prefix):
            """Walk a known directory tree without links or unknown entries."""
            for name in os.listdir(fd):
                relative = name if not prefix else prefix + "/" + name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if relative in dirs:
                    if (not stat.S_ISDIR(info.st_mode)
                            or info.st_uid != 0 or info.st_gid != 0
                            or stat.S_IMODE(info.st_mode) != 0o755):
                        raise ValueError
                    child = os.open(name, DIRFLAGS, dir_fd=fd)
                    try:
                        before = os.fstat(child)
                        if fingerprint(before) != fingerprint(info):
                            raise ValueError
                        seen_dirs.add(relative)
                        scan(child, relative)
                        if fingerprint(os.fstat(child)) != fingerprint(before):
                            raise ValueError
                    finally:
                        os.close(child)
                elif relative in EXPECTED:
                    # Reuse the same fd-bound, no-follow race checks for all
                    # installed regular files without using an untrusted path.
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or (info.st_uid, info.st_gid,
                                stat.S_IMODE(info.st_mode)) != (0, 0, 0o644)
                            or info.st_size < 0 or info.st_size > MAX_FILE):
                        raise ValueError
                    file = os.open(name, FILEFLAGS, dir_fd=fd)
                    try:
                        opened = os.fstat(file)
                        if fingerprint(opened) != fingerprint(info):
                            raise ValueError
                        digest = hashlib.sha256()
                        read = 0
                        while True:
                            block = os.read(file, 65536)
                            if not block:
                                break
                            read += len(block)
                            if read > MAX_FILE:
                                raise ValueError
                            digest.update(block)
                        if (read != info.st_size or digest.hexdigest() != EXPECTED[relative]
                                or fingerprint(os.fstat(file)) != fingerprint(opened)
                                or fingerprint(os.stat(name, dir_fd=fd,
                                        follow_symlinks=False)) != fingerprint(opened)):
                            raise ValueError
                        total[0] += read
                        if total[0] > MAX_TOTAL:
                            raise ValueError
                        seen_files.add(relative)
                    finally:
                        os.close(file)
                else:
                    raise ValueError

        scan(owned[-1], "")
        if seen_files != set(EXPECTED) or seen_dirs != dirs:
            raise ValueError
    finally:
        for fd in reversed(owned):
            os.close(fd)


# Section 5: Validate both immutable config authorities, never print values.
def verify_configs():
    """Require canonical installed predecessor configs and C34D workflow pin."""
    exec_raw, exe_meta = read_regular(EXECUTOR, 0o640, MAX_CONFIG)
    broker_raw, broker_meta = read_regular(BROKER, 0o640, MAX_CONFIG)
    ex = canonical_object(exec_raw)
    br = canonical_object(broker_raw)
    if (frozenset(ex) != _EXECUTOR_FIELDS or frozenset(br) != _BROKER_FIELDS
            or ex.get("schema_version") != 1 or br.get("schema_version") != 2
            or ex.get("stage") != "dev" or br.get("stage") != "dev"
            or ex.get("reviewed_commit") != OLD or br.get("reviewed_commit") != OLD
            or br.get("expected_workflow_sha") != WORKFLOW
            or ex.get("runtime_configuration_sha256") != _RUNTIME_SHA
            or type(ex.get("ingress_file_sha256")) is not dict
            or type(br.get("ingress_file_sha256")) is not dict
            or frozenset(ex["ingress_file_sha256"].values()) != _INGRESS_HASHES
            or frozenset(br["ingress_file_sha256"].values()) != _INGRESS_HASHES
            or exe_meta.st_gid != ex.get("executor_gid")
            or broker_meta.st_gid != br.get("broker_gid")):
        raise ValueError
    if any(ex.get(k) != br.get(k) for k in SHARED):
        raise ValueError


# Section 6: Coarse service observations and side-effect-free receipt.
def service_state():
    """Inspect fixed systemd units, retaining no private journal data."""
    table = {
        "omnilyzer-deployment-broker.service": "active",
        "omnilyzer-deployment-executor.socket": "active",
        "omnilyzer-deployment-executor.service": "inactive",
    }
    observed = []
    for name, expected in table.items():
        p = subprocess.run(
            ("/usr/bin/systemctl", "show", name,
             "--property=ActiveState,NeedDaemonReload", "--no-pager"),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, check=False, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        )
        if p.returncode != 0 or len(p.stdout) > 200:
            raise ValueError
        values = dict(line.split("=", 1) for line in
                      p.stdout.decode("ascii").strip().splitlines())
        if (values.get("ActiveState") != expected
                or values.get("NeedDaemonReload") != "no"):
            raise ValueError
        observed.append((name, expected))
    return tuple(observed)


def main():
    """Read-only root preflight, with fixed nonsecret PASS/HOLD output only."""
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (0, 0, 0, 0):
        print('C34G_PREFLIGHT_HOLD root_identity_required')
        return 2
    try:
        before = service_state()
        verify_source()
        verify_configs()
        after = service_state()
        if before != after:
            raise ValueError
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except Exception:
        print('C34G_PREFLIGHT_HOLD installed_predecessor_not_qualified')
        return 2
    print('C34G_PREFLIGHT_PASS source_41_exact config_pair_canonical workflow_pin_c34d services_unchanged')
    print('C34G_NO_MUTATION_NO_DEPLOYMENT')
    return 0


if __name__ == "__main__":
    sys.exit(main())
