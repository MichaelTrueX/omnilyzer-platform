"""File: deployment/tests/test_analytics_prod_rootless_bootstrap.py
Purpose: Focused source-only safety checks for first PROD rootless prerequisites.
Related: deployment/analytics_prod_rootless_bootstrap.py,
         docs/operations/analytics-prod-first-install.md.
No host package, user, service, database or network changes occur.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
import hashlib
import json
import os
from pathlib import Path
import subprocess
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from deployment import analytics_prod_rootless_bootstrap as boot


class AnalyticsProdRootlessBootstrapTests(unittest.TestCase):
    """Protect one-time install, fixed identity and rootless-only boundaries."""

    def test_subordinate_id_ranges_reject_collisions_and_malformed_entries(self):
        """Never overlap existing service or human UID/GID allocations."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "subuid"
            path.write_text("trusthansen:100000:65536\nomnigpt:165536:65536\n")
            self.assertEqual(boot.subid_conflicts(path), [])
            path.write_text("trusthansen:100000:65536\nother:231072:65536\nbad\n")
            result = boot.subid_conflicts(path)
            self.assertEqual(len(result), 2)
            self.assertIn("overlapping", result[0])
            self.assertIn("invalid", result[1])

    def test_real_host_ids_cannot_overlap_subordinate_ids(self):
        """Protect actual host identities even without an /etc/subuid entry."""
        accounts = [SimpleNamespace(pw_name="other", pw_uid=231072, pw_gid=231073)]
        groups = [SimpleNamespace(gr_name="othergroup", gr_gid=231074)]
        with patch.object(boot.pwd, "getpwall", return_value=accounts):
            with patch.object(boot.grp, "getgrall", return_value=groups):
                errors = boot.host_id_conflicts()
        self.assertEqual(len(errors), 3)
        self.assertTrue(any("host UID" in error for error in errors))
        self.assertTrue(any("host GID" in error for error in errors))

    def test_docker_key_bundle_requires_exactly_one_pinned_primary(self):
        """A second attacker-controlled primary key cannot enter apt trust."""
        good = "pub:::::::::\nfpr:::::::::" + boot.DOCKER_FINGERPRINT + ":\n"
        self.assertTrue(boot.valid_docker_key_listing(good))
        self.assertFalse(boot.valid_docker_key_listing(good + "pub:::::::::\nfpr:::::::::BAD:\n"))
        self.assertFalse(boot.valid_docker_key_listing("pub:::::::::\nfpr:::::::::BAD:\n"))
        self.assertFalse(boot.valid_docker_key_listing("fpr:::::::::" + boot.DOCKER_FINGERPRINT + ":\n"))

    def test_exclusive_file_creation_denies_overwrite_and_symlink(self):
        """Root-controlled artifacts cannot overwrite unrelated files."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owned"
            boot.write_new(path, b"original", 0o600)
            with self.assertRaises(FileExistsError):
                boot.write_new(path, b"replacement", 0o600)
            self.assertEqual(path.read_bytes(), b"original")
            alias = Path(directory) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(FileExistsError):
                boot.write_new(alias, b"replacement", 0o600)
            public = Path(directory) / "public"
            old_umask = os.umask(0o077)
            try:
                boot.write_new(public, b"unit", 0o644)
            finally:
                os.umask(old_umask)
            self.assertEqual(stat.S_IMODE(public.stat().st_mode), 0o644)

    def test_apply_requires_root_before_any_mutation(self):
        """No unprivileged user can enter the package installation path."""
        with patch.object(boot.os, "geteuid", return_value=1000):
            with patch.object(boot, "preflight") as preflight:
                with self.assertRaisesRegex(RuntimeError, "root required"):
                    boot.install()
                preflight.assert_not_called()

    def test_only_pinned_packages_and_no_rootful_or_public_listener(self):
        """Keep PROD's new runtime separate from existing public services."""
        self.assertEqual(boot.HOST, "truexmainserver")
        self.assertEqual(boot.USER, "omnilyzer-analytics")
        self.assertEqual(boot.SUBID_START, 231072)
        self.assertEqual(len(boot.PACKAGES), 7)
        self.assertTrue(all("=" in package for package in boot.PACKAGES))
        self.assertIn("unix://%t/docker.sock", boot.UNIT_TEXT)
        self.assertIn("ConditionUser=omnilyzer-analytics", boot.UNIT_TEXT)
        self.assertEqual(str(boot.UNIT), "/etc/systemd/user/omnilyzer-analytics-docker.service")
        self.assertEqual(str(boot.WANTS.parent), "/etc/systemd/user/default.target.wants")
        self.assertIn("DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=true", boot.UNIT_TEXT)
        self.assertNotIn("tcp://", boot.UNIT_TEXT)
        self.assertNotIn("0.0.0.0", boot.UNIT_TEXT)
        self.assertEqual(boot.ROOTFUL_UNITS, ("docker.service", "docker.socket", "containerd.service"))
        self.assertEqual(len(boot.DOCKER_FINGERPRINT), 40)

    def test_dedicated_user_command_uses_no_shell_or_shared_docker_socket(self):
        """Deployment user cannot silently become host root or share a socket."""
        with patch.object(boot, "run") as runner:
            boot.user_command(989, "/usr/bin/docker", "info")
        args = runner.call_args.args
        self.assertEqual(args[:5], ("/usr/sbin/runuser", "-u", "omnilyzer-analytics", "--", "/usr/bin/env"))
        self.assertIn("DOCKER_HOST=unix:///run/user/989/docker.sock", args)
        self.assertNotIn("/bin/sh", args)
        self.assertNotIn("/var/run/docker.sock", args)

    def test_bootstrap_does_not_install_application_or_grant_sudo(self):
        """A runtime prerequisite is not an Analytics release authorization."""
        import inspect
        source = inspect.getsource(boot.install) + inspect.getsource(boot.finish_service_install)
        self.assertNotIn("sudoers", source)
        self.assertNotIn("docker run", source)
        self.assertNotIn("nginx", source)
        self.assertNotIn("prisma", source)
        self.assertIn("prod_application_installed", source)
        self.assertIn('"--no-create-home"', source)
        self.assertIn("os.chown(HOME, 0, 0)", source)
        self.assertIn("os.chown(data, account.pw_uid, account.pw_gid)", source)


    def test_partial_recovery_never_runs_unprivileged(self):
        """Recovery inspection requires the owner-controlled root context."""
        with patch.object(boot.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(RuntimeError, "requires root"):
                boot.check_consumed_partial_install()

    def test_post_user_completion_exercises_all_real_path_operations(self):
        """Simulate the entire failed remainder, including mkdir, chown and units."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "analytics"
            home.mkdir()
            unit = root / "etc" / "systemd" / "user" / "analytics.service"
            unit.parent.mkdir(parents=True)
            config = root / "etc" / "analytics" / "daemon.json"
            wants = unit.parent / "default.target.wants" / unit.name
            marker = root / "bootstrap-done.json"
            account = SimpleNamespace(pw_uid=990, pw_gid=982)
            original_lexists = os.path.lexists

            def fake_run(*args, **kwargs):
                """Return only the expected inactive rootful-unit checks."""
                return subprocess.CompletedProcess(
                    args, 0, "inactive" if "is-active" in args else "", ""
                )

            def fake_user_command(*args, **kwargs):
                """Return a rootless-only Docker proof without contacting Docker."""
                output = json.dumps(["name=rootless"]) if "info" in args else ""
                return subprocess.CompletedProcess(args, 0, output, "")

            with patch.multiple(
                boot, HOME=home, UNIT=unit, WANTS=wants, CONFIG=config,
                MARKER=marker
            ):
                with patch.object(boot.os, "chown") as chown:
                    with patch.object(boot, "run", side_effect=fake_run) as runner:
                        with patch.object(
                            boot, "user_command", side_effect=fake_user_command
                        ) as user_runner:
                            with patch.object(
                                boot.os.path, "lexists",
                                side_effect=lambda path: False if str(path) == "/var/run/docker.sock"
                                else original_lexists(path),
                            ):
                                with redirect_stdout(StringIO()):
                                    boot.finish_service_install(account)
                    chown.assert_any_call(home, 0, 0)
                    chown.assert_any_call(home / "docker-data", 990, 982)
                    self.assertEqual(chown.call_count, 2)
                    self.assertTrue(user_runner.called)
                    self.assertFalse(
                        any(
                            any("apt-get" in str(item) or "useradd" in str(item)
                                for item in call.args)
                            for call in runner.call_args_list
                        )
                    )
            self.assertTrue(unit.exists())
            self.assertTrue(config.exists())
            self.assertTrue(wants.is_symlink())
            self.assertEqual(json.loads(marker.read_text())["rootless"], True)
            self.assertFalse(json.loads(marker.read_text())["prod_application_installed"])
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)

    def test_no_path_chown_calls_remain_in_source(self):
        """Regression guard for the actual PROD Python failure at line 299."""
        import inspect
        code = inspect.getsource(boot)
        self.assertNotIn("HOME.chown(", code)
        self.assertNotIn("data.chown(", code)
        self.assertIn("os.chown(HOME, 0, 0)", code)
        self.assertIn("os.chown(data, account.pw_uid, account.pw_gid)", code)


    @contextmanager
    def fake_exact_partial_state(self):
        """Model original root-owned PROD receipts without root or live writes."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            home = base / "lib" / "analytics"
            home.mkdir(parents=True, mode=0o755)
            lib = home.parent
            unit = base / "etc" / "systemd" / "user" / "analytics.service"
            unit.parent.mkdir(parents=True, mode=0o755)
            for parent in (home, lib, unit.parent):
                parent.chmod(0o755)
            files = {
                "original": base / "old-first-install",
                "key": base / "apt-key",
                "source": base / "apt-source",
                "apparmor": base / "apparmor-profile",
                "vendor": base / "dockerd-rootless.sh",
                "release": base / "os-release",
                "subuid": base / "subuid",
                "subgid": base / "subgid",
            }
            payloads = {
                "original": b"original-root-custody",
                "key": b"original-pinned-docker-key",
                "source": b"original-docker-repository",
                "apparmor": b"original-approved-apparmor",
                "vendor": b"original-pinned-vendor-rootless",
                "release": b'ID=ubuntu\nVERSION_ID="24.04"\n',
                "subuid": b"trust:100000:65536\nomnigpt:165536:65536\nomnilyzer-analytics:231072:65536\n",
                "subgid": b"trust:100000:65536\nomnigpt:165536:65536\nomnilyzer-analytics:231072:65536\n",
            }
            for name, file in files.items():
                file.write_bytes(payloads[name])
                file.chmod(0o500 if name == "original" else 0o644)
            account = SimpleNamespace(
                pw_uid=990, pw_gid=982, pw_dir=str(home),
                pw_shell="/usr/sbin/nologin", pw_name="omnilyzer-analytics"
            )
            service_group = SimpleNamespace(gr_gid=982, gr_mem=[])
            package_state = {"status": "install ok installed"}
            mapping = {
                "/etc/os-release": files["release"],
                "/usr/bin/dockerd-rootless.sh": files["vendor"],
                "/etc/subuid": files["subuid"],
                "/etc/subgid": files["subgid"],
                "/var/lib/omnilyzer": lib,
                "/var/lib/systemd/linger": base / "linger",
            }
            orig_lstat = os.lstat
            orig_lexists = os.path.lexists

            def source_path(value):
                """Redirect only fixed root-state reads into temporary fixtures."""
                return mapping.get(str(value), Path(value))

            def root_stat(path):
                """Represent temporary test files as root-owned with real modes."""
                entry = orig_lstat(path)
                if str(path).startswith(str(base)):
                    return SimpleNamespace(
                        st_mode=entry.st_mode, st_uid=0,
                        st_gid=0, st_nlink=entry.st_nlink
                    )
                return entry

            def fake_run(*argv, **kwargs):
                """Model explicit package statuses and masked rootful services."""
                if argv[0] == "/usr/bin/dpkg-query":
                    versions = dict(spec.split("=", 1) for spec in boot.PACKAGES)
                    return subprocess.CompletedProcess(
                        argv, 0, package_state["status"] + " " + versions[argv[-1]], ""
                    )
                if "is-enabled" in argv:
                    return subprocess.CompletedProcess(argv, 0, "masked", "")
                if "is-active" in argv:
                    return subprocess.CompletedProcess(argv, 0, "inactive", "")
                return subprocess.CompletedProcess(argv, 0, "", "")

            class ClosedPort:
                """Simulate available localhost Analytics ports without networking."""
                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def connect_ex(self, address):
                    return 111

            with ExitStack() as stack:
                stack.enter_context(patch.multiple(
                    boot, HOME=home, KEY=files["key"], SOURCE=files["source"],
                    APPARMOR=files["apparmor"], UNIT=unit,
                    WANTS=unit.parent / "default.target.wants" / "analytics.service",
                    CONFIG=base / "etc" / "analytics" / "daemon.json",
                    MARKER=base / "complete.json",
                    ORIGINAL_INSTALLER=files["original"],
                    ORIGINAL_INSTALLER_SHA256=hashlib.sha256(payloads["original"]).hexdigest(),
                    PARTIAL_APT_KEY_SHA256=hashlib.sha256(payloads["key"]).hexdigest(),
                    PARTIAL_APT_SOURCE_SHA256=hashlib.sha256(payloads["source"]).hexdigest(),
                    APPARMOR_SHA256=hashlib.sha256(payloads["apparmor"]).hexdigest(),
                    VENDOR_SHA256=hashlib.sha256(payloads["vendor"]).hexdigest()
                ))
                stack.enter_context(patch.object(boot, "Path", side_effect=source_path))
                stack.enter_context(patch.object(boot.os, "geteuid", return_value=0))
                stack.enter_context(patch.object(boot.os, "lstat", side_effect=root_stat))
                stack.enter_context(patch.object(
                    boot.os.path, "lexists",
                    side_effect=lambda path: False if str(path) == "/var/run/docker.sock"
                    else orig_lexists(path)
                ))
                stack.enter_context(patch.object(boot.pwd, "getpwnam", return_value=account))
                stack.enter_context(patch.object(boot.grp, "getgrnam", return_value=service_group))
                stack.enter_context(patch.object(boot.pwd, "getpwall", return_value=[]))
                stack.enter_context(patch.object(boot.grp, "getgrall", return_value=[]))
                stack.enter_context(patch.object(boot.socket, "gethostname", return_value=boot.HOST))
                stack.enter_context(patch.object(boot.socket, "socket", return_value=ClosedPort()))
                stack.enter_context(patch.object(boot.platform, "machine", return_value="x86_64"))
                stack.enter_context(patch.object(
                    boot.shutil, "disk_usage",
                    return_value=SimpleNamespace(free=40 * 1024**3)
                ))
                stack.enter_context(patch.object(boot, "run", side_effect=fake_run))
                yield files, account, package_state

    def test_exact_partial_state_and_negative_authority_gate(self):
        """Reject changed source, packages, identity, symlinks and later writes."""
        with self.fake_exact_partial_state() as (files, account, package_state):
            with redirect_stdout(StringIO()):
                found = boot.check_consumed_partial_install()
            self.assertEqual(found.pw_uid, 990)

            def rejected():
                """Any mismatch must stop BEFORE the privileged remainder runs."""
                with patch.object(boot, "finish_service_install") as finish:
                    with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                        with self.assertRaisesRegex(RuntimeError, "preflight rejected"):
                            boot.resume_after_user_created()
                    finish.assert_not_called()

            with patch.object(boot, "ORIGINAL_INSTALLER_SHA256", "0" * 64):
                rejected()

            package_state["status"] = "deinstall ok config-files"
            rejected()
            package_state["status"] = "install ok installed"

            with patch.object(
                boot.pwd, "getpwnam",
                return_value=SimpleNamespace(
                    pw_uid=991, pw_gid=account.pw_gid,
                    pw_dir=account.pw_dir, pw_shell=account.pw_shell
                ),
            ):
                rejected()

            files["key"].rename(files["key"].with_suffix(".saved"))
            files["key"].symlink_to(files["key"].with_suffix(".saved"))
            rejected()
            files["key"].unlink()
            files["key"].with_suffix(".saved").rename(files["key"])

            next_stage = boot.CONFIG
            next_stage.parent.mkdir(parents=True)
            next_stage.write_text("premature-install")
            rejected()
            next_stage.unlink()


if __name__ == "__main__":
    unittest.main()
