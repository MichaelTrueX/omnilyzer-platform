"""Static C22 asset checks: no systemd invocation, host provisioning or sockets.

C21 supplies layout projections. C16 descriptor constants and C9's required
/proc/self/net/unix inventory are inspected as repository source, never invoked.
"""

import ast
import hashlib
from pathlib import Path
import stat
import unittest

from deployment import host_provisioning_contract as provisioning_contract
from deployment import installation_contract as installation_contract
from deployment.host_service_layout import DevHostServiceLayout
from deployment.unix_transport import PRODUCTION_EXECUTOR_SOCKET_PATH


_DEPLOYMENT = Path(__file__).absolute().parents[1]
_ASSETS = _DEPLOYMENT / "systemd" / "dev"
_LAYOUT = DevHostServiceLayout()
_SOCKET_HEADER = (
    "# deployment/systemd/dev/omnilyzer-deployment-executor.socket\n"
    "# Purpose: inert future systemd socket-activation asset for the DEV privileged\n"
    "# executor. C21 supplies names/path ownership contracts; C16 consumes the one\n"
    "# inherited named FD. This repository asset is not installed, enabled or started.\n"
)
_SERVICE_HEADER = (
    "# deployment/systemd/dev/omnilyzer-deployment-executor.service\n"
    "# Purpose: inert future systemd service asset for one C20/C19 DEV executor\n"
    "# process. C21 supplies the fixed interpreter, working directory and symbolic\n"
    "# identities. This repository asset is not installed, enabled or started.\n"
)
_HARDENING = (
    ("UMask", "0077"),
    ("NoNewPrivileges", "yes"),
    ("PrivateTmp", "yes"),
    ("PrivateDevices", "yes"),
    ("ProtectHome", "yes"),
    ("ProtectSystem", "strict"),
    ("ReadWritePaths", "/var/lib/omnilyzer/deployment"),
    ("ProtectControlGroups", "yes"),
    ("ProtectKernelModules", "yes"),
    ("ProtectKernelTunables", "yes"),
    ("ProtectKernelLogs", "yes"),
    ("ProtectClock", "yes"),
    ("ProtectHostname", "yes"),
    ("LockPersonality", "yes"),
    ("RestrictRealtime", "yes"),
    ("RestrictSUIDSGID", "yes"),
    ("RestrictNamespaces", "yes"),
    ("CapabilityBoundingSet", ""),
    ("AmbientCapabilities", ""),
    ("RestrictAddressFamilies", "AF_UNIX AF_INET AF_INET6"),
)
_SOCKET_SECTIONS = (
    ("Unit", (("Description", "Omnilyzer DEV deployment executor socket"),)),
    ("Socket", (
        ("ListenStream", _LAYOUT.executor_socket_path),
        ("SocketUser", _LAYOUT.executor_user),
        ("SocketGroup", _LAYOUT.socket_group),
        ("SocketMode", "0660"),
        ("DirectoryMode", "0755"),
        ("FileDescriptorName", "omnilyzer-executor"),
        ("Accept", "no"),
        ("Service", _LAYOUT.executor_service_unit_name),
        ("RemoveOnStop", "yes"),
    )),
    ("Install", (("WantedBy", "sockets.target"),)),
)
_SERVICE_SECTIONS = (
    ("Unit", (
        ("Description", "Omnilyzer DEV deployment executor"),
        ("Requires", _LAYOUT.executor_socket_unit_name),
        ("After", _LAYOUT.executor_socket_unit_name),
    )),
    ("Service", (
        ("Type", "exec"),
        ("User", _LAYOUT.executor_user),
        ("Group", _LAYOUT.executor_group),
        ("SupplementaryGroups", _LAYOUT.replay_group),
        ("WorkingDirectory", _LAYOUT.working_directory),
        ("ExecStart", " ".join(_LAYOUT.executor_exec_argv)),
        ("Restart", "no"),
    ) + _HARDENING),
)
# Baseline source digests detect changes to the reviewed lower contracts.
_LOWER_CONTRACT_HASHES = {
    "host_service_layout.py": "fb323635bf2ece8e520bb5a8bf8b8716ad625a25fd123237bb4481ccbf333a0b",
    "executor_service_entrypoint.py": "17a922f138b202ec3fb38e4c469bc404b11d997183eabe96e1b616960fad2daa",
    "executor_service_bootstrap.py": "15a2e93f4d24720229f8a652b74379a81525fa9bb26223ada7a19dc8dc5713ea",
    "executor_service_config_loader.py": "48b7b0b9224b4adf5d3f1f508ea034785e05618943c4df046cefb6d4a618dcf3",
    "executor_service_config.py": "812f678e2a1a176c8aee89372d03c7d5d8ec16b6c0208331263bea3b0d210f44",
    "systemd_socket_activation.py": "25d20dddba58958d3f247d91e66b660033306bcdae72e56d5bb25174d0b0b630",
    "executor_composition.py": "9f34b0c76d168ac1096f8397df5f5f74e4e162481076955c8b2ae83099b7d3e7",
    "installation_contract.py": "99817f9558c83e229df04a1997b863b050ee9c0746e09aecc9262d0f5b2e41eb",
    "executor_listener.py": "c8644f198c0ce9362a7b01ab0b050c875237a78db610bae9c7727da6f6f47def",
    "unix_transport.py": "db2a6b8c35bd483412d1d7fa8367cbca9aba4888b7aacc5a5fa83a7bda74d4da",
}


def _parse_unit(text):
    """Parse only closed section/directive syntax, preserving exact order."""
    sections = []
    section_names = set()
    keys = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1]
            if name in section_names:
                raise ValueError("invalid unit asset")
            section_names.add(name)
            sections.append((name, []))
            keys = set()
        else:
            if not sections or "=" not in line or line.endswith("\\"):
                raise ValueError("invalid unit asset")
            key, value = line.split("=", 1)
            if not key or key in keys or key != key.strip():
                raise ValueError("invalid unit asset")
            keys.add(key)
            sections[-1][1].append((key, value))
    return tuple((name, tuple(items)) for name, items in sections)


def _render_unit(header, sections):
    """Render the single exact reviewed ASCII/LF asset for byte comparison."""
    return header + "\n" + "\n\n".join(
        "[" + name + "]\n" + "\n".join(key + "=" + value for key, value in items)
        for name, items in sections
    ) + "\n"


class SystemdExecutorUnitTests(unittest.TestCase):
    """Validate repository assets and compatibility without live host actions."""

    @classmethod
    def setUpClass(cls):
        """Read only the two repository assets and construct the inert layout."""
        cls.layout = DevHostServiceLayout()
        cls.socket_path = _ASSETS / cls.layout.executor_socket_unit_name
        cls.service_path = _ASSETS / cls.layout.executor_service_unit_name
        cls.socket_raw = cls.socket_path.read_bytes()
        cls.service_raw = cls.service_path.read_bytes()
        cls.socket_text = cls.socket_raw.decode("ascii")
        cls.service_text = cls.service_raw.decode("ascii")
        cls.socket_sections = _parse_unit(cls.socket_text)
        cls.service_sections = _parse_unit(cls.service_text)
        cls.socket = dict(dict(cls.socket_sections)["Socket"])
        cls.service = dict(dict(cls.service_sections)["Service"])
        cls.service_unit = dict(dict(cls.service_sections)["Unit"])

    def test_a_exact_asset_paths(self):
        self.assertEqual(self.socket_path.relative_to(_DEPLOYMENT).as_posix(),
                         "systemd/dev/omnilyzer-deployment-executor.socket")
        self.assertEqual(self.service_path.relative_to(_DEPLOYMENT).as_posix(),
                         "systemd/dev/omnilyzer-deployment-executor.service")
        self.assertEqual(set(_ASSETS.iterdir()), {self.socket_path, self.service_path})

    def test_b_text_hygiene_and_nonexecutable_modes(self):
        for path, raw in ((self.socket_path, self.socket_raw),
                          (self.service_path, self.service_raw)):
            with self.subTest(asset=path.name):
                text = raw.decode("ascii")
                self.assertNotIn(b"\0", raw)
                self.assertNotIn(b"\r", raw)
                self.assertTrue(raw.endswith(b"\n"))
                self.assertFalse(raw.endswith(b"\n\n"))
                self.assertTrue(all(line == line.rstrip() for line in text.splitlines()))
                self.assertEqual(path.stat().st_mode &
                                 (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH), 0)

    def test_c_exact_socket_content_and_order(self):
        self.assertEqual(self.socket_sections, _SOCKET_SECTIONS)
        self.assertEqual(self.socket_text, _render_unit(_SOCKET_HEADER, _SOCKET_SECTIONS))

    def test_d_c21_socket_projection(self):
        self.assertEqual(self.socket["ListenStream"], self.layout.executor_socket_path)
        self.assertEqual(self.socket["ListenStream"], PRODUCTION_EXECUTOR_SOCKET_PATH)
        self.assertEqual(self.socket["SocketUser"], self.layout.executor_user)
        self.assertEqual(self.socket["SocketGroup"], self.layout.socket_group)
        self.assertEqual(self.socket["Service"], self.layout.executor_service_unit_name)
        self.assertEqual(self.socket_path.name, self.layout.executor_socket_unit_name)

    def test_e_c16_descriptor_contract(self):
        tree = ast.parse((_DEPLOYMENT / "systemd_socket_activation.py").read_text())
        constants = {
            node.targets[0].id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
        }
        self.assertEqual(constants["_DESCRIPTOR_NAME"], "omnilyzer-executor")
        self.assertEqual(constants["_SYSTEMD_LISTEN_FDS_START"], 3)
        self.assertEqual(self.socket["FileDescriptorName"], constants["_DESCRIPTOR_NAME"])
        self.assertEqual(self.socket["Accept"], "no")
        self.assertEqual(self.socket_text.count("\nListenStream="), 1)

    def test_f_socket_security(self):
        self.assertEqual(self.socket["SocketMode"], "0660")
        self.assertEqual(self.socket["DirectoryMode"], "0755")
        self.assertNotEqual(self.socket["SocketUser"], "root")
        self.assertNotEqual(self.socket["SocketGroup"], "root")
        for mode in ("0666", "0777", "0775"):
            self.assertNotIn(mode, self.socket.values())

    def test_g_exact_service_sections_and_order(self):
        self.assertEqual(self.service_sections, _SERVICE_SECTIONS)
        self.assertEqual(self.service_text, _render_unit(_SERVICE_HEADER, _SERVICE_SECTIONS))
        self.assertEqual(tuple(name for name, _ in self.service_sections), ("Unit", "Service"))
        self.assertNotIn("[Install]", self.service_text)

    def test_h_c21_service_projection(self):
        self.assertEqual(self.service["User"], self.layout.executor_user)
        self.assertEqual(self.service["Group"], self.layout.executor_group)
        self.assertEqual(self.service["WorkingDirectory"], self.layout.working_directory)
        self.assertEqual(tuple(self.service["ExecStart"].split(" ")),
                         self.layout.executor_exec_argv)
        self.assertEqual(self.service_unit["Requires"], self.layout.executor_socket_unit_name)
        self.assertEqual(self.service_unit["After"], self.layout.executor_socket_unit_name)

    def test_i_service_symbolic_identity(self):
        self.assertEqual(self.service["User"], "omnilyzer-executor")
        self.assertEqual(self.service["Group"], "omnilyzer-executor")
        self.assertEqual(self.service["SupplementaryGroups"], self.layout.replay_group)
        for key in ("User", "Group", "SupplementaryGroups"):
            self.assertRegex(self.service[key], r"\A[a-z][a-z0-9-]{0,30}\Z")
        for group in (self.layout.socket_group, "docker", "sudo", "root"):
            self.assertNotIn(group, self.service["SupplementaryGroups"].split())

    def test_j_single_direct_execstart(self):
        self.assertEqual(self.service_text.count("\nExecStart="), 1)
        self.assertEqual(self.service["ExecStart"], " ".join(self.layout.executor_exec_argv))
        for forbidden in ("/bin/sh", "/bin/bash", "sh -c", "bash -c", "/usr/bin/env",
                          "python -c", "/home/", "trusthansen", "repos/omnilyzer-platform"):
            self.assertNotIn(forbidden, self.service["ExecStart"])
        self.assertTrue(self.service["ExecStart"].startswith("/opt/"))

    def test_k_no_environment_configuration(self):
        for key in ("Environment", "EnvironmentFile", "PassEnvironment", "UnsetEnvironment"):
            self.assertNotIn(key, self.service)

    def test_l_one_attempt_without_restart_loop(self):
        self.assertEqual(self.service["Type"], "exec")
        self.assertEqual(self.service["Restart"], "no")
        for key in ("RestartSec", "StartLimitIntervalSec", "StartLimitBurst"):
            self.assertNotIn(key, self.service)
            self.assertNotIn(key, self.service_unit)

    def test_m_exact_hardening_set(self):
        self.assertEqual(tuple(self.service_sections[1][1][7:]), _HARDENING)
        for key, value in _HARDENING:
            self.assertEqual(self.service[key], value)

    def test_n_required_compatibility_absences(self):
        for key in ("ProtectProc", "ProcSubset", "PrivateUsers", "PrivateNetwork",
                    "IPAddressDeny", "SystemCallFilter", "SystemCallErrorNumber",
                    "SystemCallArchitectures", "MemoryDenyWriteExecute"):
            self.assertNotIn(key + "=", self.service_text)

    def test_o_no_docker_or_capability_privilege(self):
        text = self.socket_text + self.service_text
        for forbidden in ("SupplementaryGroups=docker", "docker.sock", "sudo", "sudoers",
                          "polkit", "CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(self.service["CapabilityBoundingSet"], "")
        self.assertEqual(self.service["AmbientCapabilities"], "")

    def test_p_no_secret_channels(self):
        text = (self.socket_text + self.service_text).lower()
        self.assertNotRegex(text, r"password|secret|token|credential|api[ _-]?key")
        self.assertNotIn("loadcredential", text)
        self.assertNotIn("environmentfile", text)

    def test_q_no_command_hooks(self):
        command_keys = tuple(key for _, items in self.service_sections
                             for key, _ in items if key.startswith("Exec"))
        self.assertEqual(command_keys, ("ExecStart",))
        for key in ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload"):
            self.assertNotIn(key + "=", self.socket_text + self.service_text)

    def test_r_socket_service_coherence(self):
        self.assertEqual(self.socket["Service"], self.service_path.name)
        self.assertEqual(self.service_path.name, self.layout.executor_service_unit_name)
        for key in ("Requires", "After"):
            self.assertEqual(self.service_unit[key], self.socket_path.name)
        self.assertEqual(self.socket_path.name, self.layout.executor_socket_unit_name)
        install = dict(dict(self.socket_sections)["Install"])
        self.assertEqual(install, {"WantedBy": "sockets.target"})
        self.assertEqual(self.socket["RemoveOnStop"], "yes")

    def test_s_c9_proc_inventory_remains_visible(self):
        """C9 requires /proc/self/net/unix; read its source, never real /proc."""
        source = (_DEPLOYMENT / "executor_listener.py").read_text()
        literals = {node.value for node in ast.walk(ast.parse(source))
                    if isinstance(node, ast.Constant) and type(node.value) is str}
        self.assertIn("/proc/self/net/unix", literals)
        self.assertNotIn("ProtectProc", self.service_text)
        self.assertNotIn("ProcSubset", self.service_text)

    def test_t_local_candidate_network_compatibility(self):
        self.assertEqual(self.service["RestrictAddressFamilies"], "AF_UNIX AF_INET AF_INET6")
        self.assertNotIn("PrivateNetwork", self.service_text)
        self.assertNotIn("IPAddressDeny", self.service_text)

    def test_u_no_installation_code(self):
        """Exact asset set and test AST exclude any installer or mutation code."""
        self.assertEqual(set(_ASSETS.iterdir()), {self.socket_path, self.service_path})
        tree = ast.parse(Path(__file__).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self.assertTrue(all(alias.name in ("ast", "hashlib", "stat", "unittest")
                                    for alias in node.names))
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module, ("pathlib", "deployment",
                                            "deployment.host_service_layout",
                                            "deployment.unix_transport"))
            elif isinstance(node, ast.Call):
                name = (node.func.id if isinstance(node.func, ast.Name)
                        else node.func.attr if isinstance(node.func, ast.Attribute) else "")
                if name == "replace":
                    # Only string replacement in the in-memory attack fixtures.
                    receiver = node.func.value
                    self.assertTrue(
                        isinstance(receiver, ast.Name) and receiver.id == "text"
                        or isinstance(receiver, ast.Attribute) and receiver.attr in ("socket_text", "service_text")
                    )
                self.assertNotIn(name, (
                    "system", "popen", "Popen", "run", "check_call", "check_output",
                    "mkdir", "makedirs", "chmod", "chown", "unlink", "rename",
                    "write_text", "write_bytes", "copy", "copyfile", "copy2", "symlink_to",
                    "socket", "bind", "listen", "getpwnam", "getgrnam",
                ))
        text = self.socket_text + self.service_text
        for forbidden in ("systemctl", "daemon-reload", "/etc/systemd", "/usr/lib/systemd",
                          "useradd", "groupadd", "mkdir", "chmod", "chown",
                          "python -m venv", "pip install"):
            self.assertNotIn(forbidden, text)

    def test_v_lower_contracts_unchanged(self):
        for name, digest in _LOWER_CONTRACT_HASHES.items():
            with self.subTest(contract=name):
                self.assertEqual(hashlib.sha256((_DEPLOYMENT / name).read_bytes()).hexdigest(), digest)

    def test_w_c23_binds_exact_reviewed_asset_bytes(self):
        installation = installation_contract.DevHostInstallationContract(
            broker_uid=1201, broker_gid=1201,
            executor_uid=1202, executor_gid=1202,
            replay_group_gid=1203, socket_group_gid=1204,
        )
        assets = provisioning_contract.DevHostProvisioningContract(
            installation=installation).installed_asset_requirements()
        by_source = {item.source_path: item for item in assets}
        self.assertEqual(set(by_source), {
            "deployment/systemd/dev/" + self.socket_path.name,
            "deployment/systemd/dev/" + self.service_path.name,
        })
        for path, raw in ((self.socket_path, self.socket_raw),
                          (self.service_path, self.service_raw)):
            source = "deployment/systemd/dev/" + path.name
            with self.subTest(source=source):
                self.assertEqual(hashlib.sha256(raw).hexdigest(), by_source[source].sha256)

    def test_adversarial_operational_changes_are_rejected(self):
        """Try altered directives in memory; never write or launch a unit."""
        attacks = (
            (self.socket_text, _SOCKET_SECTIONS, "ListenStream=" + self.layout.executor_socket_path,
             "ListenStream=0.0.0.0:9000"),
            (self.socket_text, _SOCKET_SECTIONS, "Accept=no", "Accept=yes"),
            (self.socket_text, _SOCKET_SECTIONS, "FileDescriptorName=omnilyzer-executor",
             "FileDescriptorName=wrong"),
            (self.socket_text, _SOCKET_SECTIONS, "SocketMode=0660", "SocketMode=0666"),
            (self.socket_text, _SOCKET_SECTIONS, "SocketUser=" + self.layout.executor_user,
             "SocketUser=root"),
            (self.socket_text, _SOCKET_SECTIONS, "SocketGroup=" + self.layout.socket_group,
             "SocketGroup=root"),
            (self.socket_text, _SOCKET_SECTIONS, "DirectoryMode=0755", "DirectoryMode=0777"),
            (self.service_text, _SERVICE_SECTIONS, "ExecStart=" + self.service["ExecStart"],
             "ExecStart=python -m deployment.executor_service_entrypoint"),
            (self.service_text, _SERVICE_SECTIONS, "ExecStart=" + self.service["ExecStart"],
             "ExecStart=/bin/sh -c arbitrary"),
            (self.service_text, _SERVICE_SECTIONS, "Restart=no", "Restart=always"),
            (self.service_text, _SERVICE_SECTIONS, "SupplementaryGroups=" + self.layout.replay_group,
             "SupplementaryGroups=docker sudo"),
            (self.service_text, _SERVICE_SECTIONS, "CapabilityBoundingSet=",
             "CapabilityBoundingSet=CAP_SYS_ADMIN"),
        )
        for text, expected, original, malicious in attacks:
            with self.subTest(payload=malicious):
                self.assertIn(original, text)
                self.assertNotEqual(_parse_unit(text.replace(original, malicious)), expected)
        for extra in ("ListenStream=/tmp/second", "ListenDatagram=9000", "ListenFIFO=/tmp/fifo"):
            text = self.socket_text.replace("[Socket]\n", "[Socket]\n" + extra + "\n")
            try:
                parsed = _parse_unit(text)
            except ValueError:
                continue
            self.assertNotEqual(parsed, _SOCKET_SECTIONS)
        for extra in (
            "EnvironmentFile=/tmp/config", "ExecStartPre=/bin/sh -c arbitrary",
            "ExecStopPost=/bin/rm arbitrary", "PrivateUsers=yes", "ProtectProc=invisible",
            "ProcSubset=pid", "PrivateNetwork=yes", "IPAddressDeny=any",
            "SystemCallFilter=@system-service", "MemoryDenyWriteExecute=yes",
            "AmbientCapabilities=CAP_DAC_OVERRIDE", "SupplementaryGroups=omnilyzer-deployment",
        ):
            text = self.service_text + extra + "\n"
            try:
                parsed = _parse_unit(text)
            except ValueError:
                continue
            self.assertNotEqual(parsed, _SERVICE_SECTIONS)
        text = self.service_text.replace(self.service["ExecStart"], self.service["ExecStart"] + " extra")
        self.assertNotEqual(_parse_unit(text), _SERVICE_SECTIONS)


if __name__ == "__main__":
    unittest.main()
