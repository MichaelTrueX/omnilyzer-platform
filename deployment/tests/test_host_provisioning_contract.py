"""Deterministic C23 projection and boundary tests, with no host provisioning."""

import ast
from contextlib import ExitStack
import dataclasses
import hashlib
import importlib
import inspect
from pathlib import Path, PurePosixPath
import unittest
from unittest.mock import patch

import deployment.host_provisioning_contract as module
from deployment.installation_contract import DevHostInstallationContract, MAX_UID_GID
from deployment.host_service_layout import DevHostServiceLayout
from deployment.executor_service_config import (
    PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH,
    EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE,
    EXECUTOR_SERVICE_CONFIG_FILE_MODE,
)


_API = (
    "HostGroupRequirement", "HostUserRequirement", "HostPathRequirement",
    "HostInstalledAssetRequirement", "DevHostProvisioningContract",
)
_IDENTITIES = {
    "broker_uid": 1201, "broker_gid": 1201,
    "executor_uid": 1202, "executor_gid": 1202,
    "replay_group_gid": 1203, "socket_group_gid": 1204,
}
_EXPECTED_PATHS = (
    ("/opt/omnilyzer", "directory", 0o755, 0, 0, "must-exist-before-activation"),
    ("/opt/omnilyzer/deployment", "directory", 0o755, 0, 0, "must-exist-before-activation"),
    ("/opt/omnilyzer/deployment/app", "directory", 0o755, 0, 0,
     "must-contain-reviewed-application-before-activation"),
    ("/opt/omnilyzer/deployment/venv", "directory", 0o755, 0, 0,
     "must-contain-reviewed-venv-before-activation"),
    ("/etc/omnilyzer", "directory", 0o755, 0, 0, "must-exist-before-activation"),
    ("/etc/omnilyzer/deployment", "directory", 0o755, 0, 0, "must-exist-before-activation"),
    ("/etc/omnilyzer/deployment/dev", "directory", 0o750, 0, 1202, "must-exist-before-activation"),
    ("/etc/omnilyzer/deployment/dev/executor.json", "regular_file", 0o640, 0, 1202,
     "must-contain-c17-canonical-config-before-activation"),
    ("/var/lib/omnilyzer", "directory", 0o755, 0, 0, "must-exist-before-activation"),
    ("/var/lib/omnilyzer/deployment", "directory", 0o755, 0, 0, "must-exist-before-activation"),
    ("/run/omnilyzer", "directory", 0o755, 0, 0,
     "future-systemd-socket-directory-creation-only"),
    ("/run/omnilyzer/deployment", "directory", 0o755, 0, 0,
     "future-systemd-socket-directory-creation-only"),
)
_COLLECTION_METHODS = (
    "group_requirements", "user_requirements", "runtime_resource_requirements",
    "path_requirements", "installed_asset_requirements",
)


def _installation(**changes):
    """Build a reviewed C13 test fixture with optional numeric test variations."""
    return DevHostInstallationContract(**(_IDENTITIES | changes))


class HostProvisioningContractTests(unittest.TestCase):
    """Prove exact immutable projections and lack of operational authority."""

    def setUp(self):
        """Construct fresh C13/C23 fixtures without resolving anything on the host."""
        self.installation = _installation()
        self.contract = module.DevHostProvisioningContract(installation=self.installation)
        self.layout = self.contract.service_layout()

    def test_a_import_and_construction_are_inert(self):
        operations = (
            "builtins.open", "os.open", "os.stat", "os.getenv", "os.getuid",
            "os.getgid", "subprocess.Popen", "socket.socket",
        )
        with ExitStack() as stack:
            mocks = [stack.enter_context(patch(name, side_effect=AssertionError("host I/O")))
                     for name in operations]
            importlib.import_module("deployment.host_provisioning_contract")
            importlib.reload(module)
            installation = _installation()
            module.DevHostProvisioningContract(installation=installation)
            for mock in mocks:
                mock.assert_not_called()

    def test_b_exact_public_api_and_dataclasses(self):
        self.assertEqual(module.__all__, _API)
        self.assertEqual(tuple(name for name in vars(module) if not name.startswith("_")), _API)
        for name in _API:
            cls = getattr(module, name)
            self.assertTrue(dataclasses.is_dataclass(cls))
            self.assertTrue(cls.__dataclass_params__.frozen)
            self.assertIn("__slots__", vars(cls))

    def test_c_exact_keyword_only_c13_input(self):
        signature = inspect.signature(module.DevHostProvisioningContract)
        self.assertEqual(tuple(signature.parameters), ("installation",))
        parameter = signature.parameters["installation"]
        self.assertIs(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(parameter.default, inspect.Parameter.empty)
        self.assertIs(parameter.annotation, DevHostInstallationContract)
        with self.assertRaises(TypeError):
            module.DevHostProvisioningContract(self.installation)
        with self.assertRaises(TypeError):
            module.DevHostProvisioningContract()
        class Subclass(DevHostInstallationContract):
            """An otherwise valid C13 subclass must not cross the exact-type boundary."""
        for invalid in (None, {}, _IDENTITIES, object(), Subclass(**_IDENTITIES)):
            with self.assertRaises(TypeError) as caught:
                module.DevHostProvisioningContract(installation=invalid)
            self.assertEqual(str(caught.exception), "DEV host provisioning contract is invalid")
        for key in ("uid", "gid", "path", "mode", "user", "group", "layout", "config",
                    "docker", "_layout", "_paths", "_groups", "_assets"):
            with self.assertRaises(TypeError):
                module.DevHostProvisioningContract(installation=self.installation, **{key: "/tmp"})

    def test_forged_incomplete_c13_structure_has_fixed_type_error(self):
        """Exact type alone must not expose missing-field errors or mutable resources."""
        empty = object.__new__(DevHostInstallationContract)
        partial = object.__new__(DevHostInstallationContract)
        for name, value in _IDENTITIES.items():
            object.__setattr__(partial, name, value)
        mutable = _installation()
        object.__setattr__(mutable, "_resources", [])
        for invalid in (empty, partial, mutable):
            with self.assertRaises(TypeError) as caught:
                module.DevHostProvisioningContract(installation=invalid)
            self.assertEqual(str(caught.exception), "DEV host provisioning contract is invalid")

    def test_d_narrower_identity_compatibility_preserves_c13(self):
        for key in ("executor_uid", "executor_gid"):
            installation = _installation(**{key: 0})
            self.assertIs(type(installation), DevHostInstallationContract)
            with self.assertRaises(ValueError) as caught:
                module.DevHostProvisioningContract(installation=installation)
            self.assertEqual(str(caught.exception), "DEV host provisioning contract is invalid")
        groups = ("broker_gid", "executor_gid", "replay_group_gid", "socket_group_gid")
        c23_rejections = 0
        c13_rejections = 0
        for index, first in enumerate(groups):
            for second in groups[index + 1:]:
                with self.subTest(first=first, second=second):
                    if {first, second} == {"executor_gid", "socket_group_gid"}:
                        # C13 already rejects this pair; do not weaken or bypass it.
                        with self.assertRaises(ValueError):
                            _installation(**{second: _IDENTITIES[first]})
                        c13_rejections += 1
                    else:
                        installation = _installation(**{second: _IDENTITIES[first]})
                        with self.assertRaises(ValueError) as caught:
                            module.DevHostProvisioningContract(installation=installation)
                        self.assertEqual(str(caught.exception), "DEV host provisioning contract is invalid")
                        c23_rejections += 1
        self.assertEqual((c23_rejections, c13_rejections), (5, 1))

    def test_e_exact_group_projection(self):
        groups = self.contract.group_requirements()
        self.assertEqual(tuple((group.name, group.gid) for group in groups), (
            (self.layout.broker_group, self.installation.broker_gid),
            (self.layout.executor_group, self.installation.executor_gid),
            (self.layout.replay_group, self.installation.replay_group_gid),
            (self.layout.socket_group, self.installation.socket_group_gid),
        ))
        self.assertEqual(tuple(group.name for group in groups),
                         ("omnilyzer-broker", "omnilyzer-executor", "omnilyzer-replay", "omnilyzer-deployment"))
        self.assertEqual(len({group.name for group in groups}), 4)
        self.assertEqual(len({group.gid for group in groups}), 4)
        self.assertTrue(all(type(group.gid) is int and group.gid > 0 for group in groups))

    def test_f_exact_user_and_membership_projection(self):
        broker, executor = self.contract.user_requirements()
        self.assertEqual((broker.name, broker.uid, broker.primary_gid),
                         (self.layout.broker_user, self.installation.broker_uid, self.installation.broker_gid))
        self.assertEqual((executor.name, executor.uid, executor.primary_gid),
                         (self.layout.executor_user, self.installation.executor_uid, self.installation.executor_gid))
        self.assertIs(broker.supplementary_gids, self.installation.broker_required_group_gids)
        self.assertIs(executor.supplementary_gids, self.installation.executor_required_group_gids)
        self.assertEqual(broker.supplementary_gids,
                         (self.installation.replay_group_gid, self.installation.socket_group_gid))
        self.assertEqual(executor.supplementary_gids, (self.installation.replay_group_gid,))
        self.assertNotIn(self.installation.socket_group_gid, executor.supplementary_gids)

    def test_g_immutability_and_tuple_collections(self):
        values = [self.contract, self.layout]
        for name in _COLLECTION_METHODS:
            first = getattr(self.contract, name)()
            second = getattr(self.contract, name)()
            self.assertIs(type(first), tuple)
            self.assertEqual(first, second)
            values.extend(first)
        for value in values:
            self.assertFalse(hasattr(value, "__dict__"))
            self.assertEqual(hash(value), hash(value))
            for field in dataclasses.fields(value):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(value, field.name, "/tmp")
                item = getattr(value, field.name)
                self.assertTrue(type(item) in (str, int, tuple, DevHostInstallationContract, DevHostServiceLayout))
        self.assertEqual(self.contract, module.DevHostProvisioningContract(installation=self.installation))

    def test_h_runtime_resource_objects_preserved(self):
        resources = self.installation.resource_requirements()
        self.assertIs(self.contract.runtime_resource_requirements(), resources)
        for projected, original in zip(self.contract.runtime_resource_requirements(), resources, strict=True):
            self.assertIs(projected, original)

    def test_i_exact_ordered_additional_paths(self):
        self.assertEqual(tuple(dataclasses.astuple(item) for item in self.contract.path_requirements()),
                         _EXPECTED_PATHS)
        self.assertEqual(len(self.contract.path_requirements()), 12)
        self.assertFalse(any(item.path.startswith("/var/log/")
                             for item in (*self.contract.path_requirements(),
                                          *self.contract.runtime_resource_requirements())))
        for requirement in self.contract.path_requirements():
            self.assertIs(type(requirement.path), str)
            self.assertTrue(PurePosixPath(requirement.path).is_absolute())
            for name in ("mode", "owner_uid", "group_gid"):
                self.assertIs(type(getattr(requirement, name)), int)

    def test_j_no_c13_path_collisions(self):
        additional = {item.path for item in self.contract.path_requirements()}
        runtime = {item.path for item in self.installation.resource_requirements()}
        self.assertEqual(additional & runtime, set())

    def test_k_c17_config_metadata_projection(self):
        directory, config = self.contract.path_requirements()[6:8]
        self.assertEqual(config.path, PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH)
        self.assertEqual(config.path, "/etc/omnilyzer/deployment/dev/executor.json")
        self.assertEqual(directory.path, str(PurePosixPath(PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH).parent))
        self.assertEqual(directory.path, "/etc/omnilyzer/deployment/dev")
        self.assertEqual((directory.mode, config.mode),
                         (EXECUTOR_SERVICE_CONFIG_DIRECTORY_MODE, EXECUTOR_SERVICE_CONFIG_FILE_MODE))
        self.assertEqual((directory.mode, config.mode), (0o750, 0o640))
        for requirement in (directory, config):
            self.assertEqual((requirement.owner_uid, requirement.group_gid), (0, self.installation.executor_gid))

    def test_l_c21_layout_and_open_integrity_boundary(self):
        paths = self.contract.path_requirements()
        self.assertEqual(tuple(item.path for item in paths[1:4]),
                         (self.layout.installation_root, self.layout.application_root, self.layout.virtualenv_root))
        self.assertTrue(all((item.mode, item.owner_uid, item.group_gid) == (0o755, 0, 0)
                            for item in paths[:4]))
        self.assertEqual(self.layout.python_executable, "/opt/omnilyzer/deployment/venv/bin/python")
        self.assertNotIn(self.layout.python_executable, tuple(item.path for item in paths))
        with patch.object(module, "_DevHostServiceLayout", wraps=DevHostServiceLayout) as constructor:
            contract = module.DevHostProvisioningContract(installation=self.installation)
            self.assertIs(contract.service_layout(), contract.service_layout())
            constructor.assert_called_once_with()

    def test_m_run_future_creation_lifecycle_and_c22_mode(self):
        parents = self.contract.path_requirements()[-2:]
        self.assertEqual(tuple(item.path for item in parents), ("/run/omnilyzer", "/run/omnilyzer/deployment"))
        for item in parents:
            self.assertEqual((item.kind, item.mode, item.owner_uid, item.group_gid, item.lifecycle),
                             ("directory", 0o755, 0, 0, "future-systemd-socket-directory-creation-only"))
        asset = Path(__file__).absolute().parents[1] / "systemd/dev" / self.layout.executor_socket_unit_name
        self.assertIn("\nDirectoryMode=0755\n", asset.read_text())

    def test_n_exact_systemd_mappings(self):
        assets = self.contract.installed_asset_requirements()
        self.assertEqual(len(assets), 2)
        digests = (
            "4211b0a4498548a54c4aedeaeb419aef84fb76d16f9da5f60a40b20be1daf95f",
            "a79a89ccd97c1de6b7038337ab1f7089c4dad501532e376a71a811854d1e8c86",
        )
        for item, name, digest in zip(
                assets,
                (self.layout.executor_socket_unit_name,
                 self.layout.executor_service_unit_name),
                digests,
                strict=True):
            self.assertEqual(dataclasses.astuple(item), (
                "deployment/systemd/dev/" + name, "/etc/systemd/system/" + name,
                digest, 0o644, 0, 0,
            ))
            repository = Path(__file__).absolute().parents[2]
            source = repository / item.source_path
            self.assertTrue(source.is_file())
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), item.sha256)

    def test_o_os_systemd_directory_not_provisioned(self):
        self.assertNotIn("/etc/systemd/system", tuple(item.path for item in self.contract.path_requirements()))

    def test_p_no_root_user_or_group_alias(self):
        for user in self.contract.user_requirements():
            self.assertGreater(user.uid, 0)
            self.assertGreater(user.primary_gid, 0)
        self.assertEqual(len({group.gid for group in self.contract.group_requirements()}), 4)
        # All positive bounded IDs project, without a second set of fixed numbers.
        installation = _installation(broker_uid=MAX_UID_GID, executor_uid=MAX_UID_GID - 1)
        self.assertEqual(module.DevHostProvisioningContract(installation=installation).user_requirements()[0].uid,
                         MAX_UID_GID)

    def test_q_no_privilege_references(self):
        source = inspect.getsource(module)
        for forbidden in ("docker.sock", "SupplementaryGroups=docker", "sudoers", "polkit",
                          "CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "setuid helper"):
            self.assertNotIn(forbidden, source)
        for name in _API[:4]:
            self.assertFalse(any(word in field.name for field in dataclasses.fields(getattr(module, name))
                                 for word in ("docker", "sudo", "capability", "password", "shell", "home")))

    def test_r_only_pure_projection_authority(self):
        tree = ast.parse(inspect.getsource(module))
        imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
        self.assertTrue(all(isinstance(node, ast.ImportFrom) for node in imports))
        self.assertEqual(tuple(node.module for node in imports), (
            "dataclasses", "pathlib", "re", "installation_contract", "executor_service_config", "host_service_layout",
        ))
        allowed = {
            "type", "len", "all", "any", "str", "tuple", "frozenset", "TypeError", "ValueError",
            "_dataclass", "_field", "_PurePosixPath", "_fullmatch", "_valid_id", "_valid_name",
            "_valid_path", "_valid_metadata", "_DevHostServiceLayout", "HostGroupRequirement",
            "HostUserRequirement", "HostPathRequirement", "HostInstalledAssetRequirement",
        }
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, (ast.AsyncFunctionDef, ast.Await))
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    self.assertIn(node.func.id, allowed)
                else:
                    self.assertIsInstance(node.func, ast.Attribute)
                    self.assertIn(node.func.attr, ("is_absolute", "startswith", "endswith", "split",
                                                  "resource_requirements", "__setattr__"))
                    if node.func.attr == "__setattr__":
                        self.assertIsInstance(node.func.value, ast.Name)
                        self.assertEqual(node.func.value.id, "object")

    def test_s_no_config_or_runtime_creation_and_no_duplicate_literals(self):
        tree = ast.parse(inspect.getsource(module))
        forbidden = {"canonical_bytes", "initialize", "save", "open", "write"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
                self.assertNotIn(name, forbidden)
        literals = {node.value for node in ast.walk(tree)
                    if isinstance(node, ast.Constant) and type(node.value) is str}
        for resource in self.installation.resource_requirements():
            self.assertNotIn(resource.path, literals)
        for path in (self.layout.installation_root, self.layout.application_root, self.layout.virtualenv_root,
                     self.layout.python_executable, PRODUCTION_EXECUTOR_SERVICE_CONFIG_PATH):
            self.assertNotIn(path, literals)
        for name in (self.layout.broker_user, self.layout.executor_user, self.layout.replay_group,
                     self.layout.socket_group, self.layout.executor_socket_unit_name,
                     self.layout.executor_service_unit_name):
            self.assertNotIn(name, literals)
        source = inspect.getsource(module)
        for forbidden in ("trusthansen", "/home/", "/repos/", "useradd", "groupadd", "systemctl", "pip install"):
            self.assertNotIn(forbidden, source)

    def test_t_exact_value_class_field_shapes(self):
        shapes = (
            (module.HostGroupRequirement, ("name", "gid")),
            (module.HostUserRequirement, ("name", "uid", "primary_gid", "supplementary_gids")),
            (module.HostPathRequirement, ("path", "kind", "mode", "owner_uid", "group_gid", "lifecycle")),
            (module.HostInstalledAssetRequirement,
             ("source_path", "destination_path", "sha256", "mode", "owner_uid", "group_gid")),
        )
        for cls, names in shapes:
            self.assertEqual(tuple(field.name for field in dataclasses.fields(cls)), names)

    def test_value_classes_reject_wrong_types_and_bounds(self):
        class Text(str):
            """A string subclass is not an exact built-in string."""
        class Number(int):
            """An integer subclass is not an exact built-in integer."""
        class Collection(tuple):
            """A tuple subclass is not an exact built-in tuple."""
        group = self.contract.group_requirements()[0]
        user = self.contract.user_requirements()[0]
        path = self.contract.path_requirements()[0]
        asset = self.contract.installed_asset_requirements()[0]
        attacks = []
        for value in (None, "", Text("name"), "Root", "1name", "a b", "a/b", "a:b", "a\0", "é", "a" * 32):
            attacks.extend(((group, {"name": value}), (user, {"name": value})))
        for value in (None, True, 1.0, Number(1), -1, 0, MAX_UID_GID + 1):
            attacks.extend(((group, {"gid": value}), (user, {"uid": value}), (user, {"primary_gid": value})))
        for value in ([1203], Collection((1203,)), (True,), (0,), (-1,), (MAX_UID_GID + 1,), (1203, 1203), (1201,)):
            attacks.append((user, {"supplementary_gids": value}))
        for value in (None, True, -1, MAX_UID_GID + 1, Number(0)):
            for requirement in (path, asset):
                attacks.extend((requirement, {field: value}) for field in ("owner_uid", "group_gid"))
        for value in (True, -1, 0o10000, Number(0), 1.0):
            attacks.extend(((path, {"mode": value}), (asset, {"mode": value})))
        for value in (None, "", Text("0" * 64), "0" * 63, "0" * 65,
                      "A" * 64, "g" * 64):
            attacks.append((asset, {"sha256": value}))
        attacks.extend(((path, {"kind": "unix_socket"}), (path, {"kind": Text("directory")}),
                        (path, {"lifecycle": "create-now"}),
                        (path, {"lifecycle": Text("must-exist-before-activation")})))
        for requirement, change in attacks:
            with self.subTest(change=change):
                with self.assertRaises(TypeError) as caught:
                    dataclasses.replace(requirement, **change)
                self.assertEqual(str(caught.exception), "DEV host provisioning contract is invalid")
        # Root ownership and boundary modes are valid metadata for paths/assets.
        for requirement in (path, asset):
            for mode in (0, 0o7777):
                dataclasses.replace(requirement, mode=mode, owner_uid=MAX_UID_GID, group_gid=0)

    def test_path_value_classes_reject_noncanonical_text(self):
        path = self.contract.path_requirements()[0]
        asset = self.contract.installed_asset_requirements()[0]
        for value in (None, "", "relative", "//opt/app", "/opt/app/", "/opt/./app", "/opt/../app",
                      "/opt//app", "/opt/\0app"):
            for requirement, field in ((path, "path"), (asset, "destination_path")):
                with self.assertRaises(TypeError):
                    dataclasses.replace(requirement, **{field: value})
        for value in (None, "", "/absolute", "./a", "../a", "a/../b", "a/./b", "a//b", "a/", "a\0b"):
            with self.assertRaises(TypeError):
                dataclasses.replace(asset, source_path=value)


if __name__ == "__main__":
    unittest.main()
