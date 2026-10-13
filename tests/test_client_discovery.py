"""Offline discovery tests: fake registry and non-executable temporary files."""
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from fixture_support import fixture_directory

from utils import client_discovery as discovery


class FakeKey:
    def __init__(self, registry, identity):
        self.registry, self.identity = registry, identity

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class FakeRegistry:
    HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER = "machine", "user"
    KEY_READ, KEY_WOW64_64KEY, KEY_WOW64_32KEY = 1, 256, 512

    def __init__(self):
        self.values = {}
        self.reads = []

    def add(self, key, values, root="machine", view=0):
        self.values[(root, view, key)] = values

    def OpenKey(self, root, key, reserved, access):
        identity = (root, access & (256 | 512), key)
        self.reads.append(identity)
        if identity not in self.values:
            raise FileNotFoundError(key)
        return FakeKey(self, identity)

    def QueryValueEx(self, handle, name):
        if name not in self.values[handle.identity]:
            raise FileNotFoundError(name)
        return self.values[handle.identity][name], 1

    def children(self, handle):
        root, view, key = handle.identity
        prefix = key + "\\"
        return [entry[len(prefix):] for owner, scope, entry in self.values
                if owner == root and scope == view and entry.startswith(prefix)
                and "\\" not in entry[len(prefix):]]

    def QueryInfoKey(self, handle):
        return len(self.children(handle)), 0, 0

    def EnumKey(self, handle, index):
        return self.children(handle)[index]


class ClientDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_directory(self, "client-discovery")
        self.registry = FakeRegistry()
        for patcher in (patch.object(discovery, "winreg", self.registry),
                        patch.object(discovery, "_nearby_candidates", return_value=iter(())),
                        patch("subprocess.run", side_effect=AssertionError("no commands")),
                        patch("subprocess.Popen", side_effect=AssertionError("no processes")),
                        patch("os.walk", side_effect=AssertionError("no disk scans")),
                        patch.object(Path, "read_text", side_effect=AssertionError("no configuration reads")),
                        patch.object(Path, "read_bytes", side_effect=AssertionError("no credential or binary reads"))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def client(self, name):
        directory = self.root / name
        directory.mkdir()
        for filename in ("8021x.exe", "suservice.exe"):
            (directory / filename).write_bytes(b"test fixture, not executable")
        return directory.resolve()

    def service(self, value):
        self.registry.add(r"SYSTEM\CurrentControlSet\Services\RJSuService", {"ImagePath": value})

    def test_valid_saved_selection_wins_without_registry_reads(self):
        chosen, other = self.client("user choice"), self.client("service choice")
        self.service(f'"{other / "suservice.exe"}"')
        self.assertEqual(discovery.discover_client_dir(chosen), str(chosen))
        self.assertEqual(self.registry.reads, [])

    def test_stale_saved_path_follows_moved_service_install(self):
        moved = self.client("moved location")
        self.service(f'"{moved / "SuService.exe"}" -service')
        self.assertEqual(discovery.discover_client_dir(self.root / "old location"), str(moved))

    def test_empty_input_does_not_turn_into_working_directory(self):
        for value in (None, "", "   ", '""', 123, []):
            with self.subTest(value=value):
                self.assertFalse(discovery.is_client_dir(value))
                self.assertIsNone(discovery.discover_client_dir(value))

    def test_only_complete_client_directory_is_valid(self):
        incomplete = self.root / "incomplete"
        incomplete.mkdir()
        (incomplete / "8021x.exe").write_bytes(b"fixture")
        self.assertFalse(discovery.is_client_dir(incomplete))
        complete = self.client("complete")
        self.assertFalse(discovery.is_client_dir(complete / "8021x.exe"))
        self.assertTrue(discovery.is_client_dir(str(complete)))

    def test_registry_command_parses_quotes_spaces_arguments_and_icon_index(self):
        directory = self.client("directory with spaces")
        executable = directory / "SuService.EXE"
        for command in (f'"{executable}"', f'"{executable}" --service',
                        str(executable), f"{executable} --service", f'"{executable}",0',
                        f"{executable},-3"):
            with self.subTest(command=command):
                self.assertEqual(discovery._command_directory(command), directory)
        for command in (None, "", '"unterminated.exe', "not-an-executable.dll"):
            self.assertIsNone(discovery._command_directory(command))

    def test_expandable_service_path_is_supported(self):
        directory = self.client("environment folder")
        with patch.dict(os.environ, {"CAMPUS_DISCOVERY_FIXTURE": str(directory)}):
            self.service(r'"%CAMPUS_DISCOVERY_FIXTURE%\suservice.exe"')
            self.assertEqual(discovery.discover_client_dir(), str(directory))

    def test_service_is_preferred_over_stale_uninstall_entry(self):
        service, stale = self.client("current service"), self.client("old installation")
        self.service(str(service / "suservice.exe"))
        self.uninstall(stale)
        self.assertEqual(discovery.discover_client_dir(), str(service))

    def uninstall(self, directory, name="Ruijie Supplicant", root="machine", view=512,
                  field="InstallLocation"):
        location = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        self.registry.add(location, {}, root=root, view=view)
        value = str(directory) if field == "InstallLocation" else f'"{directory / "RuijieSupplicant.exe"}",0'
        self.registry.add(location + "\\product", {"DisplayName": name, field: value}, root=root, view=view)

    def test_32bit_machine_uninstall_and_64bit_user_uninstall_are_read(self):
        directory = self.client("registry installation")
        for root, view in (("machine", 512), ("user", 256)):
            with self.subTest(root=root, view=view):
                self.registry.values.clear()
                self.uninstall(directory, name="锐捷认证客户端", root=root, view=view)
                self.assertEqual(discovery.discover_client_dir(), str(directory))

    def test_uninstall_icon_can_locate_directory_without_installlocation(self):
        directory = self.client("icon fallback")
        self.uninstall(directory, field="DisplayIcon")
        self.assertEqual(discovery.discover_client_dir(), str(directory))

    def test_unrelated_uninstall_product_is_not_used(self):
        directory = self.client("unrelated registry item")
        self.uninstall(directory, name="Another product")
        self.assertIsNone(discovery.discover_client_dir())

    def test_app_paths_record_is_supported(self):
        directory = self.client("app registration")
        key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\RuijieSupplicant.exe"
        self.registry.add(key, {"": str(directory / "RuijieSupplicant.exe")}, view=256)
        self.assertEqual(discovery.discover_client_dir(), str(directory))

    def test_nearby_candidate_used_when_registry_unavailable(self):
        directory = self.client("near the program")
        with patch.object(discovery, "winreg", None), \
             patch.object(discovery, "_nearby_candidates", return_value=iter([self.root / "missing", directory])):
            self.assertEqual(discovery.discover_client_dir(), str(directory))


if __name__ == "__main__":
    unittest.main()
