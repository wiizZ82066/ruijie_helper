import contextlib
import hashlib
from pathlib import Path
import time
import unittest
from fixture_support import fixture_directory
from unittest.mock import patch

from utils.auth_credentials import (CredentialPreparationError, decode_profile, encode_profile,
    encrypt_native_password, _build_profiles, _get, _set, _text, _user_path, prepare_credentials)
from utils.credential_store import Credentials
from utils.auth_runtime import CoreSession


class CodecTests(unittest.TestCase):
    def test_native_decoder_golden_literal(self):
        # Verified with original 0x432498 in analysis/native_codec_oracle.c.
        plain = bytes.fromhex("5b5055424c49435d0d0a583d310d0a")
        expected = bytes(255 - b for b in b"\0[PUBLIC]\0\r\nX=1\r\n")
        self.assertEqual(encode_profile(plain), expected)
        self.assertEqual(decode_profile(expected), plain)

    def test_predicted_dictionary_entries_and_partial_tail(self):
        # Flags 7 produce three predicted initial spaces then two literals.
        data = bytes(255 - b for b in bytes([7, 65, 66]))
        self.assertEqual(decode_profile(data), b"   AB")
        for length in [1, 7, 8, 9, 63, 64, 255, 256]:
            plain = bytes((i * 37) % 256 for i in range(length))
            self.assertEqual(decode_profile(encode_profile(plain)), plain)

    def test_native_cbc_golden(self):
        # Native 0x4b0241 observed using only this synthetic input and key/IV.
        key = bytes.fromhex("133457799bbcdff1")
        iv = bytes(range(8, 16))
        self.assertEqual(encrypt_native_password("FakePass9", key + iv),
                         "DA500B4022741E1A90F0138F58E24A84")

    def test_padding_has_no_extra_block(self):
        material = hashlib.md5(b"synthetic-serial").digest()
        self.assertEqual(len(encrypt_native_password("12345678", material)), 16)
        self.assertEqual(len(encrypt_native_password("123456789", material)), 32)

    def test_invalid_inputs(self):
        for value in [b"", b"x" * (2 * 1024 * 1024 + 1)]:
            with self.assertRaises(CredentialPreparationError):
                decode_profile(value)
        for value in ["", "bad\0pass", "x" * 129]:
            with self.assertRaises(CredentialPreparationError):
                encrypt_native_password(value, b"x" * 16)

    def test_ini_update_preserves_unrelated_sections_and_rejects_duplicate(self):
        text = "[PUBLIC]\r\nX=old\r\n[NIC]\r\nGuid=fixture-guid\r\n"
        updated = _set(text, "PUBLIC", "X", "new")
        self.assertIn("[NIC]\r\nGuid=fixture-guid", updated)
        self.assertEqual(_get(updated, "PUBLIC", "X"), "new")
        with self.assertRaises(CredentialPreparationError):
            _set("[PUBLIC]\r\nX=1\r\nX=2\r\n", "PUBLIC", "X", "3")


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_directory(self, "auth-credentials")
        self.global_path = self.root / "SuConfig.dat"
        self.template = self.root / "users" / "old-demo" / "userinfo.dat"
        self.template.parent.mkdir(parents=True)
        self.original = encode_profile(b"[PUBLIC]\r\nName=old-demo\r\n[USERS]\r\nNumber=1\r\nusername0=old-demo\r\n")
        self.global_path.write_bytes(self.original)
        self.template.write_bytes(encode_profile(b"[PUBLIC]\r\nPassword=old-cipher\r\n[NIC]\r\nGuid=fixture-guid\r\n"))
        self.credentials = Credentials("new-demo", "FakePass9")
        self.material = hashlib.md5(b"synthetic-serial").digest()

    def test_profiles_contain_no_plain_password_and_preserve_network_config(self):
        files = _build_profiles(self.root, self.credentials, self.material)
        self.assertEqual(len(files), 2)
        self.assertEqual(files[0][0], self.root / "users" / "new-demo" / "userinfo.dat")
        self.assertNotIn(b"FakePass9", b"".join(content for _, content in files))
        user = _text(files[0][1])
        self.assertNotIn("FakePass9", user)
        self.assertEqual(_get(user, "NIC", "Guid"), "fixture-guid")
        self.assertEqual(_get(user, "PUBLIC", "RunConnect"), "1")
        config = _text(files[1][1])
        self.assertEqual(_get(config, "PUBLIC", "Name"), "new-demo")
        self.assertEqual(_get(config, "PUBLIC", "ModifySave"), "1")
        self.assertEqual(_get(config, "USERS", "Number"), "2")
        self.assertEqual(self.global_path.read_bytes(), self.original)  # build is read-only

    def test_existing_account_reuses_selected_profile_without_duplicate_user(self):
        credentials = Credentials("old-demo", "FakePass9")
        files = _build_profiles(self.root, credentials, self.material)
        self.assertEqual(_get(_text(files[1][1]), "USERS", "Number"), "1")

    def test_unsafe_account_fails_without_exposing_it(self):
        for name in ["..", "CON", "foo. ", "bad\nname", "[unsafe]"]:
            with self.subTest(name=name), self.assertRaises(CredentialPreparationError) as error:
                _build_profiles(self.root, Credentials(name, "FakePass9"), self.material)
            self.assertNotIn(name, str(error.exception))

    def test_native_filename_escaping(self):
        self.assertEqual(_user_path(self.root, 'u#/:?"').parent.name, "u#23#2f#3a#3f#22")

    def test_users_junction_refused_without_reading_target(self):
        if not hasattr(Path, "is_junction"):
            self.skipTest("junction API unavailable")
        with patch.object(Path, "is_junction", return_value=True):
            with self.assertRaises(CredentialPreparationError):
                _build_profiles(self.root, self.credentials, self.material)


class FakeOps:
    def __init__(self):
        self.calls = []
        self.others = []
    def other_core_paths(self, target):
        return self.others
    def service_snapshot(self):
        return {"state": "RUNNING", "name": "RJSuService"}
    def stop_exact_core(self, target):
        self.calls.append("stop_core")


class FakeInstaller:
    def __init__(self, root, operations):
        self.target = root / "8021x.exe"
        self.target.write_bytes(b"reviewed")
        self.operations = operations
        self.journals = []
        self.fail_write = False
    def _exclusive(self):
        return contextlib.nullcontext()
    def _material(self):
        return b"reviewed", b"reviewed", {}
    def _verify_service(self, service):
        pass
    def _journal(self):
        return None
    def _save_journal(self, journal):
        self.journals.append(dict(journal))
    def _stop(self, service, journal, log):
        self.operations.calls.append("stop_service")
    def _restore_service(self, service):
        self.operations.calls.append("restore_service")
    def _atomic_write(self, path, content):
        if self.fail_write and path.name == "SuConfig.dat":
            self.fail_write = False
            raise OSError("unsafe account in filesystem error")
        path.write_bytes(content)
    def _emit(self, log, message):
        log(message)


class PreparationTests(ProfileTests):
    def setUp(self):
        super().setUp()
        self.ops = FakeOps()
        self.installer = FakeInstaller(self.root, self.ops)
        self.addCleanup(patch.stopall)
        patch("utils.core_install.CoreInstaller", return_value=self.installer).start()
        self.running = patch("utils.auth_runtime._running_core", return_value=None).start()
        self.snapshot = patch("utils.auth_runtime.result_snapshot", return_value=(123, "synthetic-hash")).start()
        self.start = patch("utils.auth_runtime.start_core", side_effect=self.start_core).start()
        self.log = []

    def start_core(self, client_dir, log):
        self.assertEqual(client_dir, self.root.resolve())
        self.ops.calls.append("start_core")
        session = CoreSession(123, time.time())
        self.running.return_value = session
        return session

    def prepare(self):
        return prepare_credentials(self.root, self.credentials, log=self.log.append,
                                   operations=self.ops, material_provider=lambda: self.material)

    def test_success_stops_core_then_restores_service_and_returns_baseline(self):
        result = self.prepare()
        self.assertEqual(result["before"], (123, "synthetic-hash"))
        self.assertIsInstance(result["started"], float)
        self.assertEqual(self.ops.calls, ["stop_service", "stop_core", "start_core", "restore_service"])
        self.start.assert_called_once()
        self.assertEqual(self.installer.journals[-1]["phase"], "complete")
        self.assertTrue((self.root / "users" / "new-demo" / "userinfo.dat").exists())
        self.assertNotIn("FakePass9", repr(self.log) + repr(self.installer.journals))
        self.assertNotIn("new-demo", repr(self.log) + repr(self.installer.journals))

    def test_other_core_refused_before_any_service_operation(self):
        self.ops.others = ["different-core"]
        with self.assertRaises(CredentialPreparationError):
            self.prepare()
        self.assertEqual(self.ops.calls, [])
        self.assertEqual(self.global_path.read_bytes(), self.original)

    def test_write_failure_rolls_back_and_restores_service_without_sensitive_error(self):
        self.installer.fail_write = True
        with self.assertRaises(CredentialPreparationError) as error:
            self.prepare()
        self.assertNotIn("unsafe account", str(error.exception))
        self.assertEqual(self.global_path.read_bytes(), self.original)
        self.assertFalse((self.root / "users" / "new-demo" / "userinfo.dat").exists())
        self.assertEqual(self.ops.calls[-1], "restore_service")
        self.assertEqual(self.installer.journals[-1]["phase"], "rolled_back")

    def test_live_core_cannot_race_profile_write(self):
        self.running.return_value = object()
        with self.assertRaises(CredentialPreparationError):
            self.prepare()
        self.assertEqual(self.global_path.read_bytes(), self.original)
        self.assertEqual(self.ops.calls[-1], "restore_service")

    def test_unknown_hash_cannot_stop_service(self):
        self.installer.target.write_bytes(b"unknown")
        with self.assertRaises(CredentialPreparationError):
            self.prepare()
        self.assertEqual(self.ops.calls, [])

    def test_service_restore_failure_is_visible_without_sensitive_data(self):
        def fail(_):
            raise OSError("new-demo FakePass9")
        self.installer._restore_service = fail
        with self.assertRaises(CredentialPreparationError) as error:
            self.prepare()
        self.assertNotIn("FakePass9", str(error.exception))
        self.assertNotIn("new-demo", str(error.exception))
        self.assertEqual(self.installer.journals[-1]["phase"], "recovery_required")

    def test_core_start_failure_rolls_back_before_restoring_service(self):
        def fail_start(client_dir, log):
            self.ops.calls.append("start_core")
            raise RuntimeError("new-demo FakePass9")
        self.start.side_effect = fail_start
        with self.assertRaises(CredentialPreparationError) as error:
            self.prepare()
        self.assertNotIn("FakePass9", str(error.exception))
        self.assertNotIn("new-demo", str(error.exception))
        self.assertEqual(self.global_path.read_bytes(), self.original)
        self.assertFalse((self.root / "users" / "new-demo" / "userinfo.dat").exists())
        self.assertEqual(self.ops.calls,
                         ["stop_service", "stop_core", "start_core", "stop_service", "stop_core", "restore_service"])
        self.assertEqual(self.installer.journals[-1]["phase"], "rolled_back")

    def test_service_cannot_replace_just_started_core(self):
        def replace_core(service):
            self.ops.calls.append("restore_service")
            self.running.return_value = CoreSession(456, time.time())
        self.installer._restore_service = replace_core
        with self.assertRaises(CredentialPreparationError):
            self.prepare()
        self.assertEqual(self.global_path.read_bytes(), self.original)
        self.assertFalse((self.root / "users" / "new-demo" / "userinfo.dat").exists())
        self.assertEqual(self.installer.journals[-1]["phase"], "rolled_back")


if __name__ == "__main__":
    unittest.main()
