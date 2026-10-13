"""Synthetic credentials only; native DPAPI is mocked, and no real vault is read."""
import ctypes
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from fixture_support import fixture_directory

from utils.credential_store import (Credentials, CredentialStore, CredentialStoreError,
                                    CredentialUnlockError, WindowsDPAPI)


class FakeProtector:
    def __init__(self):
        self.entries = {}
        self.encrypt_calls = 0
        self.fail_encrypt = self.fail_decrypt = False
        self.on_encrypt = None

    def encrypt(self, plaintext):
        self.encrypt_calls += 1
        if self.fail_encrypt:
            raise RuntimeError("synthetic-provider-secret")
        ciphertext = b"offline-only:" + hashlib.sha256(plaintext).digest()
        self.entries[ciphertext] = plaintext
        if self.on_encrypt:
            self.on_encrypt()
        return ciphertext

    def decrypt(self, ciphertext):
        if self.fail_decrypt:
            raise RuntimeError("synthetic-provider-secret")
        return self.entries[ciphertext]


class CredentialStoreTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_directory(self, "credential-store")
        self.protector = FakeProtector()
        self.store = CredentialStore(self.root / "fake profile", self.protector)
        self.first = Credentials("student-demo-甲", "fake-test-password-123")
        self.second = Credentials("student-demo-乙", "different-fake-password-456")
        for patcher in (patch("subprocess.run", side_effect=AssertionError("no commands")),
                        patch("subprocess.Popen", side_effect=AssertionError("no processes")),
                        patch("ctypes.WinDLL", side_effect=AssertionError("no native encryption"), create=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def assert_no_plaintext(self, content):
        for credentials in (self.first, self.second):
            for value in (credentials.username, credentials.password):
                self.assertNotIn(value.encode("utf-8"), content)
                self.assertNotIn(value.encode("utf-16le"), content)

    def test_credential_repr_does_not_reveal_either_field(self):
        self.assertNotIn(self.first.username, repr(self.first))
        self.assertNotIn(self.first.password, repr(self.first))
        self.assertEqual(repr(self.first), "Credentials()")

    def test_empty_load_creates_no_directory(self):
        self.assertIsNone(self.store.load())
        self.assertFalse(self.store.path.parent.exists())
        self.assertFalse(self.store.remembered)

    def test_without_remembering_only_current_instance_holds_credentials(self):
        self.store.save(self.first, remember=False)
        self.assertEqual(self.store.load(), self.first)
        self.assertFalse(self.store.path.parent.exists())
        self.assertEqual(self.protector.encrypt_calls, 0)
        self.assertIsNone(CredentialStore(self.store.path.parent, self.protector).load())

    def test_username_and_password_are_encrypted_together_and_roundtrip(self):
        self.store.save(self.first, remember=True)
        content = self.store.path.read_bytes()
        self.assert_no_plaintext(content)
        self.assertTrue(content.startswith(CredentialStore._HEADER))
        self.assertTrue(self.store.remembered)
        self.assertEqual(CredentialStore(self.store.path.parent, self.protector).load(), self.first)
        self.assertEqual(len(self.protector.entries), 1)

    def test_unchecking_remember_removes_old_saved_entry_and_retains_session(self):
        self.store.save(self.first, remember=True)
        self.store.save(self.second, remember=False)
        self.assertFalse(self.store.path.exists())
        self.assertEqual(self.store.load(), self.second)

    def test_corrupt_file_cannot_be_silently_overwritten_or_removed(self):
        self.store.path.parent.mkdir()
        self.store.path.write_bytes(b"unknown credentials format")
        for remember in (True, False):
            with self.subTest(remember=remember), self.assertRaises(CredentialUnlockError):
                self.store.save(self.first, remember=remember)
            self.assertEqual(self.store.path.read_bytes(), b"unknown credentials format")
        self.assertTrue(self.store.locked)

    def test_load_decryption_failure_locks_saves_and_redacts_provider_error(self):
        self.store.save(self.first, remember=True)
        previous = self.store.path.read_bytes()
        self.protector.fail_decrypt = True
        with self.assertRaises(CredentialUnlockError) as caught:
            self.store.load()
        self.assertNotIn("synthetic-provider-secret", str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)
        self.protector.fail_decrypt = False
        with self.assertRaises(CredentialUnlockError):
            self.store.save(self.second, remember=True)
        self.assertEqual(self.store.path.read_bytes(), previous)

    def test_explicit_clear_unlocks_store_and_forgets_memory(self):
        self.store.path.parent.mkdir()
        self.store.path.write_bytes(b"unreadable")
        with self.assertRaises(CredentialUnlockError):
            self.store.load()
        self.store.clear()
        self.assertFalse(self.store.locked)
        self.assertIsNone(self.store.load())
        self.store.save(self.second, remember=True)
        self.assertEqual(self.store.load(), self.second)

    def test_encryption_failure_preserves_previous_file(self):
        self.store.save(self.first, remember=True)
        previous = self.store.path.read_bytes()
        self.protector.fail_encrypt = True
        with self.assertRaises(CredentialStoreError) as caught:
            self.store.save(self.second, remember=True)
        self.assertNotIn("synthetic-provider-secret", str(caught.exception))
        self.assertEqual(self.store.path.read_bytes(), previous)

    def test_replace_failure_keeps_old_file_and_removes_temporary_ciphertext(self):
        self.store.save(self.first, remember=True)
        previous = self.store.path.read_bytes()
        def reject(source, target):
            self.assertEqual(Path(target).read_bytes(), previous)
            self.assert_no_plaintext(Path(source).read_bytes())
            raise PermissionError("synthetic file busy")
        with patch("utils.credential_store.os.replace", side_effect=reject), \
             self.assertRaises(CredentialStoreError):
            self.store.save(self.second, remember=True)
        self.assertEqual(self.store.path.read_bytes(), previous)
        self.assertEqual(list(self.store.path.parent.iterdir()), [self.store.path])

    def test_file_changed_during_encryption_is_not_overwritten(self):
        self.store.save(self.first, remember=True)
        self.protector.on_encrypt = lambda: self.store.path.write_bytes(b"changed by another operation")
        with self.assertRaises(CredentialStoreError):
            self.store.save(self.second, remember=True)
        self.assertEqual(self.store.path.read_bytes(), b"changed by another operation")

    def test_decrypted_invalid_json_is_not_echoed_or_replaced(self):
        self.store.save(self.first, remember=True)
        previous = self.store.path.read_bytes()
        key = previous[len(CredentialStore._HEADER):]
        self.protector.entries[key] = ("not-json " + self.first.password).encode()
        with self.assertRaises(CredentialUnlockError) as caught:
            self.store.load()
        self.assertNotIn(self.first.password, str(caught.exception))
        self.assertEqual(self.store.path.read_bytes(), previous)


class WindowsDPAPITests(unittest.TestCase):
    def test_native_calls_use_current_user_no_ui_and_release_output(self):
        buffers, calls, freed = [], [], []
        def transform(source, description, entropy, reserved, prompt, flags, output):
            incoming = ctypes.string_at(source._obj.pbData, source._obj.cbData)
            calls.append((incoming, description, flags, reserved, prompt,
                          ctypes.string_at(entropy._obj.pbData, entropy._obj.cbData)))
            buffer = ctypes.create_string_buffer(b"fake native result")
            buffers.append(buffer)
            output._obj.cbData = len(b"fake native result")
            output._obj.pbData = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
            return 1
        crypt = SimpleNamespace(CryptProtectData=Mock(side_effect=transform),
                                CryptUnprotectData=Mock(side_effect=transform))
        kernel = SimpleNamespace(LocalFree=Mock(side_effect=lambda pointer: freed.append(pointer)))
        with patch("utils.credential_store.os.name", "nt"), \
             patch("ctypes.WinDLL", side_effect=[crypt, kernel, crypt, kernel], create=True):
            protector = WindowsDPAPI()
            self.assertEqual(protector.encrypt(b"synthetic credential pair"), b"fake native result")
            self.assertEqual(protector.decrypt(b"synthetic ciphertext"), b"fake native result")
        self.assertEqual(len(freed), 2)
        self.assertEqual([entry[2] for entry in calls], [1, 1])  # Never LOCAL_MACHINE (4).
        self.assertEqual(calls[0][1:5], (None, 1, None, None))
        self.assertEqual(calls[0][-1], calls[1][-1])
        self.assertEqual(bytes(buffers[1])[:18], b"\0" * 18)


if __name__ == "__main__":
    unittest.main()
