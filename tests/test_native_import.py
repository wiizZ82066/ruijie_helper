"""Synthetic native profiles only; importing never starts a network session."""
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

from fixture_support import fixture_directory
from utils import auth_credentials as native


class NativeImportTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_directory(self, "native-import")
        self.material = hashlib.md5(b"synthetic-import-material").digest()
        self.global_path = self.root / "SuConfig.dat"
        self.user_path = self.root / "users" / "synthetic-account" / "userinfo.dat"
        self.user_path.parent.mkdir(parents=True)
        self.global_path.write_bytes(native.encode_profile(b"[PUBLIC]\r\nName=synthetic-account\r\n"))
        self.write_profile(native.encrypt_native_password("FakePass9", self.material))
        guard = patch.object(native, "_verify_import_core")
        self.guard = guard.start()
        self.addCleanup(guard.stop)

    def write_profile(self, cipher, extra="SaveCheck=1\r\n"):
        text = "[PUBLIC]\r\nPassword=" + cipher + "\r\n" + extra
        self.user_path.write_bytes(native.encode_profile(text.encode("ascii")))

    def read(self):
        return native.read_saved_credentials(self.root, material_provider=lambda: self.material)

    def test_known_native_cipher_vector(self):
        material = bytes.fromhex("133457799bbcdff1") + bytes(range(8, 16))
        self.assertEqual(native._decrypt_saved_password("DA500B4022741E1A90F0138F58E24A84", material), "FakePass9")

    def test_selected_account_only_and_no_writes(self):
        unrelated = self.root / "users" / "unselected" / "userinfo.dat"
        unrelated.parent.mkdir()
        unrelated.write_bytes(b"invalid unselected profile")
        before = {p: p.read_bytes() for p in self.root.rglob("*.dat")}
        value = self.read()
        self.assertEqual(value.username, "synthetic-account")
        self.assertEqual(value.password, "FakePass9")
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob("*.dat")})
        self.assertNotIn(value.password, repr(value))
        self.guard.assert_called_once_with(self.root.resolve())

    def test_block_boundaries_and_native_character_encoding(self):
        for password in ["12345678", "x" * 128, "密码Demo9", " pass "]:
            with self.subTest(length=len(password)):
                cipher = native.encrypt_native_password(password, self.material)
                self.assertEqual(native._decrypt_saved_password(cipher, self.material), password)

    def test_malformed_cipher_or_padding_never_returns_garbage(self):
        from Crypto.Cipher import DES
        cipher = DES.new(self.material[:8], DES.MODE_CBC, iv=self.material[8:]).encrypt(b"a\0bxxxxx").hex()
        for value in ["", "not-hex", "AB" * 7, "AB" * 136, cipher]:
            with self.subTest(length=len(value)), self.assertRaises(native.CredentialPreparationError):
                native._decrypt_saved_password(value, self.material)

    def test_missing_or_disabled_saved_password(self):
        for cipher, extra in [("", ""), ("AA" * 8, "SaveCheck=0\r\n")]:
            self.write_profile(cipher, extra)
            with self.assertRaises(native.CredentialPreparationError):
                self.read()

    def test_missing_profile_does_not_expose_account_path(self):
        self.user_path.unlink()
        with self.assertRaises(native.CredentialPreparationError) as error:
            self.read()
        self.assertNotIn("synthetic-account", str(error.exception))
        self.assertNotIn(str(self.root), str(error.exception))

    def test_unknown_core_does_not_read_credentials(self):
        self.guard.side_effect = ValueError("unsupported core")
        with patch.object(native, "_read_import_profile") as read:
            with self.assertRaises(native.CredentialPreparationError):
                self.read()
            read.assert_not_called()

    def test_changed_account_during_read_is_rejected(self):
        def material():
            self.global_path.write_bytes(native.encode_profile(b"[PUBLIC]\r\nName=another-account\r\n"))
            return self.material
        with self.assertRaisesRegex(native.CredentialPreparationError, "正在变化"):
            native.read_saved_credentials(self.root, material_provider=material)

    def test_duplicate_field_and_redirected_directory_are_rejected(self):
        self.write_profile("AA" * 8, "Password=" + "BB" * 8 + "\r\n")
        with self.assertRaises(native.CredentialPreparationError):
            self.read()
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaises(native.CredentialPreparationError):
                self.read()

    def test_oversized_profile_rejected_before_decode(self):
        self.user_path.write_bytes(b"x" * (native._MAX_PROFILE + 1))
        with self.assertRaises(native.CredentialPreparationError):
            self.read()
