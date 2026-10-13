import unittest
from unittest.mock import patch
from utils.core_patch import PATCHES, patch_bytes, digest


class CorePatchTests(unittest.TestCase):
    def test_unknown_version_is_refused(self):
        with self.assertRaises(ValueError):
            patch_bytes(b"unknown executable")

    def fixture(self):
        data = bytearray(b"\x90" * (max(p.offset + len(p.expected) for p in PATCHES) + 20))
        for item in PATCHES:
            data[item.offset:item.offset + len(item.expected)] = item.expected
        return bytes(data)

    def test_only_reviewed_bytes_change(self):
        original = self.fixture()
        with patch("utils.core_patch.ORIGINAL_SHA256", digest(original)):
            output, manifest = patch_bytes(original)
        allowed = {p.offset + i for p in PATCHES for i in range(len(p.replacement))}
        changed = {i for i, (before, after) in enumerate(zip(original, output)) if before != after}
        self.assertEqual(len(output), len(original))
        self.assertLessEqual(changed, allowed)
        self.assertEqual(manifest["byte_changes"], len(changed))
        for item in PATCHES:
            self.assertEqual(output[item.offset:item.offset+len(item.replacement)], item.replacement)

    def test_instruction_mismatch_is_refused_even_with_matching_digest(self):
        original = bytearray(self.fixture())
        original[PATCHES[0].offset] = 0
        with patch("utils.core_patch.ORIGINAL_SHA256", digest(original)):
            with self.assertRaises(ValueError):
                patch_bytes(bytes(original))
