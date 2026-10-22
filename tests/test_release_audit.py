"""Release-gate regressions using synthetic files, Git output and host markers."""
import errno
import hashlib
import json
import unittest
from unittest.mock import call, patch

from fixture_support import fixture_directory
from tools import audit_release


class ReleaseAuditTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_directory(self, "release-audit")
        for patcher in (patch.object(audit_release, "ROOT", self.root),
                        patch.object(audit_release, "local_markers", return_value=set()),
                        patch("subprocess.run", side_effect=AssertionError("Real Git and OS commands are forbidden"))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def audit(self, *relative):
        with patch.object(audit_release, "candidates", return_value=list(relative)):
            return audit_release.audit()

    def test_force_tracked_ignored_runtime_file_is_rejected_and_account_path_redacted(self):
        account = "synthetic-account-for-test"
        relative = "users/" + account + "/settings.json"
        self.write(".gitignore", "settings.json\n")
        self.write(relative, "{}")
        self.write("safe.py", "VERSION = '1.2.3'\n")
        # Tracked output intentionally contains an ignored, force-added file.
        with patch.object(audit_release, "git", side_effect=[relative.encode() + b"\0", b"safe.py\0"]) as git:
            result = audit_release.audit()
        self.assertEqual(git.call_args_list, [call("ls-files", "-z"),
                                             call("ls-files", "--others", "--exclude-standard", "-z")])
        self.assertEqual(result["checked_files"], 1)
        self.assertEqual(result["findings"], [{"path": "users/<account>/settings.json",
                                              "category": "runtime_or_build_artifact"}])
        self.assertNotIn(account, json.dumps(result))

    def test_token_and_host_marker_report_locations_without_matched_values(self):
        token = "ghp_" + "a" * 36
        marker = "synthetic-host-marker-for-test"
        self.write("notes.md", "Example\n" + token + "\n" + marker + "\n")
        with patch.object(audit_release, "local_markers", return_value={marker}):
            result = self.audit("notes.md")
        self.assertEqual({(finding["category"], finding["line"]) for finding in result["findings"]},
                         {("github_token", 2), ("local_machine_marker", 3)})
        rendered = json.dumps(result)
        self.assertNotIn(token, rendered)
        self.assertNotIn(marker, rendered)

    def test_personal_absolute_path_literal_is_rejected_without_exposing_account(self):
        account = "synthetic-profile-for-test"
        # Construct the intentionally invalid fixture at runtime, so this test
        # source itself contains no personal or drive-rooted path literal.
        personal = "Q" + ":" + "\\" + "Users" + "\\" + account + "\\" + "example"
        for suffix in (".py", ".PY"):
            with self.subTest(suffix=suffix):
                relative = "bad_fixture" + suffix
                self.write(relative, "LOCATION = " + json.dumps(personal) + "\n")
                result = self.audit(relative)
                self.assertEqual({finding["category"] for finding in result["findings"]},
                                 {"personal_windows_directory", "absolute_windows_path_literal"})
                self.assertNotIn(account, json.dumps(result))
                self.assertNotIn(personal, json.dumps(result))

    def test_dynamic_paths_and_public_version_hash_are_allowed(self):
        digest = hashlib.sha256(b"synthetic public release artifact").hexdigest()
        self.write("portable.py", "from pathlib import Path\nimport os\n"
                   "ROOT = Path(os.environ.get('APPDATA', Path.home())) / 'ExampleApp'\n"
                   "VERSION = '1.2.3'\nRELEASE_SHA256 = " + repr(digest) + "\n")
        result = self.audit("portable.py")
        self.assertEqual(result["checked_files"], 1)
        self.assertEqual(result["findings"], [])

    def test_nsis_sources_are_audited_for_secrets_and_machine_paths(self):
        token = "ghp_" + "b" * 36
        absolute = "Q" + ":" + "\\" + "build" + "\\" + "app.exe"
        for suffix in (".nsi", ".nsh"):
            relative = "installer" + suffix
            self.write(relative, '; ' + token + '\nFile "' + absolute + '"\n')
            result = self.audit(relative)
            self.assertEqual({item["category"] for item in result["findings"]},
                             {"github_token", "absolute_windows_path_literal"})
            self.assertNotIn(token, json.dumps(result))
            self.assertNotIn(absolute, json.dumps(result))

    def test_symlink_outside_release_root_is_rejected_without_reading_target(self):
        outside = fixture_directory(self, "release-audit-outside") / "outside.py"
        outside.write_text("synthetic outside file; not Python source", encoding="utf-8")
        link = self.root / "linked.py"
        try:
            link.symlink_to(outside)
        except OSError as error:
            if error.errno in (errno.EPERM, errno.EACCES) or getattr(error, "winerror", None) in (5, 1314):
                self.skipTest("This test runner lacks symbolic-link creation permission")
            raise
        result = self.audit("linked.py")
        self.assertEqual(result["checked_files"], 0)
        self.assertEqual(result["findings"], [{"path": "linked.py", "category": "external_symlink"}])


if __name__ == "__main__":
    unittest.main()
