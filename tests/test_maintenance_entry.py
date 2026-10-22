"""Maintenance must be independent of UI/credentials and keep errors private."""
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from utils import maintenance_entry as entry


class MaintenanceTests(unittest.TestCase):
    def test_normal_start_has_no_side_effects(self):
        with patch.object(entry, '_journal') as journal:
            self.assertIsNone(entry.run_maintenance(['--connect', '--minimized']))
            journal.assert_not_called()

    def test_startup_requires_existing_elevation_and_passes_ownership_mode(self):
        shell = SimpleNamespace(IsUserAnAdmin=Mock(return_value=False))
        with patch.object(entry.ctypes, 'windll', SimpleNamespace(shell32=shell), create=True), \
             patch.object(entry, '_journal'), patch('utils.auth_startup.set_startup') as setup:
            self.assertEqual(entry.run_maintenance(['--setup-startup', 'enable']), 1)
            setup.assert_not_called()
            shell.IsUserAnAdmin.return_value = True
            self.assertEqual(entry.run_maintenance(['--setup-startup', 'remove-owned'],
                                                 entry_script=Path('example.py')), 0)
            setup.assert_called_once_with(False, entry_script=Path('example.py'), remove_only_matching=True)

    def test_failure_records_type_but_not_private_exception_text(self):
        journal = Mock()
        with patch.object(entry, '_journal', return_value=journal), \
             patch('utils.driver_setup.probe_driver', side_effect=RuntimeError('private-secret-path')):
            self.assertEqual(entry.run_maintenance(['--check-driver']), 1)
        events = str(journal.mock_calls)
        self.assertIn('RuntimeError', events)
        self.assertNotIn('private-secret-path', events)
        self.assertIn('maintenance_end', events)

    def test_entrypoint_does_not_import_ui_or_credentials_for_probe(self):
        # A fresh process prevents already-imported modules from masking a regression.
        script = '''
import importlib.abc, runpy, sys
from unittest.mock import patch
from utils import maintenance_entry, driver_setup
class RejectUI(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in ('flet', 'utils.credential_store', 'utils.auth_service'):
            raise AssertionError('Maintenance imported a UI/account dependency')
sys.meta_path.insert(0, RejectUI())
sys.argv = ['campus_flet.py', '--check-driver']
with patch.object(maintenance_entry, '_journal'), patch.object(driver_setup, 'probe_driver', return_value={'state':'ready'}):
    try:
        runpy.run_path('campus_flet.py', run_name='__main__')
    except SystemExit as result:
        assert result.code == 0, result.code
    else:
        raise AssertionError('Maintenance did not exit')
print('isolated')
'''
        result = subprocess.run([sys.executable, '-c', script],
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'isolated')

    def test_conflicting_modes_never_execute(self):
        with patch.object(entry, '_journal') as journal, patch('sys.stderr'):
            with self.assertRaises(SystemExit) as caught:
                entry.run_maintenance(['--check-driver', '--setup-startup', 'enable'])
            self.assertEqual(caught.exception.code, 2)
            journal.assert_not_called()


if __name__ == '__main__':
    unittest.main()
