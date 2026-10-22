"""Read-only driver detection using synthetic DLLs and process outcomes."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from fixture_support import fixture_directory
from utils import driver_setup as setup


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.root = fixture_directory(self, 'driver')

    def test_missing_does_not_load_any_dll(self):
        with patch.dict(setup.os.environ, WINDIR=str(self.root)), patch.object(setup.C, 'CDLL') as load:
            self.assertEqual(setup.probe_driver()['state'], 'missing')
            load.assert_not_called()

    def test_broken_and_denied_are_not_reported_as_missing(self):
        system = self.root / 'System32' / 'Npcap'
        system.mkdir(parents=True)
        (system / 'wpcap.dll').touch()
        for winerror, expected in ((193, 'broken'), (5, 'denied')):
            error = OSError('synthetic private details')
            error.winerror = winerror
            with patch.dict(setup.os.environ, WINDIR=str(self.root)), patch.object(setup.C, 'CDLL', side_effect=error):
                data = setup.probe_driver()
                self.assertEqual(data['state'], expected)
                self.assertNotIn('private', json.dumps(data))

    def test_no_interfaces_is_not_ready_or_missing(self):
        system = self.root / 'System32'
        system.mkdir()
        (system / 'wpcap.dll').touch()
        dll = Mock()
        dll.pcap_findalldevs.return_value = 0
        with patch.dict(setup.os.environ, WINDIR=str(self.root)), patch.object(setup.C, 'CDLL', return_value=dll):
            self.assertEqual(setup.probe_driver()['state'], 'no_interfaces')
            dll.pcap_open_live.assert_not_called()

    def test_process_failure_is_unknown_and_bounded(self):
        with patch.object(setup.subprocess, 'run', side_effect=setup.subprocess.TimeoutExpired('probe', 12)) as run:
            self.assertEqual(setup.check_driver()['state'], 'unknown')
            self.assertEqual(run.call_args.kwargs['timeout'], 12)

    def test_probe_output_is_normalized(self):
        response = SimpleNamespace(returncode=0, stdout=b'')
        with patch.object(setup.subprocess, 'run', return_value=response):
            self.assertEqual(setup.check_driver(), setup.result('ready'))

    def test_security_block_is_not_misreported_as_missing_driver(self):
        for code in (225, 226):
            error = OSError('private security path')
            error.winerror = code
            with patch.object(setup.subprocess, 'run', side_effect=error) as run:
                self.assertEqual(setup.check_driver(), setup.result('blocked'))
                run.assert_called_once()
