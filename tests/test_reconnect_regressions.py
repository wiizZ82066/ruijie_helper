"""Synthetic driver/session/startup regressions; no host network modifications."""
import threading
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from utils import startup_network
from utils.wired_transport import ProbeError, _open_error
from utils.wired_native_session import NativeSessionMonitor
from utils.auth_runtime import CoreSession
import test_connection_modes as modes
from test_connection_modes import adapter
import test_auth_credentials as profiles
from utils.auth_credentials import _build_profiles, _text, _get


class StartupNetworkTests(unittest.TestCase):
    def test_online_never_associates_or_authenticates(self):
        with patch.object(startup_network,'internet_available',return_value=True), \
             patch.object(startup_network,'jnu_available') as wlan:
            result=startup_network.decision({'connection_mode':'auto'},('wired','synthetic'))
        self.assertFalse(result['connect']); wlan.assert_not_called()

    def test_no_campus_waits_and_wired_only_does_not_scan_wifi(self):
        with patch.object(startup_network,'internet_available',return_value=False), \
             patch.object(startup_network,'jnu_available',return_value=False) as wlan:
            self.assertFalse(startup_network.decision({'connection_mode':'auto'},('wireless',''))['connect'])
            wlan.reset_mock()
            self.assertFalse(startup_network.decision({'connection_mode':'wired'},('unplugged',''))['connect'])
            wlan.assert_not_called()

    def test_offline_with_campus_allows_login(self):
        with patch.object(startup_network,'internet_available',return_value=False), \
             patch.object(startup_network,'jnu_available',return_value=True):
            for target in [('wired','synthetic'),('wireless','')]:
                self.assertTrue(startup_network.decision({'connection_mode':'auto'},target)['connect'])

    def test_capture_access_denied_is_distinct_from_link_reset(self):
        self.assertFalse(_open_error('pcap_open_failed',b'Access is denied. private path').retryable)
        self.assertTrue(_open_error('pcap_open_failed',b'adapter disappeared').retryable)
        self.assertNotIn('private',str(_open_error('pcap_open_failed',b'Access is denied. private path')))
        self.assertFalse(ProbeError('driver_missing').retryable)


class NativeMonitorTests(unittest.TestCase):
    def setUp(self):
        self.session=CoreSession(123,1)
        self.monitor=NativeSessionMonitor(Path('synthetic-client'),self.session,'synthetic-guid')
        self.patches=[]
        for target, value in [('utils.wired_native_session.network.link_up',True),
                              ('utils.wired_native_session._running_core',self.session),
                              ('utils.wired_native_session.network.config',{'index':4,'addresses':['192.0.2.1'],'dns':['192.0.2.53']}),
                              ('utils.wired_native_session.network.has_lease',True)]:
            p=patch(target,return_value=value); self.patches.append(p); p.start()
        self.http_patch=patch('utils.wired_native_session.InterfaceHTTP');self.http=self.http_patch.start().return_value
        self.http.request.return_value=SimpleNamespace(status=200,body=b'Microsoft Connect Test')
        self.addCleanup(self.http_patch.stop)
        for p in self.patches:self.addCleanup(p.stop)

    def test_fresh_success_requires_real_exit_and_link_loss_clears_status(self):
        self.assertTrue(self.monitor.verify()['ready'])
        with patch('utils.wired_native_session.network.link_up',return_value=False):
            state=self.monitor.snapshot()
        self.assertFalse(state['ready']);self.assertTrue(state['retryable'])

    def test_replaced_process_cannot_reuse_success(self):
        self.monitor.verify()
        with patch('utils.wired_native_session._running_core',return_value=CoreSession(124,2)):
            self.assertFalse(self.monitor.snapshot()['ready'])
            with patch('utils.wired_native_session.NativeHandoff') as handoff:
                self.monitor.close();handoff.assert_not_called()

    def test_two_exit_failures_allow_reconnect_and_close_releases_core(self):
        self.monitor.verify();self.http.request.return_value.body=b'portal'
        self.monitor._next_probe=0
        state=self.monitor.snapshot()
        self.assertFalse(state['ready']);self.assertFalse(state['retryable'])
        self.monitor._next_probe=0
        self.assertTrue(self.monitor.snapshot()['retryable'])
        with patch('utils.wired_native_session.NativeHandoff') as handoff:
            self.monitor.close()
            handoff.return_value.pause.assert_called_once()


class FallbackTests(unittest.TestCase):
    mocked = modes.ConnectionModeTests.mocked
    setUp = modes.ConnectionModeTests.setUp
    tearDown = modes.ConnectionModeTests.tearDown
    connect = modes.ConnectionModeTests.connect

    def test_transient_failure_uses_supported_fallback_once_and_preserves_auto_setting(self):
        self.adapter_query.return_value=[adapter()]
        self.discovery.return_value=str(self.root/'native-client')
        def failed(*args):
            self.service._last_wired_status={'fallback_allowed':True,'retryable':True}
            raise RuntimeError('temporary capture loss')
        with patch.object(self.service,'_connect_independent',side_effect=failed):
            self.assertTrue(self.connect(wired_backend='auto')['ready'])
        self.prepare.assert_called_once()
        self.assertEqual(self.service.load_settings()['wired_backend'],'auto')

    def test_rejected_credentials_or_unsupported_installation_do_not_fallback(self):
        self.adapter_query.return_value=[adapter()]
        def failed(*args):
            self.service._last_wired_status={'fallback_allowed':False,'retryable':False}
            raise RuntimeError('account rejected')
        with patch.object(self.service,'_connect_independent',side_effect=failed):
            with self.assertRaisesRegex(RuntimeError,'account rejected'):
                self.connect(wired_backend='auto')
        self.prepare.assert_not_called();self.discovery.assert_not_called()
        self.service._last_wired_status={'fallback_allowed':True,'retryable':True}
        with patch.object(self.service,'_connect_independent',side_effect=RuntimeError('driver unavailable')):
            with self.assertRaisesRegex(RuntimeError,'driver unavailable'):
                self.connect(wired_backend='auto')
        self.prepare.assert_not_called()

    def test_native_stale_success_cannot_mark_online_and_old_core_is_closed(self):
        self.adapter_query.return_value=[adapter()]
        self.discovery.return_value=str(self.root/'native-client')
        self.monitor.verify.return_value=dict(connection_kind='wired',ready=False,authenticated=False,
            retryable=True,active=True,message='exit unavailable')
        result=self.connect(wired_backend='native')
        self.assertFalse(result['ready']);self.assertTrue(result['retryable'])
        self.monitor.close.assert_called_once()
        self.assertIsNone(self.service._native_session)
        self.assertTrue(self.service.wired_status()['retryable'])


class AdapterProfileTests(unittest.TestCase):
    setUp = profiles.ProfileTests.setUp

    def test_selected_adapter_replaces_old_native_profile_and_forces_wired(self):
        files=_build_profiles(self.root,self.credentials,self.material,adapter_name='Synthetic replacement Ethernet')
        text=_text(files[0][1])
        self.assertEqual(_get(text,'PUBLIC','Adapter'),'Synthetic replacement Ethernet')
        self.assertEqual(_get(text,'PUBLIC','AuthModeMediaType'),'Wire')
        self.assertEqual(_get(text,'PUBLIC','AuthMode'),'EAPMD5')
