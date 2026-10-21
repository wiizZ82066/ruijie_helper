"""Connection-mode routing with synthetic credentials; no OS/network operations."""
import threading
import unittest
from unittest.mock import patch

from fixture_support import fixture_directory
from utils import auth_service
from utils.auth_runtime import CoreSession
from utils.credential_store import Credentials
from utils.wireless_network import InterfaceBinding

WIRED = '11111111-1111-4111-8111-111111111111'
SECOND = '22222222-2222-4222-8222-222222222222'
WIFI = 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'
ACCOUNT = 'synthetic-mode-account'
PASSWORD = 'synthetic-mode-password'


def adapter(guid=WIRED, *, status='Up', kind=6, hardware=True, description='Realtek USB GbE Family Controller'):
    return dict(guid=guid, status=status, if_type=kind, hardware_interface=hardware,
                interface_description=description)


class ConnectionModeTests(unittest.TestCase):
    def mocked(self, target, **kwargs):
        patcher = patch(target, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def setUp(self):
        self.root = fixture_directory(self, 'connection-modes')
        for target in ('subprocess.run', 'subprocess.Popen', 'psutil.process_iter',
                       'socket.create_connection', 'socket.getaddrinfo'):
            self.mocked(target, side_effect=AssertionError('Real OS/network operations forbidden'))
        self.mocked('ctypes.WinDLL', side_effect=AssertionError('Native operations forbidden'), create=True)
        self.mocked('utils.hotspot.platform.system', return_value='OfflineTestOS')
        self.vault_type = self.mocked('utils.auth_service.CredentialStore', autospec=True)
        self.vault = self.vault_type.return_value
        self.credentials = Credentials(ACCOUNT, PASSWORD)
        self.vault.load.return_value = self.credentials
        self.service = auth_service.CampusService(self.root / 'user-data', self.root / 'frontend.py')
        self.cancel = threading.Event()
        self.logs = []
        self.values = dict(auth_service.DEFAULT_SETTINGS, connection_mode='auto', client_dir='', ethernet_guid=None)
        self.native_valid = self.mocked('utils.auth_service.is_client_dir', return_value=False)
        self.discovery = self.mocked('utils.auth_service.discover_client_dir', return_value=None)
        self.adapter_query = self.mocked('utils.auth_service.WindowsOperations.list_adapters', return_value=[])
        self.current_jnu = self.mocked('utils.wireless_network.current_jnu', return_value={WIFI})
        self.binding = InterfaceBinding(18, '192.0.2.42', ('192.0.2.53',), WIFI)
        self.ensure = self.mocked('utils.wireless_network.ensure_jnu', return_value=self.binding)
        self.http_type = self.mocked('utils.interface_http.InterfaceHTTP', autospec=True)
        self.portal_type = self.mocked('utils.jnu_portal.PortalClient', autospec=True)
        self.portal = self.portal_type.return_value
        self.portal.keepalive_seconds = 0.0
        self.portal.session_index = ''
        self.portal.connect.return_value = {'authenticated': True, 'ready': True,
                                          'connection_kind': 'wireless', 'message': '已连接 JNU'}
        self.reader = self.mocked('utils.auth_service.read_saved_credentials', return_value=self.credentials)
        self.installer_type = self.mocked('utils.auth_service.CoreInstaller', autospec=True)
        self.installer_type.return_value.status.return_value = {'state': 'patched', 'recovery_needed': False}
        self.prepare = self.mocked('utils.auth_service.prepare_credentials', return_value={'before': 'synthetic', 'started': 100.0})
        self.start = self.mocked('utils.auth_service.start_core', return_value=CoreSession(123, 100.5))
        self.wait_auth = self.mocked('utils.auth_service.wait_authentication', return_value=True)
        self.snapshot = self.mocked('utils.auth_service.result_snapshot', return_value='synthetic-snapshot')
        self.auth_log = self.mocked('utils.auth_service.capture_auth_log', return_value=None)
        self.hotspot = self.mocked('utils.auth_service.HotspotManager.start_hotspot_detailed')
        self.startup = self.mocked('utils.auth_service.configure_startup', return_value={'enabled': True})
        self.monitor = self.mocked('utils.auth_service.NativeSessionMonitor', autospec=True).return_value
        self.monitor.verify.return_value = dict(connection_kind='wired', backend='native',
            authenticated=True, ready=True, active=True, retryable=False, message='已连接校园网 · 兼容认证')

    def tearDown(self):
        self.assertNotIn(ACCOUNT, repr(self.logs))
        self.assertNotIn(PASSWORD, repr(self.logs))

    def connect(self, *, credentials=None, require_ethernet=False, **changes):
        return self.service.connect(dict(self.values, **changes),
                                    self.credentials if credentials is None else credentials,
                                    True, self.cancel, self.logs.append,
                                    require_ethernet=require_ethernet)

    def assert_no_native_auth(self):
        self.installer_type.assert_not_called()
        self.prepare.assert_not_called()
        self.start.assert_not_called()
        self.wait_auth.assert_not_called()
        self.snapshot.assert_not_called()
        self.auth_log.assert_not_called()

    def test_auto_prefers_unique_physical_up_ethernet(self):
        self.adapter_query.return_value = [adapter(), adapter(SECOND, kind=71),
                                           adapter(WIFI, hardware=False)]
        self.assertEqual(self.service.connection_target(self.values), ('wired', WIRED))
        self.current_jnu.assert_not_called()
        self.ensure.assert_not_called()

    def test_auto_replaces_removed_adapter_with_connected_physical_adapter(self):
        self.adapter_query.return_value = [adapter(status='Disconnected'), adapter(SECOND)]
        values = dict(self.values, ethernet_guid=WIRED)
        self.assertEqual(self.service.connection_target(values), ('wired', SECOND))
        self.ensure.assert_not_called()
        self.assert_no_native_auth()

    def test_tether_virtual_wifi_and_disconnected_not_wired_candidates(self):
        for description in ('Remote NDIS Compatible Device', 'USB RNDIS Ethernet',
                            'Apple Mobile Device Ethernet', 'remote ndis usb'):
            with self.subTest(description=description):
                self.adapter_query.return_value = [adapter(description=description)]
                self.assertEqual(self.service.list_adapters(), [])
                self.assertEqual(self.service.connection_target(self.values), ('wireless', WIFI))
        for row in (adapter(kind=71), adapter(hardware=False), adapter(status='Disconnected')):
            with self.subTest(row=row):
                self.adapter_query.return_value = [row]
                self.assertEqual(self.service.connection_target(self.values), ('wireless', WIFI))

    def test_real_usb_gbe_not_rejected_with_tether_adapters(self):
        self.adapter_query.return_value = [adapter(), adapter(SECOND, description='Remote NDIS Compatible Device')]
        self.assertEqual(self.service.connection_target(self.values), ('wired', WIRED))

    def test_multiple_wired_have_stable_automatic_selection(self):
        self.adapter_query.return_value = [adapter(), adapter(SECOND)]
        self.assertEqual(self.service.connection_target(self.values), ('wired', WIRED))
        self.adapter_query.return_value.reverse()
        self.assertEqual(self.service.connection_target(self.values), ('wired', WIRED))
        self.ensure.assert_not_called()
        self.portal.connect.assert_not_called()
        self.vault.save.assert_not_called()
        self.assert_no_native_auth()

    def test_explicit_wired_selection_resolves_ambiguity(self):
        self.adapter_query.return_value = [adapter(), adapter(SECOND)]
        self.assertEqual(self.service.connection_target(dict(self.values, ethernet_guid=SECOND)), ('wired', SECOND))

    def test_auto_up_ethernet_dispatches_existing_wired_path(self):
        self.adapter_query.return_value = [adapter()]
        self.discovery.return_value = str(self.root / 'native-client')
        result = self.connect(wired_backend='native')
        self.assertTrue(result['authenticated'])
        self.ensure.assert_not_called()
        self.http_type.assert_not_called()
        self.portal_type.assert_not_called()
        self.installer_type.assert_called_once()
        self.prepare.assert_called_once()
        self.start.assert_called_once()
        self.assertEqual(self.service.load_settings()['ethernet_guid'], WIRED)

    def test_auto_without_physical_adapter_uses_wireless_and_saved_vault(self):
        saved = self.service.load_credentials()
        result = self.service.connect(self.values, saved, True, self.cancel, self.logs.append)
        self.assertTrue(result['authenticated'])
        self.vault.load.assert_called_once()
        self.ensure.assert_called_once_with(self.cancel)
        self.http_type.assert_called_once_with(18, '192.0.2.42', ('192.0.2.53',), self.cancel)
        self.portal.connect.assert_called_once()
        self.assertIs(self.portal.connect.call_args.args[0], self.credentials)
        self.discovery.assert_not_called()
        self.native_valid.assert_not_called()
        self.reader.assert_not_called()
        self.assert_no_native_auth()
        stored = self.service.settings_path.read_text(encoding='utf-8')
        self.assertNotIn(ACCOUNT, stored)
        self.assertNotIn(PASSWORD, stored)

    def test_explicit_wireless_never_queries_ethernet(self):
        self.adapter_query.side_effect = AssertionError('wireless must not enumerate Ethernet')
        self.assertTrue(self.connect(connection_mode='wireless')['ready'])
        self.assert_no_native_auth()
        self.reader.assert_not_called()

    def test_wireless_startup_does_not_require_native_client(self):
        values = dict(self.values, connection_mode='wireless')
        self.assertTrue(self.service.set_startup(True, values, self.logs.append)['enabled'])
        self.startup.assert_called_once_with(True, entry_script=self.service.entry_script)
        self.discovery.assert_not_called()
        self.native_valid.assert_not_called()
        self.assert_no_native_auth()
        # Existing scheduled startup flag should not force wireless into wired mode.
        self.assertTrue(self.connect(connection_mode='wireless', require_ethernet=True)['ready'])
        self.portal.connect.assert_called_once()
        self.assert_no_native_auth()

    def test_auto_startup_no_wire_uses_wireless_without_native(self):
        self.assertTrue(self.service.set_startup(True, self.values, self.logs.append)['enabled'])
        self.assertTrue(self.connect(require_ethernet=True)['ready'])
        self.assert_no_native_auth()

    def test_invalid_mode_never_reads_adapters_credentials_or_login(self):
        for mode in ('bogus', '', None):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, '连接方式'):
                self.connect(connection_mode=mode)
        self.adapter_query.assert_not_called()
        self.current_jnu.assert_not_called()
        self.ensure.assert_not_called()
        self.portal.connect.assert_not_called()
        self.reader.assert_not_called()
        self.assert_no_native_auth()

    def test_cancel_before_dispatch_never_logs_in(self):
        self.cancel.set()
        result = self.connect()
        self.assertFalse(result['authenticated'])
        self.adapter_query.assert_not_called()
        self.ensure.assert_not_called()
        self.portal.connect.assert_not_called()
        self.reader.assert_not_called()
        self.assert_no_native_auth()

    def test_cancel_during_wifi_association_never_reads_or_saves_credentials(self):
        def associate(cancel):
            cancel.set()
            return self.binding
        self.ensure.side_effect = associate
        result = self.connect(connection_mode='wireless', legacy_saved_login=True)
        self.assertFalse(result['authenticated'])
        self.reader.assert_not_called()
        self.vault.save.assert_not_called()
        self.portal.connect.assert_not_called()
        self.assertFalse(self.service.settings_path.exists())
        self.assert_no_native_auth()

    def test_wireless_legacy_reads_only_native_profile_not_native_login(self):
        self.discovery.return_value = str(self.root / 'native-client')
        result = self.connect(connection_mode='wireless', legacy_saved_login=True)
        self.assertTrue(result['authenticated'])
        self.reader.assert_called_once_with((self.root / 'native-client').resolve())
        self.vault.save.assert_not_called()
        self.assertIs(self.portal.connect.call_args.args[0], self.credentials)
        self.assert_no_native_auth()
        self.hotspot.assert_not_called()

    def test_wireless_auto_hotspot_without_selected_ethernet_still_logs_in(self):
        result = self.connect(connection_mode='wireless', auto_hotspot=True, ethernet_guid=None)
        self.assertTrue(result['ready'])
        self.portal.connect.assert_called_once()
        self.hotspot.assert_not_called()
        self.assert_no_native_auth()

    def test_wireless_auto_hotspot_with_selected_ethernet_never_starts_ics(self):
        self.assertTrue(self.connect(connection_mode='wireless', auto_hotspot=True, ethernet_guid=WIRED)['ready'])
        self.portal.connect.assert_called_once()
        self.hotspot.assert_not_called()
        self.assert_no_native_auth()

    def test_portal_receives_live_association_guard(self):
        self.connect(connection_mode='wireless')
        check = self.portal_type.call_args.args[2]
        self.assertTrue(check())
        self.current_jnu.return_value = {WIFI.lower()}
        self.assertTrue(check())
        self.current_jnu.return_value = {SECOND}
        self.assertFalse(check())

    def test_wireless_default_never_schedules_heartbeat(self):
        self.connect(connection_mode='wireless')
        self.assertIsNone(self.service._wireless_session)
        self.service.maintain_wireless()
        self.portal.keepalive.assert_not_called()
        self.assertEqual(self.portal.connect.call_count, 1)

    def test_wireless_server_heartbeat_is_memory_only_and_due_only(self):
        clock = self.mocked('utils.auth_service.time.monotonic', return_value=100.0)
        self.portal.keepalive_seconds = 30.0
        self.portal.session_index = 'synthetic-session-id'
        self.portal.keepalive.return_value = True
        self.connect(connection_mode='wireless')
        self.assertIs(self.service._wireless_session, self.portal)
        self.assertEqual(self.service._wireless_next_keepalive, 130.0)
        self.assertNotIn('synthetic-session-id', self.service.settings_path.read_text(encoding='utf-8'))
        clock.return_value = 129.0
        self.service.maintain_wireless()
        self.portal.keepalive.assert_not_called()
        clock.return_value = 130.0
        self.service.maintain_wireless()
        self.portal.keepalive.assert_called_once_with()
        self.assertEqual(self.service._wireless_next_keepalive, 160.0)
        self.assertEqual(self.portal.connect.call_count, 1)
        self.ensure.assert_called_once()
        self.assertEqual(self.vault.save.call_count, 1)
        self.assert_no_native_auth()

    def test_heartbeat_failure_clears_session_without_retrying_login(self):
        clock = self.mocked('utils.auth_service.time.monotonic', return_value=100.0)
        self.portal.keepalive_seconds = 10.0
        self.portal.session_index = 'synthetic-session-id'
        self.portal.keepalive.return_value = False
        self.connect(connection_mode='wireless')
        clock.return_value = 110.0
        with self.assertRaisesRegex(RuntimeError, '在线状态'):
            self.service.maintain_wireless()
        self.assertIsNone(self.service._wireless_session)
        clock.return_value = 200.0
        self.service.maintain_wireless()
        self.portal.keepalive.assert_called_once()
        self.assertEqual(self.portal.connect.call_count, 1)
        self.ensure.assert_called_once()
        self.assertEqual(self.vault.save.call_count, 1)
        self.assert_no_native_auth()

    def test_heartbeat_exception_is_redacted_and_not_retried(self):
        clock = self.mocked('utils.auth_service.time.monotonic', return_value=100.0)
        self.portal.keepalive_seconds = 10.0
        self.portal.session_index = 'synthetic-session-id'
        self.portal.keepalive.side_effect = RuntimeError('synthetic failure ' + PASSWORD)
        self.connect(connection_mode='wireless')
        clock.return_value = 110.0
        with self.assertRaises(RuntimeError) as error:
            self.service.maintain_wireless()
        self.assertNotIn(PASSWORD, str(error.exception))
        self.assertIsNone(self.service._wireless_session)
        self.assertEqual(self.portal.connect.call_count, 1)

    def test_legacy_missing_mode_preserves_wired_dispatch(self):
        self.adapter_query.return_value = [adapter()]
        values = dict(self.values,wired_backend='native')
        values.pop('connection_mode')
        self.discovery.return_value = str(self.root / 'native-client')
        self.assertTrue(self.service.connect(values, self.credentials, True, self.cancel, self.logs.append)['ready'])
        self.adapter_query.assert_called_once()  # Read selected adapter for native profile binding.
        self.ensure.assert_not_called()
        self.portal_type.assert_not_called()
        self.prepare.assert_called_once()
        self.start.assert_called_once()

    def test_default_independent_wired_never_requires_client(self):
        self.adapter_query.return_value=[adapter()]
        with patch('utils.wired_auth.WiredClient',autospec=True) as factory:
            client=factory.return_value
            client.connect.return_value={'authenticated':True,'ready':True,'active':True,'connection_kind':'wired'}
            self.assertTrue(self.connect()['ready'])
            factory.assert_called_once_with(WIRED,'internet')
            self.assert_no_native_auth()
            self.discovery.assert_not_called()
            self.reader.assert_not_called()
            self.service.disconnect()
            client.close.assert_called_once()

    def test_independent_startup_without_client(self):
        self.assertTrue(self.service.set_startup(True,dict(self.values,connection_mode='wired'),self.logs.append)['enabled'])
        self.discovery.assert_not_called()
        self.assert_no_native_auth()

    def test_independent_failure_closes_session_and_does_not_start_hotspot(self):
        self.adapter_query.return_value=[adapter()]
        with patch('utils.wired_auth.WiredClient',autospec=True) as factory:
            factory.return_value.connect.side_effect=RuntimeError('fixture failure')
            state={'active':False,'ready':False,'retryable':True,'message':'retry'}
            factory.return_value.snapshot.return_value=state
            with self.assertRaises(RuntimeError): self.connect(auto_hotspot=True)
            factory.return_value.close.assert_called_once()
            self.assertEqual(self.service.wired_status(),state)
            self.service.disconnect()
            self.assertIsNone(self.service.wired_status())
            self.hotspot.assert_not_called()

    def test_switching_to_wireless_closes_independent_worker(self):
        from unittest.mock import Mock
        old=Mock()
        self.service._wired_session=old
        self.connect(connection_mode='wireless')
        old.close.assert_called_once()
        self.assertIsNone(self.service._wired_session)


if __name__ == '__main__':
    unittest.main()
