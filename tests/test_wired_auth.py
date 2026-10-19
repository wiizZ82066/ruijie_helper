"""Synthetic switch and injected OS boundaries; no real networking or credentials."""
from collections import deque
from copy import deepcopy
import threading
import unittest
from unittest.mock import Mock,patch
from utils.wired_auth import WiredClient, RecoverableError
from utils.wired_eapol import EthernetEapol,EapPacket
from utils.credential_store import Credentials
import test_wired_vendor

LOCAL=bytes.fromhex('020000000001')
PEER=bytes.fromhex('020000000002')
GUID='11111111-1111-4111-8111-111111111111'
CONFIG={'guid':GUID,'mac_bytes':LOCAL,'permanentMac':LOCAL.hex(),'index':9,
        'addresses':['192.0.2.10'],'prefixes':[24],'gateways':['192.0.2.1'],
        'dns':['192.0.2.53'],'dhcp':'Enabled'}


class Switch:
    def __init__(self, failure=False, heartbeat=False):
        self.frames=deque(); self.identifier=0; self.closed=False
        self.sent=[]; self.failure=failure; self.heartbeat=heartbeat
    def send(self,raw):
        self.sent.append(raw)
        if raw[15]==1:
            self.identifier+=1
            self.frames.append(EthernetEapol(LOCAL,PEER,0,EapPacket(1,self.identifier,1).encode()).encode())
        elif raw[15]==0 and raw[22]==1:
            self.identifier+=1
            self.frames.append(EthernetEapol(LOCAL,PEER,0,EapPacket(1,self.identifier,4,b'\x10'+bytes(range(16))).encode()).encode())
        elif raw[15]==0 and raw[22]==4:
            if self.failure:
                self.frames.append(EthernetEapol(LOCAL,PEER,0,EapPacket(4,self.identifier).encode()).encode())
            else:
                body=test_wired_vendor.VendorCodecTests.success(enabled=int(self.heartbeat))
                payload=bytes([3,self.identifier])+(len(body)+4).to_bytes(2,'big')+body
                self.frames.append(LOCAL+PEER+b'\x88\x8e\x01\x00'+len(payload).to_bytes(2,'big')+payload)
    def receive(self):
        return self.frames.popleft() if self.frames else None
    def close(self):
        self.closed=True


class WiredAuthTests(unittest.TestCase):
    def mock(self,target,**kwargs):
        p=patch(target,**kwargs); self.addCleanup(p.stop); return p.start()
    def setUp(self):
        for target in ('subprocess.run','subprocess.Popen','psutil.process_iter','ctypes.CDLL'):
            self.mock(target,side_effect=AssertionError('OS access forbidden'))
        self.cfg=self.mock('utils.wired_auth.network.config',side_effect=lambda _:deepcopy(CONFIG))
        self.link=self.mock('utils.wired_auth.network.link_up',return_value=True)
        self.lease=self.mock('utils.wired_auth.network.acquire_lease')
        self.absent=self.mock('utils.wired_auth.native_absent',return_value=True)
        self.handoff=self.mock('utils.wired_auth.NativeHandoff',autospec=True).return_value
        self.switch=Switch()
        self.capture=self.mock('utils.wired_auth.Pcap',return_value=self.switch)
        self.http=self.mock('utils.wired_auth.InterfaceHTTP',autospec=True).return_value
        self.http.request.return_value=Mock(status=200,body=b'Microsoft Connect Test')
        self.client=WiredClient(GUID)
        self.addCleanup(self.client.close)
        self.credentials=Credentials('synthetic-user','synthetic-password')
        self.cancel=threading.Event()
    def test_two_stage_success_disconnect_and_no_native_restart(self):
        result=self.client.connect(self.credentials,self.cancel)
        self.assertTrue(result['authenticated']); self.assertTrue(result['ready'])
        self.assertEqual(sum(f[15]==1 for f in self.switch.sent),2)
        self.lease.assert_not_called()
        self.client.close()
        self.assertTrue(self.switch.closed)
        self.assertFalse(self.client.snapshot()['active'])
        self.handoff.restore.assert_not_called()
        self.assertNotIn('synthetic-password',repr(self.client.snapshot()))
    def test_cold_dhcp_renews_only_selected_interface_between_rounds(self):
        empty=deepcopy(CONFIG);empty.update(addresses=[],prefixes=[],gateways=[],dns=[])
        self.cfg.side_effect=[empty,deepcopy(CONFIG)]
        self.assertTrue(self.client.connect(self.credentials,self.cancel)['ready'])
        self.lease.assert_called_once_with(GUID)
        self.assertEqual(sum(f[15]==1 for f in self.switch.sent),2)
    def test_delayed_dhcp_or_dns_retries_and_then_uses_lease(self):
        empty=deepcopy(CONFIG);empty.update(addresses=[],prefixes=[],gateways=[],dns=[])
        self.cfg.side_effect=[empty,deepcopy(CONFIG)]
        self.lease.side_effect=[RuntimeError('DHCP service starting'),None]
        with patch.object(self.client._stop,'wait',return_value=False):
            result=self.client._wait_for_lease(empty)
        self.assertEqual(result['addresses'],CONFIG['addresses'])
        self.assertEqual(self.lease.call_count,2)
        self.assertTrue(all(c.args==(GUID,) for c in self.lease.call_args_list))
    def test_dhcp_is_bounded_and_cancellation_does_not_renew_again(self):
        empty=deepcopy(CONFIG);empty.update(addresses=[],prefixes=[],gateways=[],dns=[])
        self.cfg.side_effect=lambda _:deepcopy(empty)
        with patch.object(self.client._stop,'wait',return_value=False):
            with self.assertRaises(RecoverableError):
                self.client._wait_for_lease(empty)
        self.assertEqual(self.lease.call_count,3)
        self.client._stop.set()
        with self.assertRaises(InterruptedError): self.client._wait_for_lease(empty)
        self.assertEqual(self.lease.call_count,3)
    def test_rejected_password_no_automatic_repeat(self):
        self.switch.failure=True
        with self.assertRaisesRegex(RuntimeError,'认证未通过'):
            self.client.connect(self.credentials,self.cancel)
        self.assertEqual(sum(f[15]==1 for f in self.switch.sent),1)
        self.assertFalse(self.client.snapshot()['retryable'])
        self.handoff.restore.assert_called_once()
        self.assertTrue(self.switch.closed)
    def test_server_enables_unimplemented_heartbeat_not_falsely_online(self):
        self.switch.heartbeat=True
        with self.assertRaisesRegex(RuntimeError,'保活'):
            self.client.connect(self.credentials,self.cancel)
        self.assertFalse(self.client.snapshot()['ready'])
    def test_driver_failure_does_not_pause_existing_client(self):
        self.capture.side_effect=OSError('synthetic driver missing')
        with self.assertRaises(RuntimeError): self.client.connect(self.credentials,self.cancel)
        self.handoff.pause.assert_not_called()
    def test_changed_interface_between_rounds_rejected(self):
        other=deepcopy(CONFIG);other['mac_bytes']=bytes.fromhex('020000000003')
        self.cfg.side_effect=[deepcopy(CONFIG),other]
        with self.assertRaisesRegex(RuntimeError,'网卡已改变'):
            self.client.connect(self.credentials,self.cancel)
    def test_link_loss_clears_online_state(self):
        self.client.connect(self.credentials,self.cancel)
        self.link.return_value=False
        self.client._thread.join(3)
        self.assertFalse(self.client.snapshot()['active'])
        self.assertIn('断开',self.client.snapshot()['message'])
        self.assertTrue(self.client.snapshot()['retryable'])
    def test_authenticated_without_internet_not_ready(self):
        self.http.request.return_value.body=b'portal'
        result=self.client.connect(self.credentials,self.cancel)
        self.assertTrue(result['authenticated']);self.assertFalse(result['ready'])


if __name__=='__main__': unittest.main()
