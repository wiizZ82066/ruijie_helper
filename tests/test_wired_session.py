import unittest
from utils.wired_session import MinimalVendorSession
from utils.wired_eapol import State
from test_wired_eapol import LOCAL, PEER, OTHER, request
import test_wired_vendor
from utils.wired_vendor import parse_extension
from utils.wired_vendor import password_field


class MinimalSessionTests(unittest.TestCase):
    def session(self):
        return MinimalVendorSession({'mac_bytes': LOCAL, 'permanentMac':LOCAL.hex(),
            'addresses':['192.0.2.10'], 'prefixes':[24], 'gateways':['192.0.2.1'],
            'dns':['192.0.2.53','192.0.2.54'], 'dhcp':'Enabled'},
            'fixture-user',b'fixture-password','fixture-service')

    def test_challenge_extension_and_duplicate(self):
        session=self.session(); session.start(0)
        session.receive(request(),1)
        challenge=bytes(range(16))
        req=request(8,4,b'\x10'+challenge)
        action=session.receive(req,2)
        size=int.from_bytes(action.frame[16:18],'big')
        fields={k:v for _,k,v in parse_extension(action.frame[18+size:])}
        self.assertEqual(fields[0x2f],password_field(b'fixture-user',b'fixture-password',challenge))
        self.assertEqual(fields[0x76],b'192.0.2.54')
        self.assertNotIn(0x17,fields); self.assertNotIn(0x4d,fields)
        self.assertEqual(action.frame,session.receive(req,3).frame)

    def test_vendor_success_peer_identifier_and_order(self):
        def outcome(peer=PEER,identifier=8):
            body=test_wired_vendor.VendorCodecTests.success()
            payload=bytes([3,identifier])+(len(body)+4).to_bytes(2,'big')+body
            return LOCAL+peer+b'\x88\x8e\x01\x00'+len(payload).to_bytes(2,'big')+payload
        session=self.session(); session.start(0)
        self.assertNotEqual(session.receive(outcome(),1).state,State.AUTHENTICATED)
        session.receive(request(),2); session.receive(request(8,4,b'\x10'+bytes(16)),3)
        self.assertNotEqual(session.receive(outcome(OTHER),4).state,State.AUTHENTICATED)
        self.assertNotEqual(session.receive(outcome(identifier=9),5).state,State.AUTHENTICATED)
        self.assertEqual(session.receive(outcome(),6).state,State.AUTHENTICATED)
        self.assertFalse(session.success.hello_enabled)
        saved=session.success
        session.receive(outcome(OTHER),7)
        self.assertIs(session.success,saved)
        session.receive(request(10),8)
        self.assertIs(session.success,saved)
        self.assertFalse(session._vendor_password)
        session.cancel()
        self.assertFalse(session._vendor_password)

    def test_oversized_success_rejected(self):
        session=self.session(); session.start(0)
        session.receive(request(),1); session.receive(request(8,4,b'\x10'+bytes(16)),2)
        body=test_wired_vendor.VendorCodecTests.success()
        eap=bytes([3,8])+(len(body)+4).to_bytes(2,'big')+body
        raw=LOCAL+PEER+b'\x88\x8e\x01\x00'+len(eap).to_bytes(2,'big')+eap
        self.assertEqual(session.receive(raw+b'EXCESS',3).state,State.WAIT_RESULT)


if __name__=='__main__': unittest.main()
