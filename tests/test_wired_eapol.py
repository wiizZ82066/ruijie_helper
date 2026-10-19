"""Synthetic, offline-only protocol tests. Never opens a network adapter."""
import random
import struct
import unittest
from utils.wired_eapol import (EapPacket, EthernetEapol, Effect, Md5Supplicant,
                            PAE_GROUP, ProtocolError, State, md5_response)

LOCAL = bytes.fromhex('020000000001')
PEER = bytes.fromhex('020000000002')
OTHER = bytes.fromhex('020000000003')


def request(identifier=7, method=1, data=b'', *, source=PEER, destination=LOCAL):
    return EthernetEapol(destination, source, 0, EapPacket(1, identifier, method, data).encode()).encode()


def outcome(code, identifier=8, *, source=PEER):
    return EthernetEapol(LOCAL, source, 0, EapPacket(code, identifier).encode()).encode()


def response(effect):
    return EapPacket.decode(EthernetEapol.decode(effect.frame).payload)


class CodecTests(unittest.TestCase):
    def test_known_eap_identity_wire(self):
        packet = EapPacket(2, 7, 1, b'alice')
        self.assertEqual(packet.encode().hex(), '0207000a01616c696365')
        self.assertEqual(EapPacket.decode(bytes.fromhex('0207000a01616c696365')), packet)

    def test_known_start_wire(self):
        expected = bytes.fromhex('0180c2000003020000000001888e01010000')
        self.assertEqual(EthernetEapol(PAE_GROUP, LOCAL, 1).encode(pad=False), expected)
        self.assertEqual(EthernetEapol.decode(expected).kind, 1)
        self.assertEqual(len(EthernetEapol(PAE_GROUP, LOCAL, 1).encode()), 60)

    def test_outcomes_exact_four_bytes(self):
        for code in (3, 4):
            self.assertEqual(EapPacket.decode(bytes((code, 0, 0, 4))), EapPacket(code, 0))
            with self.assertRaises(ProtocolError):
                EapPacket.decode(bytes((code, 0, 0, 5, 1)))

    def test_length_consistency(self):
        for raw in (b'', b'\x01\x02\x00\x04', b'\x01\x02\x00\x06\x01', b'\x01\x02\x00\x04\x01'):
            with self.subTest(raw=raw), self.assertRaises(ProtocolError):
                EapPacket.decode(raw)
        frame = bytearray(request())
        frame[16:18] = b'\xff\xff'
        with self.assertRaises(ProtocolError):
            EthernetEapol.decode(bytes(frame))

    def test_vendor_suffix_not_silently_discarded(self):
        raw = EthernetEapol(LOCAL, PEER, 0, EapPacket(3, 8).encode()).encode(pad=False)
        for changed in (raw + b'private', raw.ljust(61, b'\0')):
            with self.assertRaises(ProtocolError):
                EthernetEapol.decode(changed)
        self.assertEqual(EthernetEapol.decode(raw.ljust(60, b'\0')).payload, EapPacket(3, 8).encode())

    def test_nonzero_minimum_ethernet_padding(self):
        raw = EthernetEapol(LOCAL, PEER, 0, EapPacket(1, 1, 1).encode()).encode(pad=False)
        self.assertEqual(EthernetEapol.decode(raw.ljust(60, b'\xa5')).payload, EapPacket(1, 1, 1).encode())

    def test_vlan_and_unknown_types_rejected(self):
        raw = bytearray(request())
        for offset, value in ((12, 0x81), (14, 9), (15, 3)):
            changed = raw.copy(); changed[offset] = value
            with self.assertRaises(ProtocolError):
                EthernetEapol.decode(bytes(changed))

    def test_nonzero_unicast_source_required(self):
        for mac in (bytes(6), PAE_GROUP, b'\xff' * 6, b'short'):
            with self.assertRaises(ProtocolError):
                EthernetEapol(LOCAL, mac, 1).encode()

    def test_md5_abc_known_vector_and_order(self):
        self.assertEqual(md5_response(ord('a'), b'b', b'c').hex(), '900150983cd24fb0d6963f7d28e17f72')
        self.assertNotEqual(md5_response(ord('a'), b'c', b'b'), md5_response(ord('a'), b'b', b'c'))
        self.assertNotEqual(md5_response(ord('b'), b'b', b'c'), md5_response(ord('a'), b'b', b'c'))

    def test_md5_boundaries(self):
        for identifier, password, challenge in ((-1, b'p', b'c'), (256, b'p', b'c'), (1, b'', b'c'), (1, b'p', b''), (1, b'p', b'c'*256)):
            with self.assertRaises(ProtocolError):
                md5_response(identifier, password, challenge)
        self.assertEqual(len(md5_response(255, b'p', b'c' * 255)), 16)

    def test_eap_valid_roundtrip_all_identifiers(self):
        for identifier in range(256):
            for packet in (EapPacket(1, identifier, 1, b'prompt'), EapPacket(2, identifier, 4, b'\x10' + bytes(16)), EapPacket(3, identifier)):
                self.assertEqual(EapPacket.decode(packet.encode()), packet)

    def test_private_repr(self):
        payload = b'synthetic-private-username'
        packet = EapPacket(2, 1, 1, payload)
        frame = EthernetEapol(PEER, LOCAL, 0, packet.encode())
        self.assertNotIn(payload.decode(), repr(packet))
        self.assertNotIn(payload.decode(), repr(frame))
        self.assertNotIn(payload.decode(), repr(Effect('send', State.WAIT_CHALLENGE, 'response', frame.encode())))

    def test_random_input_is_bounded(self):
        rng = random.Random(806)
        for _ in range(1000):
            raw = rng.randbytes(rng.randrange(0, 2000))
            try:
                frame = EthernetEapol.decode(raw)
            except ProtocolError:
                continue
            self.assertEqual(EthernetEapol.decode(frame.encode(pad=False)), frame)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.session = Md5Supplicant(LOCAL, 'alice', b'b')
        self.session.start(0)

    def challenge(self, identifier=97, payload=b'\x01c', now=2):
        return self.session.receive(request(identifier, 4, payload), now)

    def test_complete_flow_and_no_ip_claim(self):
        identity = self.session.receive(request(), 1)
        self.assertEqual(response(identity), EapPacket(2, 7, 1, b'alice'))
        challenge = self.challenge()
        expected = b'\x10' + bytes.fromhex('900150983cd24fb0d6963f7d28e17f72') + b'alice'
        self.assertEqual(response(challenge), EapPacket(2, 97, 4, expected))
        done = self.session.receive(outcome(3, 97), 3)
        self.assertEqual(done.state, State.AUTHENTICATED)
        self.assertIn('IP access unverified', done.reason)
        self.assertEqual(len(self.session._password), 0)

    def test_success_requires_own_md5_response_and_matching_id(self):
        for now in (0.1,):
            self.assertEqual(self.session.receive(outcome(3), now).kind, 'ignored')
        self.session.receive(request(), 1)
        self.assertEqual(self.session.receive(outcome(3, 7), 1.1).kind, 'ignored')
        self.challenge()
        self.assertEqual(self.session.receive(outcome(3, 96), 3).kind, 'ignored')
        self.assertEqual(self.session.state, State.WAIT_RESULT)
        self.assertEqual(self.session.receive(outcome(3, 97), 4).state, State.AUTHENTICATED)

    def test_direct_md5_request_supported(self):
        self.assertEqual(response(self.challenge()).method, 4)

    def test_exact_retransmit_and_reused_id_conflict(self):
        first = self.session.receive(request(), 1)
        again = self.session.receive(request(), 2)
        self.assertEqual(again.frame, first.frame)
        self.assertEqual(again.reason, 'duplicate request')
        self.assertEqual(self.session._requests, 1)
        different = self.session.receive(request(7, 4, b'\x01c'), 3)
        self.assertEqual(different.kind, 'ignored')
        self.assertEqual(self.session.state, State.WAIT_CHALLENGE)

    def test_challenge_retransmit_same_digest_without_new_state(self):
        first = self.challenge()
        repeat = self.challenge(now=3)
        self.assertEqual(first.frame, repeat.frame)
        self.assertEqual(self.session._requests, 1)

    def test_server_optional_name_excluded_from_hash(self):
        self.assertEqual(response(self.challenge(payload=b'\x01cSERVERNAME')).data[1:17].hex(), '900150983cd24fb0d6963f7d28e17f72')

    def test_peer_pinning_and_wrong_destination(self):
        self.session.receive(request(), 1)
        for raw in (request(8, 4, b'\x01c', source=OTHER), request(8, 4, b'\x01c', destination=OTHER), request(8, 4, b'\x01c', source=LOCAL)):
            self.assertEqual(self.session.receive(raw, 2).kind, 'ignored')
        self.assertEqual(self.session.state, State.WAIT_CHALLENGE)
        self.challenge(now=3)
        self.assertEqual(self.session.receive(outcome(3, 97, source=OTHER), 4).kind, 'ignored')

    def test_malformed_first_frame_does_not_pin_peer(self):
        self.assertEqual(self.session.receive(request(8, 4, b'\x10short', source=OTHER), 1).kind, 'ignored')
        self.assertIsNone(self.session.peer)
        self.assertEqual(self.session._requests, 0)
        self.assertEqual(self.session.receive(request(source=PEER), 2).kind, 'send')
        self.assertEqual(self.session.peer, PEER)

    def test_new_identity_after_md5_requires_explicit_restart(self):
        self.challenge()
        self.assertEqual(self.session.receive(request(98, 1), 3).kind, 'ignored')
        self.assertEqual(self.session.state, State.WAIT_RESULT)

    def test_unknown_method_nak_and_notification(self):
        effect = self.session.receive(request(3, 25), 1)
        self.assertEqual(response(effect), EapPacket(2, 3, 3, b'\x04'))
        effect = self.session.receive(request(4, 2, b'ignored text'), 2)
        self.assertEqual(response(effect), EapPacket(2, 4, 2))
        self.assertEqual(effect.state, State.WAIT_CHALLENGE)

    def test_bad_md5_does_not_advance(self):
        for raw in (b'', b'\0', b'\x10too short'):
            result = self.challenge(payload=raw)
            self.assertEqual(result.kind, 'ignored')
            self.assertEqual(result.state, State.WAIT_REQUEST)
        self.assertEqual(self.session._requests, 0)

    def test_bounded_start_retries_and_timeout(self):
        self.assertEqual(self.session.tick(2.9).kind, 'none')
        self.assertEqual(self.session.tick(3).kind, 'send')
        self.assertEqual(self.session.tick(6).kind, 'send')
        self.assertEqual(self.session.tick(9).kind, 'none')
        self.assertEqual(self.session.tick(60).state, State.TIMED_OUT)
        self.assertFalse(self.session._password)
        self.assertEqual(self.session.receive(request(), 61).kind, 'ignored')

    def test_retransmits_do_not_extend_deadline(self):
        self.session.receive(request(), 1)
        self.session.receive(request(), 59)
        self.assertEqual(self.session.receive(request(), 60).state, State.TIMED_OUT)

    def test_failure_terminal_and_clears_password(self):
        self.challenge()
        self.assertEqual(self.session.receive(outcome(4, 97), 3).state, State.FAILED)
        self.assertFalse(self.session._password)
        self.assertEqual(self.session.receive(outcome(3, 97), 4).kind, 'ignored')

    def test_identity_rejection_is_terminal(self):
        self.session.receive(request(7, 1), 1)
        self.assertEqual(self.session.receive(outcome(4, 7), 2).state, State.FAILED)
        self.assertFalse(self.session._password)

    def test_old_challenge_replay_is_not_answered(self):
        self.challenge(97, now=1)
        self.challenge(98, now=2)
        self.assertEqual(self.challenge(97, now=3).kind, 'ignored')
        self.assertEqual(self.session._last_identifier, 98)

    def test_unrepresentable_deadline_rejected(self):
        session = Md5Supplicant(LOCAL, 'alice', b'b')
        with self.assertRaises(ProtocolError):
            session.start(1e308)
        self.assertEqual(session.state, State.IDLE)

    def test_cancel_no_logoff_side_effect(self):
        self.assertEqual(self.session.cancel().state, State.CANCELLED)
        self.assertIsNone(self.session.logoff().frame)
        self.assertEqual(self.session.receive(request(), 1).kind, 'ignored')
        self.assertFalse(self.session._password)

    def test_explicit_logoff(self):
        self.session.receive(request(), 1)
        effect = self.session.logoff()
        frame = EthernetEapol.decode(effect.frame)
        self.assertEqual((frame.destination, frame.source, frame.kind), (PEER, LOCAL, 2))
        self.assertEqual(effect.state, State.CLOSED)
        self.assertIsNone(self.session.logoff().frame)

    def test_clock_and_no_implicit_restart(self):
        self.session.tick(5)
        for now in (4, float('inf'), float('nan')):
            with self.assertRaises(ProtocolError): self.session.tick(now)
        self.session.cancel()
        with self.assertRaises(ProtocolError): self.session.start(6)

    def test_unicode_username_and_password_encoding_explicit(self):
        session = Md5Supplicant(LOCAL, '测试', b'\xe9')
        session.start(0)
        self.assertEqual(response(session.receive(request(), 1)).data, '测试'.encode('utf-8'))
        digest = response(session.receive(request(8, 4, b'\x01c'), 2)).data[1:17]
        self.assertEqual(digest, md5_response(8, b'\xe9', b'c'))
        self.assertNotEqual(digest, md5_response(8, 'é'.encode('utf-8'), b'c'))

    def test_request_flood_bound(self):
        session = Md5Supplicant(LOCAL, 'alice', b'b', max_requests=2)
        session.start(0)
        session.receive(request(1, 1), 1)
        session.receive(request(2, 1), 2)
        self.assertEqual(session.receive(request(3, 1), 3).state, State.FAILED)
        self.assertFalse(session._password)

    def test_idle_cannot_authenticate(self):
        idle = Md5Supplicant(LOCAL, 'alice', b'b')
        self.assertEqual(idle.receive(request(97, 4, b'\x01c'), 0).kind, 'ignored')
        self.assertIsNone(idle.peer)


if __name__ == '__main__':
    unittest.main(verbosity=2)
