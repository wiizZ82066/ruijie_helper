import hashlib
import unittest
from utils.wired_vendor import VENDOR, transform, network_prefix, read_network_prefix, password_field, extension, success_parameters
from utils.wired_vendor import parse_extension


class VendorCodecTests(unittest.TestCase):
    def test_transform_is_involution(self):
        data = bytes(range(256))
        self.assertEqual(transform(transform(data)), data)

    def test_prefix_known_crc_and_corruption(self):
        prefix = network_prefix(True, '192.0.2.2', '255.255.255.0', '192.0.2.1', '192.0.2.53')
        self.assertEqual(read_network_prefix(prefix), (True, ('192.0.2.2', '255.255.255.0', '192.0.2.1', '192.0.2.53')))
        with self.assertRaises(ValueError):
            read_network_prefix(prefix[:-1]+bytes([prefix[-1]^1]))

    def test_password_multiple_blocks_and_challenge(self):
        user, password, seed = b'fixture-user', b'synthetic password over 16 bytes', bytes(range(16))
        encoded = password_field(user, password, seed)
        plain = bytearray()
        for i in range(0, len(encoded), 16):
            block = encoded[i:i+16]
            plain.extend(a ^ b for a, b in zip(block, hashlib.md5(user+seed).digest()))
            seed = block
        self.assertEqual(bytes(plain).rstrip(b'\0'), password)
        self.assertNotEqual(encoded, password_field(user, password, bytes(16)))

    def test_password_bounds(self):
        for password in (b'', b'a'*241, b'a\0b'):
            with self.assertRaises(ValueError):
                password_field(b'fixture', password, bytes(16))

    def test_tlv_embedded_marker_not_split(self):
        prefix = network_prefix(False, *(['0.0.0.0']*4))
        props = [(0x39, b'\x1a\x00'+VENDOR), (0x76, b'')]
        data = extension(prefix, b'CampusAuthenticator', bytes(4), 0, props)
        self.assertEqual([(k,v) for _,k,v in parse_extension(data)], props)

    @staticmethod
    def success(enabled=0, interval=20):
        fixed = VENDOR+bytes(107)
        blocks = (VENDOR+b'\x01\x00')*2
        hello = transform(VENDOR+b'\x0a'+bytes([enabled])+b'\x01\x02\x03\x04'+interval.to_bytes(4,'big')+b'\0')
        return VENDOR+b'\0\0'+fixed+blocks+hello+VENDOR+b'\x79\x03\x02'

    def test_disabled_heartbeat_preserved_and_secret_repr(self):
        result = success_parameters(self.success())
        self.assertFalse(result.hello_enabled)
        self.assertEqual(result.hello_interval, 20)
        self.assertEqual(result.properties, ((0x79, b'\x02'),))
        self.assertNotIn('16909060', repr(result))

    def test_success_truncated_every_boundary(self):
        data = self.success()
        # Complete header with no optional properties is valid; all cuts before it fail.
        for cut in range(len(data)-7):
            with self.subTest(cut=cut), self.assertRaises(ValueError):
                success_parameters(data[:cut])
        with self.assertRaises(ValueError):
            success_parameters(self.success(enabled=1, interval=0))


if __name__ == '__main__':
    unittest.main()
