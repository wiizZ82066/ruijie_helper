"""Private, pure codec for evidenced Ruijie network/credential extensions.

No I/O, packet transmission, native code calls or fabricated integrity fields.
The caller supplies its real interface values and its own credentials.
"""
from dataclasses import dataclass, field
import binascii
import hashlib
import ipaddress

VENDOR = b'\x00\x00\x13\x11'


def transform(data):
    return bytes(int(f'{x:08b}'[::-1], 2) ^ 255 for x in data)


def network_prefix(dhcp, address, mask, gateway, dns):
    if type(dhcp) is not bool:
        raise ValueError('invalid DHCP flag')
    plain = VENDOR + bytes([dhcp]) + b''.join(
        ipaddress.IPv4Address(x).packed for x in (address, mask, gateway, dns))
    return transform(plain + binascii.crc_hqx(plain, 0).to_bytes(2, 'big'))


def read_network_prefix(data):
    if len(data) != 23:
        raise ValueError('invalid network prefix length')
    raw = transform(data)
    if raw[:4] != VENDOR or raw[4] not in (0, 1) or binascii.crc_hqx(raw[:21], 0) != int.from_bytes(raw[21:], 'big'):
        raise ValueError('invalid network prefix checksum or signature')
    return bool(raw[4]), tuple(str(ipaddress.IPv4Address(raw[i:i+4])) for i in (5, 9, 13, 17))


def password_field(username, password, seed):
    if not all(type(x) is bytes for x in (username, password, seed)):
        raise ValueError('credentials and seed must be bytes')
    if not username or b'\0' in username or not 1 <= len(password) <= 240 or b'\0' in password or len(seed) != 16:
        raise ValueError('invalid credential or seed length')
    padded = password.ljust(max(16, (len(password)+15)//16*16), b'\0')
    output = bytearray()
    for offset in range(0, len(padded), 16):
        digest = hashlib.md5(username + seed, usedforsecurity=False).digest()
        seed = bytes(a ^ b for a, b in zip(padded[offset:offset+16], digest))
        output.extend(seed)
    return bytes(output)


def tlv(kind, payload):
    if type(kind) is not int or not 0 <= kind <= 255 or type(payload) is not bytes or len(payload) > 247:
        raise ValueError('invalid extension property')
    return bytes((0x1a, len(payload)+8)) + VENDOR + bytes((kind, len(payload)+2)) + payload


def extension(prefix, name, version, reason, properties):
    read_network_prefix(prefix)
    if type(name) is not bytes or not name or len(name) > 32 or b'\0' in name or len(version) != 4 or not 0 <= reason <= 255:
        raise ValueError('invalid extension header')
    data = b''.join(tlv(kind, payload) for kind, payload in properties)
    if len(data) > 1426:
        raise ValueError('extension exceeds Ethernet capacity')
    return prefix + VENDOR + name.ljust(32, b'\0') + version + bytes([reason]) + VENDOR + len(data).to_bytes(2, 'big') + data


@dataclass(frozen=True)
class SuccessParameters:
    hello_enabled: bool
    hello_interval: int
    hello_flags: int
    hello_key: int = field(repr=False)
    properties: tuple = field(repr=False)


def success_parameters(body):
    """Parse the observed native outcome layout; never expose notices/keys in repr."""
    if len(body) < 6 or body[:4] != VENDOR:
        raise ValueError('invalid success signature')
    q = 6 + int.from_bytes(body[4:6], 'big')
    if q+111 > len(body) or body[q:q+4] != VENDOR:
        raise ValueError('truncated success header')
    offset = q+111+body[q+110]*32
    if offset+27 > len(body) or body[offset:offset+4] != VENDOR or body[offset+6:offset+10] != VENDOR:
        raise ValueError('invalid success blocks')
    if body[offset+4] != 1 or body[offset+10] != 1 or body[offset+5] not in (0, 1) or body[offset+11] not in (0, 1):
        raise ValueError('unsupported success block types')
    hello = transform(body[offset+12:offset+27])
    if hello[:5] != VENDOR+b'\x0a' or hello[5] not in (0, 1):
        raise ValueError('invalid heartbeat descriptor')
    interval = int.from_bytes(hello[10:14], 'big')
    if hello[5] and not 1 <= interval <= 86400:
        raise ValueError('invalid enabled heartbeat interval')
    cursor = offset+27
    properties = []
    while cursor < len(body):
        if cursor+6 > len(body) or body[cursor:cursor+4] != VENDOR:
            raise ValueError('invalid success property signature')
        kind, size = body[cursor+4:cursor+6]
        if size < 2 or cursor+4+size > len(body):
            raise ValueError('invalid success property length')
        properties.append((kind, body[cursor+6:cursor+4+size]))
        cursor += 4+size
    return SuccessParameters(bool(hello[5]), interval, hello[14], int.from_bytes(hello[6:10], 'big'), tuple(properties))


def parse_extension(blob):
    if len(blob) < 70 or blob[23:27] != b'\x00\x00\x13\x11' or blob[64:68] != b'\x00\x00\x13\x11':
        raise ValueError('extension_layout_mismatch')
    size = int.from_bytes(blob[68:70], 'big')
    if size != len(blob)-70:
        raise ValueError('extension_total_length_mismatch')
    fields = []
    cursor = 70
    while cursor < len(blob):
        if len(blob)-cursor < 8:
            raise ValueError('short_tlv')
        kind, length = blob[cursor:cursor+2]
        if kind != 0x1a or length < 8 or cursor+length > len(blob) or blob[cursor+2:cursor+6] != b'\x00\x00\x13\x11' or blob[cursor+7] != length-6:
            raise ValueError('invalid_tlv')
        fields.append((cursor, blob[cursor+6], blob[cursor+8:cursor+length]))
        cursor += length
    return fields
