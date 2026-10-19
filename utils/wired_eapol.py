"""Pure EAPOL/EAP-MD5 prototype. No sockets, DLL loads, credentials files or I/O.

This implements standard packets only: no vendor fingerprint/health spoofing,
no Ruijie extensions, no heartbeat and no claim of campus interoperability.
Only a caller can transmit returned bytes. Treat them as sensitive session data.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import math
import struct

PAE_GROUP = bytes.fromhex('0180c2000003')
ETHERTYPE = 0x888E
MAX_BODY = 1496


class ProtocolError(ValueError):
    """Malformed/unsupported input, deliberately without packet contents."""


def _mac(value: bytes, *, source: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != 6:
        raise ProtocolError('invalid MAC address')
    if source and (value == b'\0' * 6 or value[0] & 1):
        raise ProtocolError('source must be nonzero unicast')
    return value


@dataclass(frozen=True)
class EapPacket:
    code: int
    identifier: int
    method: int | None = None
    data: bytes = field(default=b'', repr=False)

    def encode(self) -> bytes:
        if type(self.code) is not int or self.code not in (1, 2, 3, 4):
            raise ProtocolError('unsupported EAP code')
        if type(self.identifier) is not int or not 0 <= self.identifier <= 255:
            raise ProtocolError('invalid EAP identifier')
        if type(self.data) is not bytes:
            raise ProtocolError('EAP data must be bytes')
        if self.code in (3, 4):
            if self.method is not None or self.data:
                raise ProtocolError('outcome packet has unexpected body')
            body = b''
        else:
            if type(self.method) is not int or not 1 <= self.method <= 255:
                raise ProtocolError('request/response requires method')
            body = bytes((self.method,)) + self.data
        if len(body) + 4 > MAX_BODY:
            raise ProtocolError('oversized EAP packet')
        return struct.pack('!BBH', self.code, self.identifier, len(body) + 4) + body

    @classmethod
    def decode(cls, raw: bytes) -> EapPacket:
        if type(raw) is not bytes or not 4 <= len(raw) <= MAX_BODY:
            raise ProtocolError('invalid EAP size')
        code, identifier, length = struct.unpack('!BBH', raw[:4])
        if length != len(raw):
            raise ProtocolError('EAP length mismatch')
        if code in (1, 2):
            if len(raw) < 5:
                raise ProtocolError('missing EAP method')
            result = cls(code, identifier, raw[4], raw[5:])
        else:
            result = cls(code, identifier, None, raw[4:])
        result.encode()  # Central validation, including exact success/failure size.
        return result


@dataclass(frozen=True)
class EthernetEapol:
    destination: bytes = field(repr=False)
    source: bytes = field(repr=False)
    kind: int
    payload: bytes = field(default=b'', repr=False)
    version: int = 1

    def encode(self, *, pad: bool = True) -> bytes:
        _mac(self.destination)
        _mac(self.source, source=True)
        if type(self.version) is not int or self.version not in (1, 2, 3):
            raise ProtocolError('unsupported EAPOL version')
        if type(self.kind) is not int or self.kind not in (0, 1, 2):
            raise ProtocolError('unsupported EAPOL kind')
        if type(self.payload) is not bytes or len(self.payload) > MAX_BODY:
            raise ProtocolError('invalid EAPOL body')
        if self.kind == 0:
            EapPacket.decode(self.payload)
        elif self.payload:
            raise ProtocolError('start/logoff must have empty body')
        raw = self.destination + self.source + struct.pack('!HBBH', ETHERTYPE, self.version, self.kind, len(self.payload)) + self.payload
        return raw.ljust(60, b'\0') if pad else raw

    @classmethod
    def decode(cls, raw: bytes) -> EthernetEapol:
        if type(raw) is not bytes or not 18 <= len(raw) <= 1514:
            raise ProtocolError('invalid Ethernet size')
        protocol, version, kind, length = struct.unpack('!HBBH', raw[12:18])
        if protocol != ETHERTYPE:
            raise ProtocolError('not untagged EAPOL')
        end = 18 + length
        if end > len(raw) or length > MAX_BODY:
            raise ProtocolError('truncated EAPOL')
        # Minimum Ethernet padding need not be zero. Longer extensions remain
        # outside this standard-only codec and are not silently hidden.
        if len(raw) > max(60, end) or (len(raw) != 60 and any(raw[end:])):
            raise ProtocolError('unsupported trailing bytes')
        result = cls(raw[:6], raw[6:12], kind, raw[18:end], version)
        result.encode(pad=False)
        return result


def md5_response(identifier: int, password: bytes, challenge: bytes) -> bytes:
    if type(identifier) is not int or not 0 <= identifier <= 255:
        raise ProtocolError('invalid EAP identifier')
    if type(password) is not bytes or not 1 <= len(password) <= 1024:
        raise ProtocolError('invalid password byte length')
    if type(challenge) is not bytes or not 1 <= len(challenge) <= 255:
        raise ProtocolError('invalid challenge byte length')
    return hashlib.md5(bytes((identifier,)) + password + challenge, usedforsecurity=False).digest()


class State(str, Enum):
    IDLE = 'idle'
    WAIT_REQUEST = 'waiting_for_request'
    WAIT_CHALLENGE = 'waiting_for_challenge'
    WAIT_RESULT = 'waiting_for_result'
    AUTHENTICATED = 'eap_authenticated'
    FAILED = 'failed'
    TIMED_OUT = 'timed_out'
    CANCELLED = 'cancelled'
    CLOSED = 'closed'


@dataclass(frozen=True)
class Effect:
    kind: str
    state: State
    reason: str
    frame: bytes | None = field(default=None, repr=False)


class Md5Supplicant:
    """One explicitly started session, without automatic reauthentication.

    username is UTF-8 on wire. password_bytes are explicit: callers must choose
    the server/native-compatible encoding; this module never guesses it.
    EAP-MD5 provides no server authentication; peer-MAC pinning is routing hygiene,
    not cryptographic trust. A matching EAP Success says nothing about IP access.
    """
    _active = frozenset((State.WAIT_REQUEST, State.WAIT_CHALLENGE, State.WAIT_RESULT))

    def __init__(self, local_mac: bytes, username: str, password_bytes: bytes,
                 *, timeout: float = 60, start_interval: float = 3,
                 max_start_attempts: int = 3, max_requests: int = 64):
        self.local_mac = _mac(local_mac, source=True)
        if not isinstance(username, str) or not username or any(ord(c) < 32 or ord(c) == 127 for c in username):
            raise ProtocolError('invalid username')
        self._username = username.encode('utf-8')
        if len(self._username) > 253:
            raise ProtocolError('username too long')
        if type(password_bytes) is not bytes or not 1 <= len(password_bytes) <= 1024:
            raise ProtocolError('invalid password byte length')
        if not all(type(x) in (int, float) and math.isfinite(x) and x > 0 for x in (timeout, start_interval)):
            raise ProtocolError('invalid timeout')
        if type(max_start_attempts) is not int or not 1 <= max_start_attempts <= 10:
            raise ProtocolError('invalid retry count')
        if type(max_requests) is not int or not 1 <= max_requests <= 256:
            raise ProtocolError('invalid request limit')
        self._password = bytearray(password_bytes)
        self.timeout, self.start_interval = timeout, start_interval
        self.max_start_attempts, self.max_requests = max_start_attempts, max_requests
        self.state = State.IDLE
        self.peer = None
        self._clock = None
        self._deadline = None
        self._retry_at = None
        self._attempts = 0
        self._requests = 0
        self._seen_identifiers = set()
        self._last_request = None
        self._last_response = None
        self._last_identifier = None

    def _time(self, now: float) -> None:
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0 or (self._clock is not None and now < self._clock):
            raise ProtocolError('time must be finite and monotonic')
        self._clock = now

    def _effect(self, kind: str, reason: str, frame: bytes | None = None) -> Effect:
        return Effect(kind, self.state, reason, frame)

    def _wipe(self) -> None:
        self._password[:] = b'\0' * len(self._password)
        self._password.clear()
        self._last_request = self._last_response = None
        # Python and hashlib can retain temporary immutable copies: not a secure
        # memory erasure guarantee. No credentials or packets are persisted.

    def _expire(self) -> bool:
        if self.state in self._active and self._clock >= self._deadline:
            self.state = State.TIMED_OUT
            self._wipe()
            return True
        return False

    def start(self, now: float) -> Effect:
        if self.state is not State.IDLE:
            raise ProtocolError('session already started')
        self._time(now)
        self.state = State.WAIT_REQUEST
        self._deadline = now + self.timeout
        if not math.isfinite(self._deadline) or self._deadline <= now:
            self.state = State.IDLE
            raise ProtocolError('time resolution cannot represent deadline')
        self._retry_at = now + self.start_interval
        self._attempts = 1
        return self._effect('send', 'start', EthernetEapol(PAE_GROUP, self.local_mac, 1).encode())

    def tick(self, now: float) -> Effect:
        self._time(now)
        if self._expire():
            return self._effect('status', 'authentication deadline exceeded')
        if self.state is State.WAIT_REQUEST and self._attempts < self.max_start_attempts and now >= self._retry_at:
            self._attempts += 1
            self._retry_at = now + self.start_interval
            return self._effect('send', 'retry start', EthernetEapol(PAE_GROUP, self.local_mac, 1).encode())
        return self._effect('none', 'no action')

    def receive(self, raw: bytes, now: float) -> Effect:
        self._time(now)
        if self._expire():
            return self._effect('status', 'authentication deadline exceeded')
        if self.state not in self._active:
            return self._effect('ignored', 'no active authentication')
        try:
            frame = EthernetEapol.decode(raw)
            if frame.destination != self.local_mac or frame.source == self.local_mac or frame.kind != 0:
                return self._effect('ignored', 'unrelated frame')
            if self.peer is not None and frame.source != self.peer:
                return self._effect('ignored', 'unrelated peer')
            packet = EapPacket.decode(frame.payload)
            if packet.code in (3, 4):
                if packet.identifier != self._last_identifier or self._last_identifier is None:
                    return self._effect('ignored', 'unsolicited outcome')
                if packet.code == 3 and self.state is not State.WAIT_RESULT:
                    return self._effect('ignored', 'success before MD5 response')
                self.state = State.AUTHENTICATED if packet.code == 3 else State.FAILED
                self._wipe()
                return self._effect('status', 'EAP success; IP access unverified' if packet.code == 3 else 'EAP failure')
            if packet.code != 1:
                return self._effect('ignored', 'not an authenticator request')
            if packet.identifier == self._last_identifier:
                if frame.payload == self._last_request:
                    return self._effect('send', 'duplicate request', self._last_response)
                return self._effect('ignored', 'identifier reused with changed request')
            if packet.identifier in self._seen_identifiers:
                return self._effect('ignored', 'stale request identifier')
            if self._requests >= self.max_requests:
                self.state = State.FAILED
                self._wipe()
                return self._effect('status', 'request limit exceeded')
            if packet.method == 1:
                if self.state is State.WAIT_RESULT:
                    return self._effect('ignored', 'new identity requires explicit restart')
                response = EapPacket(2, packet.identifier, 1, self._username)
                next_state = State.WAIT_CHALLENGE
            elif packet.method == 4:
                if not packet.data or not 1 <= packet.data[0] <= len(packet.data) - 1:
                    raise ProtocolError('truncated MD5 challenge')
                count = packet.data[0]
                # Name following the challenge is optional, not part of the hash.
                challenge = packet.data[1:1 + count]
                digest = md5_response(packet.identifier, bytes(self._password), challenge)
                response = EapPacket(2, packet.identifier, 4, b'\x10' + digest + self._username)
                next_state = State.WAIT_RESULT
            elif packet.method == 2:
                response = EapPacket(2, packet.identifier, 2)
                next_state = self.state
            elif packet.method in (3, 254, 255):
                return self._effect('ignored', 'unsupported request method')
            else:
                response = EapPacket(2, packet.identifier, 3, b'\x04')
                next_state = State.WAIT_CHALLENGE
            encoded = EthernetEapol(frame.source, self.local_mac, 0, response.encode()).encode()
        except ProtocolError:
            return self._effect('ignored', 'malformed or unsupported frame')
        self.peer = frame.source
        self.state = next_state
        self._requests += 1
        self._seen_identifiers.add(packet.identifier)
        self._last_request, self._last_response = frame.payload, encoded
        self._last_identifier = packet.identifier
        return self._effect('send', 'response', encoded)

    def cancel(self) -> Effect:
        if self.state is State.CLOSED:
            return self._effect('none', 'already closed')
        self.state = State.CANCELLED
        self._wipe()
        return self._effect('status', 'cancelled')

    def logoff(self) -> Effect:
        if self.state in (State.IDLE, State.CANCELLED, State.CLOSED, State.TIMED_OUT, State.FAILED):
            return self._effect('none', 'no session to close')
        frame = EthernetEapol(self.peer or PAE_GROUP, self.local_mac, 2).encode()
        self.state = State.CLOSED
        self._wipe()
        return self._effect('send', 'logoff', frame)
