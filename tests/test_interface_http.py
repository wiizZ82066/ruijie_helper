"""Offline packets and sockets; never access a real interface or resolver."""
import io
import socket
import ssl
import struct
import threading
import time
import unittest
from unittest.mock import Mock, patch

from utils import interface_http as http


HOST = http.PORTAL_HOST
URL = "https://" + HOST + ":8443/eportal/InterFace.do?method=login"
PROBE = "http://www.msftconnecttest.com/connecttest.txt"


def name(value):
    return b"".join(bytes([len(x)]) + x.encode("ascii") for x in value.split(".")) + b"\0"


def record(owner, kind, payload, ttl=45):
    return owner + struct.pack("!HHIH", kind, 1, ttl, len(payload)) + payload


def dns_packet(records, host=HOST, ident=1234, flags=0x8180):
    return struct.pack("!6H", ident, flags, 1, len(records), 0, 0) + name(host) + struct.pack("!HH", 1, 1) + b"".join(records)


class FakeSocket:
    def __init__(self, response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", *, udp=False):
        self.data = io.BytesIO(response)
        self.udp = udp
        self.calls = []
        self.closed = False
        self.sent = b""

    def setsockopt(self, *args): self.calls.append(("setsockopt", args))
    def bind(self, value): self.calls.append(("bind", value))
    def settimeout(self, value): self.calls.append(("settimeout", value))
    def connect(self, value): self.calls.append(("connect", value))
    def close(self): self.closed = True
    def send(self, value): self.sent += value; return len(value)
    def sendall(self, value): self.sent += value
    def recv(self, size):
        ident = struct.unpack_from("!H", self.sent)[0]
        return dns_packet([record(b"\xc0\x0c", 1, socket.inet_aton("10.22.33.44"))], ident=ident)
    def recv_into(self, buffer, size):
        result = self.data.read(size)
        buffer[:len(result)] = result
        return len(result)


class DNSParserTests(unittest.TestCase):
    def parse(self, packet):
        return http._parse_dns(packet, 1234, HOST)

    def test_a_answer_and_short_cache_ttl(self):
        result = self.parse(dns_packet([record(b"\xc0\x0c", 1, socket.inet_aton("10.22.33.44"))]))
        self.assertEqual(result, (["10.22.33.44"], None, 30))

    def test_cname_and_only_related_a_answer(self):
        alias = "portal.example.edu"
        data = dns_packet([record(b"\xc0\x0c", 5, name(alias), 9),
                           record(name(alias), 1, socket.inet_aton("10.2.3.4"), 20),
                           record(name("unrelated.example"), 1, socket.inet_aton("10.9.9.9"))])
        self.assertEqual(self.parse(data), (["10.2.3.4"], None, 9))

    def test_cname_only_requests_followup(self):
        self.assertEqual(self.parse(dns_packet([record(b"\xc0\x0c", 5, name("alias.example"))])),
                         ([], "alias.example", 30))

    def test_bad_ids_questions_flags_and_types_rejected(self):
        base = dns_packet([])
        packets = [dns_packet([], ident=22), dns_packet([], host="wrong.example"),
                   dns_packet([], flags=0x0100), dns_packet([], flags=0x8380),
                   dns_packet([], flags=0x8183), dns_packet([], flags=0x8980),
                   base[:-4] + struct.pack("!HH", 28, 1), base + b"junk"]
        for packet in packets:
            with self.subTest(packet=packet[:12]):
                with self.assertRaises(ValueError): self.parse(packet)

    def test_invalid_address_ranges_rejected(self):
        for address in ("127.0.0.1", "0.0.0.0", "169.254.1.1", "224.1.2.3", "198.18.4.5", "198.19.255.254", "255.255.255.255"):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    self.parse(dns_packet([record(b"\xc0\x0c", 1, socket.inet_aton(address))]))

    def test_truncations_and_compression_loops_rejected(self):
        data = dns_packet([record(b"\xc0\x0c", 1, socket.inet_aton("10.1.2.3"))])
        for size in range(len(data)):
            with self.assertRaises(ValueError): self.parse(data[:size])
        for data in (b"\xc0\x00", b"\xc0\xff", b"\x40invalid", b"\xff", b"\x05abc"):
            with self.assertRaises(ValueError): http._dns_name(data, 0)

    def test_cname_cycle_and_duplicate_alias_rejected(self):
        for records in ([record(b"\xc0\x0c", 5, name(HOST))],
                        [record(b"\xc0\x0c", 5, name("a.example")), record(b"\xc0\x0c", 5, name("b.example"))],
                        [record(b"\xc0\x0c", 1, b"bad")]):
            with self.assertRaises(ValueError): self.parse(dns_packet(records))


class InterfaceHTTPTests(unittest.TestCase):
    def make(self, cancel=None):
        return http.InterfaceHTTP(7, "10.1.2.3", ["10.1.2.1"], cancel)

    def transport(self, response=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", error=None):
        client = self.make()
        fake = FakeSocket(response)
        context = ssl.create_default_context()
        wrap = Mock(side_effect=error) if error else Mock(return_value=fake)
        # The real default context is retained so certificate options are tested.
        context.wrap_socket = wrap
        return client, fake, context

    def test_interface_validation(self):
        for args in ((0, "10.1.2.3", ["10.1.2.1"]), (True, "10.1.2.3", ["10.1.2.1"]),
                     (1, "127.0.0.1", ["10.1.2.1"]), (1, "10.1.2.3", []),
                     (1, "10.1.2.3", "10.1.2.1"), (1, "10.1.2.3", ["198.18.0.2"])):
            with self.assertRaises(http.InterfaceHTTPError) as caught: http.InterfaceHTTP(*args)
            self.assertEqual(caught.exception.kind, "policy")

    def test_dns_and_tcp_are_both_pinned_no_system_resolver(self):
        client, tcp, context = self.transport()
        udp = FakeSocket(udp=True)
        with patch.object(http.socket, "socket", side_effect=[udp, tcp]) as factory, \
                patch.object(http.socket, "getaddrinfo", side_effect=AssertionError("system DNS forbidden")), \
                patch.object(http.ssl, "create_default_context", return_value=context):
            result = client.request("POST", URL, b"synthetic=credential", {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(result.body, b"OK")
        self.assertEqual(factory.call_args_list[0].args, (socket.AF_INET, socket.SOCK_DGRAM))
        self.assertEqual(factory.call_args_list[1].args, (socket.AF_INET, socket.SOCK_STREAM))
        for sock in (udp, tcp):
            self.assertIn(("setsockopt", (socket.IPPROTO_IP, 31, socket.htonl(7))), sock.calls)
            self.assertIn(("bind", ("10.1.2.3", 0)), sock.calls)
            self.assertTrue(sock.closed)
        self.assertIn(("connect", ("10.1.2.1", 53)), udp.calls)
        self.assertIn(("connect", ("10.22.33.44", 8443)), tcp.calls)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.maximum_version, ssl.TLSVersion.TLSv1_2)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        context.wrap_socket.assert_called_once_with(tcp, server_hostname=HOST)

    def test_cache_is_bounded_and_per_instance(self):
        client = self.make()
        udp = FakeSocket(udp=True)
        with patch.object(http.socket, "socket", return_value=udp) as factory:
            self.assertEqual(client._resolve(HOST, time.monotonic() + 10), ["10.22.33.44"])
            client._resolve(HOST, time.monotonic() + 10)
            self.assertEqual(factory.call_count, 1)
        self.assertLessEqual(client._cache[HOST][0] - time.monotonic(), 30)
        self.assertEqual(self.make()._cache, {})

    def test_redirect_returned_without_followup_or_credential_leak(self):
        data = b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/path\r\nContent-Length: 0\r\n\r\n"
        client, sock, context = self.transport(data)
        with patch.object(client, "_resolve", return_value=["10.2.3.4"]), \
                patch.object(http.socket, "socket", return_value=sock) as factory, \
                patch.object(http.ssl, "create_default_context", return_value=context):
            result = client.request("POST", URL, b"password=synthetic")
        self.assertEqual(result.status, 302)
        self.assertEqual(result.headers["location"], "https://evil.example/path")
        self.assertEqual(factory.call_count, 1)
        self.assertNotIn("synthetic", repr(result))

    def test_allowlist_before_any_network(self):
        client = self.make()
        with patch.object(http.socket, "socket", side_effect=AssertionError("network forbidden")):
            for method, target in (("GET", "https://evil.example/"), ("GET", "http://" + HOST + ":8443/"),
                                   ("GET", "https://" + HOST + "/"), ("GET", "https://" + HOST + ":8443@evil.example/"),
                                   ("GET", "https://" + "user:secret" + "@" + HOST + ":8443/"), ("GET", URL + "#secret"),
                                   ("GET", PROBE + "?password=secret"), ("POST", PROBE),
                                   ("GET", "https://" + HOST + ".evil.example:8443/"), ("GET", URL + "\r\nX:secret")):
                with self.subTest(target=target):
                    with self.assertRaises(http.InterfaceHTTPError) as caught: client.request(method, target)
                    self.assertEqual(caught.exception.kind, "policy")
                    self.assertNotIn("secret", str(caught.exception))

    def test_probe_cannot_carry_credentials_or_cookies(self):
        client = self.make()
        with patch.object(http.socket, "socket", side_effect=AssertionError("network forbidden")):
            for body, headers in ((b"secret", {}), (None, {"Authorization": "Bearer secret"}), (None, {"Cookie": "secret"})):
                with self.assertRaises(http.InterfaceHTTPError): client.request("GET", PROBE, body, headers)
        sock = FakeSocket()
        client._cookies["session"] = ("synthetic", "/")
        with patch.object(client, "_resolve", return_value=["10.2.3.4"]), patch.object(http.socket, "socket", return_value=sock):
            client.request("GET", PROBE)
        self.assertNotIn(b"synthetic", sock.sent)

    def test_header_injection_and_overrides_rejected(self):
        client = self.make()
        for headers in ({"Host": "evil.example"}, {"X\r\nBad": "x"}, {"X": "x\r\nCookie:secret"},
                        {"Content-Length": "0"}, {"Transfer-Encoding": "chunked"}, {"Proxy-Authorization": "secret"}):
            with self.assertRaises(http.InterfaceHTTPError) as caught: client.request("GET", URL, headers=headers)
            self.assertEqual(caught.exception.kind, "policy")

    def test_certificate_timeout_and_network_exceptions_sanitized(self):
        for error, kind in ((ssl.SSLCertVerificationError("secret-url-and-password"), "certificate"),
                            (TimeoutError("secret-url-and-password"), "timeout"),
                            (OSError("secret-url-and-password"), "network")):
            client, sock, context = self.transport(error=error)
            with patch.object(client, "_resolve", return_value=["10.2.3.4"]), \
                    patch.object(http.socket, "socket", return_value=sock), \
                    patch.object(http.ssl, "create_default_context", return_value=context):
                with self.assertRaises(http.InterfaceHTTPError) as caught: client.request("POST", URL, b"private-value")
            self.assertEqual(caught.exception.kind, kind)
            self.assertNotIn("secret", str(caught.exception))
            self.assertNotIn("private", str(caught.exception))
            self.assertTrue(sock.closed)

    def test_socket_closed_when_pinning_fails(self):
        fake = FakeSocket()
        fake.setsockopt = Mock(side_effect=OSError("private"))
        with patch.object(http.socket, "socket", return_value=fake):
            with self.assertRaises(OSError): self.make()._socket(socket.SOCK_STREAM, time.monotonic() + 5)
        self.assertTrue(fake.closed)

    def test_cancellation_and_expired_deadline(self):
        event = threading.Event()
        event.set()
        with patch.object(http.socket, "socket", side_effect=AssertionError("network forbidden")):
            with self.assertRaises(http.InterfaceHTTPError) as caught: self.make(event).request("GET", URL)
        self.assertEqual(caught.exception.kind, "cancelled")
        with self.assertRaises(http.InterfaceHTTPError) as caught: self.make()._check(time.monotonic() - 1)
        self.assertEqual(caught.exception.kind, "timeout")

    def test_response_bound_and_protocol_errors(self):
        for response in (b"HTTP/1.1 200 OK\r\nContent-Length: 2097152\r\n\r\n",
                         b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort",
                         b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nOK",
                         b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n0\r\n\r\n",
                         b"HTTP/1.1 200 OK\r\nContent-Length: -3\r\n\r\n",
                         b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * http.MAX_RESPONSE,
                         b"not HTTP: private-secret\r\n\r\n"):
            client, sock, context = self.transport(response)
            with patch.object(client, "_resolve", return_value=["10.2.3.4"]), \
                    patch.object(http.socket, "socket", return_value=sock), \
                    patch.object(http.ssl, "create_default_context", return_value=context):
                with self.assertRaises(http.InterfaceHTTPError) as caught: client.request("GET", URL)
            self.assertEqual(caught.exception.kind, "protocol")
            self.assertNotIn("secret", str(caught.exception))
            self.assertTrue(sock.closed)

    def test_cookies_in_memory_only_and_domain_restricted(self):
        client = self.make()
        client._remember_cookies([("Set-Cookie", "bad=secret; Domain=evil.example"),
                                 ("Set-Cookie", "good=synthetic; Path=/eportal; Secure; HttpOnly")])
        self.assertEqual(client._cookies, {"good": ("synthetic", "/eportal")})
        self.assertEqual(self.make()._cookies, {})
        client._remember_cookies([("Set-Cookie", "good=gone; Max-Age=0")])
        self.assertEqual(client._cookies, {})


if __name__ == "__main__":
    unittest.main()
