"""Bounded, interface-pinned transport for the campus portal and its HTTP probe.

No system resolver, proxy settings, routing changes, or automatic redirects are
used. Authentication requests remain on the portal's verified TLS connection.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import http.client
from http.cookies import SimpleCookie
import io
import ipaddress
import secrets
import socket
import ssl
import struct
import time
from urllib.parse import urlsplit


PORTAL_HOST = "webauthsa.jnu.edu.cn"
PROBE_HOST = "www.msftconnecttest.com"
MAX_RESPONSE = 1024 * 1024
MAX_HEADERS = 64 * 1024
REQUEST_SECONDS = 20.0
IP_UNICAST_IF = 31  # Windows IPv4 interface pinning; index uses network byte order.


class InterfaceHTTPError(RuntimeError):
    def __init__(self, message, kind="network"):
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str] = field(repr=False)
    body: bytes = field(repr=False)


def _failure(kind):
    messages = {
        "cancelled": "操作已取消", "timeout": "校园认证网络请求超时",
        "certificate": "校园认证服务器证书验证失败", "dns": "校园网络域名解析失败",
        "protocol": "校园认证服务器响应格式异常", "policy": "认证请求目标或参数不受支持",
        "network": "无法通过所选无线网卡访问校园认证服务",
    }
    return InterfaceHTTPError(messages[kind], kind)


def _real_ipv4(value):
    address = ipaddress.IPv4Address(value)
    if (address.is_loopback or address.is_multicast or address.is_link_local
            or address.is_unspecified or address.is_reserved
            or address in ipaddress.IPv4Network("198.18.0.0/15")):
        raise ValueError("unusable interface address")
    return str(address)


def _dns_name(data, offset):
    """Decode a DNS name with bounded labels, compression hops and wire offsets."""
    labels, visited = [], set()
    end = None
    size = 0
    for _ in range(128):
        if offset >= len(data) or offset in visited:
            raise ValueError("invalid DNS name")
        visited.add(offset)
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("invalid DNS pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer >= offset:
                raise ValueError("non-backward DNS pointer")
            if end is None:
                end = offset + 2
            offset = pointer
            continue
        if length & 0xC0:
            raise ValueError("invalid DNS label")
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), end if end is not None else offset
        if offset + length > len(data):
            raise ValueError("truncated DNS name")
        label = data[offset:offset + length].decode("ascii")
        if not all(c.isascii() and (c.isalnum() or c in "-_") for c in label):
            raise ValueError("invalid DNS characters")
        labels.append(label)
        size += length + 1
        if size > 254:
            raise ValueError("oversized DNS name")
        offset += length
    raise ValueError("too many DNS labels")


def _dns_query(host, query_id):
    labels = host.encode("ascii").split(b".")
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError("invalid query name")
    name = b"".join(bytes([len(label)]) + label for label in labels) + b"\0"
    if len(name) > 255:
        raise ValueError("oversized query name")
    return struct.pack("!6H", query_id, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)


def _parse_dns(data, query_id, host):
    """Return validated A answers, optional terminal CNAME and capped TTL."""
    if len(data) < 12 or len(data) > 4096:
        raise ValueError("invalid DNS size")
    ident, flags, questions, answers, authority, additional = struct.unpack_from("!6H", data)
    if ident != query_id or flags & 0x8000 == 0 or flags & 0x7A0F or questions != 1:
        raise ValueError("invalid DNS header")
    if answers + authority + additional > 128:
        raise ValueError("too many DNS records")
    question, offset = _dns_name(data, 12)
    if question != host.lower() or offset + 4 > len(data):
        raise ValueError("wrong DNS question")
    if struct.unpack_from("!HH", data, offset) != (1, 1):
        raise ValueError("wrong DNS question type")
    offset += 4
    aliases, addresses = {}, {}
    for record in range(answers + authority + additional):
        owner, offset = _dns_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("truncated DNS record")
        rtype, rclass, ttl, length = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        end = offset + length
        if end > len(data):
            raise ValueError("truncated DNS data")
        # Only answer-section records are accepted as resolution evidence.
        if record < answers and rclass == 1:
            if rtype == 1:
                if length != 4:
                    raise ValueError("invalid A record")
                address = _real_ipv4(data[offset:end])
                addresses.setdefault(owner, []).append((address, ttl))
            elif rtype == 5:
                alias, alias_end = _dns_name(data, offset)
                if alias_end != end or not alias or owner in aliases:
                    raise ValueError("invalid CNAME record")
                aliases[owner] = (alias, ttl)
        offset = end
    if offset != len(data):
        raise ValueError("trailing DNS bytes")
    current, seen, ttl = host.lower(), set(), 30
    for _ in range(9):
        if current in seen:
            raise ValueError("CNAME loop")
        seen.add(current)
        if current in addresses:
            if current in aliases:
                raise ValueError("ambiguous DNS answer")
            values = addresses[current]
            return [address for address, _ in values], None, min(ttl, *(t for _, t in values))
        if current not in aliases:
            return [], current if current != host.lower() else None, ttl
        current, alias_ttl = aliases[current]
        ttl = min(ttl, alias_ttl)
    raise ValueError("CNAME chain too long")


class _Reader(io.RawIOBase):
    def __init__(self, owner, sock, deadline):
        super().__init__()
        self.owner, self.sock, self.deadline = owner, sock, deadline
        self.total = 0

    def readable(self):
        return True

    def readinto(self, buffer):
        self.owner._timeout(self.sock, self.deadline)
        count = self.sock.recv_into(buffer, min(len(buffer), MAX_RESPONSE + 1 - self.total))
        self.total += count
        if self.total > MAX_RESPONSE:
            raise _failure("protocol")
        return count


class _HTTPStream:
    def __init__(self, owner, sock, deadline):
        self.owner, self.sock, self.deadline = owner, sock, deadline

    def makefile(self, mode):
        return io.BufferedReader(_Reader(self.owner, self.sock, self.deadline))


class InterfaceHTTP:
    """One selected IPv4 interface; create a new instance when binding changes."""
    def __init__(self, index, address, dns, cancel=None):
        try:
            if isinstance(index, bool) or not isinstance(index, int) or not 0 < index <= 0xFFFFFFFF:
                raise ValueError()
            self.index, self.address = index, _real_ipv4(address)
            if isinstance(dns, str):
                raise ValueError()
            self.dns = tuple(dict.fromkeys(_real_ipv4(server) for server in dns))
            if not self.dns or len(self.dns) > 8:
                raise ValueError()
        except (ValueError, TypeError):
            raise _failure("policy") from None
        self.cancel = cancel
        self._cache = {}
        self._cookies = {}

    def _check(self, deadline):
        cancelled = self.cancel and (self.cancel.is_set() if hasattr(self.cancel, "is_set") else self.cancel())
        if cancelled:
            raise _failure("cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _failure("timeout")
        return remaining

    def _timeout(self, sock, deadline):
        sock.settimeout(min(5.0, self._check(deadline)))

    def _socket(self, kind, deadline):
        sock = socket.socket(socket.AF_INET, kind)
        try:
            sock.setsockopt(socket.IPPROTO_IP, IP_UNICAST_IF, socket.htonl(self.index))
            sock.bind((self.address, 0))
            self._timeout(sock, deadline)
            return sock
        except BaseException:
            sock.close()
            raise

    def _resolve(self, host, deadline):
        self._check(deadline)
        cached = self._cache.get(host)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        current, seen, ttl = host, set(), 30
        for _ in range(8):
            if current in seen:
                break
            seen.add(current)
            answer = None
            for dns in self.dns:
                self._check(deadline)
                query_id = secrets.randbelow(65536)
                request = _dns_query(current, query_id)
                sock = None
                try:
                    sock = self._socket(socket.SOCK_DGRAM, deadline)
                    sock.connect((dns, 53))
                    sock.send(request)
                    answer = _parse_dns(sock.recv(4097), query_id, current)
                    break
                except (OSError, ValueError):
                    continue
                finally:
                    if sock is not None:
                        sock.close()
            if answer is None:
                break
            addresses, alias, answer_ttl = answer
            ttl = min(ttl, answer_ttl)
            if addresses:
                self._cache[host] = (time.monotonic() + max(0, ttl), addresses)
                return addresses
            if not alias:
                break
            current = alias
        self._check(deadline)
        raise _failure("dns")

    @staticmethod
    def _target(method, url):
        try:
            if not isinstance(url, str) or len(url) > 16384 or any(ord(c) <= 32 or ord(c) == 127 for c in url):
                raise ValueError()
            parsed = urlsplit(url)
            if parsed.username is not None or parsed.password is not None or parsed.fragment:
                raise ValueError()
            portal = parsed.scheme == "https" and parsed.hostname == PORTAL_HOST and parsed.port == 8443
            probe = (parsed.scheme == "http" and parsed.hostname == PROBE_HOST and parsed.port in (None, 80)
                     and parsed.path == "/connecttest.txt" and not parsed.query and method == "GET")
            if not (portal or probe) or method not in ("GET", "POST"):
                raise ValueError()
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            path.encode("ascii")
            return parsed.hostname, 8443 if portal else 80, path, portal
        except (ValueError, TypeError, UnicodeError):
            raise _failure("policy") from None

    def request(self, method, url, body=None, headers=None):
        """Return a bounded response without redirects; all exception text is safe."""
        sock = None
        response = None
        try:
            deadline = time.monotonic() + REQUEST_SECONDS
            self._check(deadline)
            method = str(method).upper()
            host, port, path, portal = self._target(method, url)
            if body is None:
                body = b""
            if not isinstance(body, bytes) or len(body) > 65536 or (method == "GET" and body):
                raise _failure("policy")
            request_headers = {"Host": host + (":8443" if portal else ""), "Connection": "close",
                               "Accept-Encoding": "identity", "User-Agent": "CampusLogin/1.0"}
            for key, value in (headers or {}).items():
                if (not isinstance(key, str) or not isinstance(value, str) or not key
                        or any(c not in "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" for c in key)
                        or any(ord(c) < 32 or ord(c) >= 127 for c in value)
                        or key.lower() in ("host", "connection", "content-length", "transfer-encoding", "cookie", "proxy-authorization", "accept-encoding")
                        or (not portal and key.lower() not in ("accept", "user-agent"))):
                    raise _failure("policy")
                request_headers[key] = value
            if portal and self._cookies:
                cookie = "; ".join(f"{name}={value}" for name, (value, prefix) in self._cookies.items()
                                   if path.split("?", 1)[0].startswith(prefix))
                if cookie:
                    request_headers["Cookie"] = cookie
            if method == "POST":
                request_headers["Content-Length"] = str(len(body))
            wire = (f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in request_headers.items()) + "\r\n").encode("ascii")
            if len(wire) > MAX_HEADERS:
                raise _failure("policy")
            addresses = self._resolve(host, deadline)
            connection_timed_out = False
            for address in addresses:
                try:
                    sock = self._socket(socket.SOCK_STREAM, deadline)
                    sock.connect((address, port))
                    break
                except OSError as exc:
                    connection_timed_out = isinstance(exc, TimeoutError)
                    if sock is not None:
                        sock.close()
                    sock = None
            if sock is None:
                raise _failure("timeout" if connection_timed_out else "network")
            if portal:
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_2
                context.set_ciphers("DEFAULT")
                self._timeout(sock, deadline)
                sock = context.wrap_socket(sock, server_hostname=host)
            self._timeout(sock, deadline)
            sock.sendall(wire + body)
            response = http.client.HTTPResponse(_HTTPStream(self, sock, deadline), method=method)
            response.begin()
            pairs = response.getheaders()
            lengths = [value for key, value in pairs if key.lower() == "content-length"]
            encodings = [value.lower().strip() for key, value in pairs if key.lower() == "transfer-encoding"]
            if (len(lengths) > 1 or lengths and not lengths[0].isascii()
                    or lengths and not lengths[0].isdigit()
                    or encodings and (encodings != ["chunked"] or lengths)):
                raise _failure("protocol")
            if (sum(len(k) + len(v) + 4 for k, v in pairs) > MAX_HEADERS
                    or response.length is not None and response.length > MAX_RESPONSE):
                raise _failure("protocol")
            payload = response.read(MAX_RESPONSE + 1)
            self._check(deadline)
            if len(payload) > MAX_RESPONSE or response.length not in (None, 0):
                raise _failure("protocol")
            if portal:
                self._remember_cookies(pairs)
            result_headers = {}
            for key, value in pairs:
                key = key.lower()
                result_headers[key] = result_headers.get(key, "") + (", " if key in result_headers else "") + value
            return Response(response.status, result_headers, payload)
        except InterfaceHTTPError:
            raise
        except ssl.SSLCertVerificationError:
            raise _failure("certificate") from None
        except (TimeoutError, socket.timeout):
            raise _failure("timeout") from None
        except (http.client.HTTPException, ValueError, UnicodeError, TypeError):
            raise _failure("protocol") from None
        except OSError:
            raise _failure("network") from None
        finally:
            if response is not None:
                response.close()
            if sock is not None:
                sock.close()

    def _remember_cookies(self, pairs):
        for name, value in pairs:
            if name.lower() != "set-cookie" or len(value) > 4096:
                continue
            parsed = SimpleCookie()
            try:
                parsed.load(value)
            except Exception:
                continue
            for key, item in parsed.items():
                if item["domain"] and item["domain"].lower() != PORTAL_HOST:
                    continue
                prefix = item["path"] or "/"
                encoded = item.coded_value
                if (not prefix.startswith("/") or any(ord(c) < 32 or ord(c) >= 127 for c in encoded)
                        or len(key) + len(encoded) > 2048):
                    continue
                if item["max-age"] == "0":
                    self._cookies.pop(key, None)
                elif len(self._cookies) < 16 or key in self._cookies:
                    self._cookies[key] = (encoded, prefix)
            if sum(len(k) + len(v[0]) for k, v in self._cookies.items()) > 4096:
                self._cookies.clear()
