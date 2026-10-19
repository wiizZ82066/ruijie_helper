"""JNU's observed ePortal flow. Credentials and session context stay in memory.

This is separate from wired 802.1X. Never infer authentication from a global
Internet check, execute portal JavaScript, or reuse another interface's redirect.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import html
import json
import math
import re
from urllib.parse import parse_qs, quote, urlsplit

from utils.credential_store import Credentials

ORIGIN = "https://webauthsa.jnu.edu.cn:8443"
PROBE = "http://www.msftconnecttest.com/connecttest.txt"
EXPECTED = b"Microsoft Connect Test"
_SAFE = "~!*'()"


class PortalError(RuntimeError):
    """Deliberately contains no server-controlled credential/session text."""


def _encode(value):
    return quote(value, safe=_SAFE)


def _form(values, *, double=False):
    return "&".join(k + "=" + (_encode(_encode(v)) if double else _encode(v))
                    for k, v in values.items()).encode("ascii")


def _json(response):
    if response.status != 200 or len(response.body) > 1024 * 1024:
        raise PortalError("JNU 认证服务器未返回有效结果，请稍后再试。")
    try:
        value = json.loads(response.body)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, UnicodeError):
        raise PortalError("JNU 认证接口格式已变化，请使用学校登录页面。") from None


def portal_context(response):
    """Accept only the exact school HTTPS origin and this interface's redirect."""
    candidates = []
    if response.status in (301, 302, 303, 307, 308):
        candidates.append(response.headers.get("location", ""))
    elif response.status == 200:
        text = response.body.decode("ascii", errors="replace")
        # Observed JNU response: <script>top.self.location.href='...'</script>.
        candidates.extend(re.findall(
            r"(?:top\.self\.|top\.|window\.)?location(?:\.href)?\s*=\s*['\"]([^'\"\r\n]+)['\"]", text))
    if len(candidates) != 1:
        raise PortalError("未取得 JNU 登录入口，请确认已连接 JNU 无线网络。")
    url = html.unescape(candidates[0])
    try:
        u = urlsplit(url)
        if (len(url) > 16384 or u.scheme != "https" or u.netloc != "webauthsa.jnu.edu.cn:8443"
                or u.path != "/eportal/index.jsp" or u.fragment or u.username or u.password
                or any(ord(c) < 33 or ord(c) > 126 for c in url)):
            raise ValueError()
        fields = parse_qs(u.query, keep_blank_values=True, strict_parsing=True, max_num_fields=32)
        if any(len(v) != 1 for v in fields.values()):
            raise ValueError()
        if any(not fields.get(k, [""])[0] for k in ("wlanuserip", "wlanacname", "ssid", "mac")):
            raise ValueError()
        return u.query, fields["mac"][0]
    except ValueError:
        raise PortalError("无线登录入口不符合 JNU 的已验证地址，已停止提交账号。") from None


def _rsa_password(password, mac, page):
    """Match security.js's reversed ASCII, zero-filled, little-endian blocks.

    This legacy protocol is not a recommendation for new cryptography. TLS
    certificate verification remains mandatory even with this extra encoding.
    """
    try:
        modulus, exponent = page["publicKeyModulus"], page["publicKeyExponent"]
        if (not isinstance(modulus, str) or not re.fullmatch(r"[0-9a-fA-F]{256,1024}", modulus)
                or not isinstance(exponent, str) or not re.fullmatch(r"[0-9a-fA-F]{1,8}", exponent)):
            raise ValueError()
        n, e = int(modulus, 16), int(exponent, 16)
        if not 1024 <= n.bit_length() <= 4096 or e not in (3, 65537) or n % 2 == 0:
            raise ValueError()
        data = (password + ">" + mac)[::-1].encode("ascii")
        chunk = 2 * ((n.bit_length() - 1) // 16)
        data += b"\0" * (-len(data) % chunk)
        result = []
        for i in range(0, len(data), chunk):
            value = pow(int.from_bytes(data[i:i+chunk], "little"), e, n)
            digits = max(4, ((value.bit_length() + 15) // 16) * 4)
            result.append(format(value, f"0{digits}x"))
        return " ".join(result)
    except (KeyError, ValueError, TypeError, UnicodeError):
        raise PortalError("该登录页的密码加密参数暂不支持，请使用学校登录页面。") from None


@dataclass
class PortalClient:
    http: object = field(repr=False)
    cancel: object = field(repr=False)
    check_association: object = field(repr=False)
    session_index: str = field(default="", init=False, repr=False)
    keepalive_seconds: float = field(default=0.0, init=False, repr=False)

    def _check(self):
        if self.cancel.is_set():
            raise PortalError("已取消无线连接。")
        if not self.check_association():
            raise PortalError("无线网络已切换，已停止本次 JNU 认证。")

    def _api(self, method, values, *, double=False):
        self._check()
        response = self.http.request("POST", ORIGIN + "/eportal/InterFace.do?method=" + method,
                     body=_form(values, double=double),
                     headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
        self._check()
        return _json(response)

    def _online(self, index=""):
        online = self._api("getOnlineUserInfo", {"userIndex": index})
        value = online.get("userIndex")
        confirmed = (online.get("result") == "success" and isinstance(value, str) and
                     0 < len(value) <= 4096 and (not index or value == index))
        if confirmed:
            self.session_index = value
        return confirmed

    def _confirm_online(self, index=""):
        # The read-only endpoint can briefly lag behind both a new login and an
        # existing working connection. Never resubmit credentials to resolve it.
        for attempt in range(3):
            if attempt:
                self.cancel.wait(0.5)
                self._check()
            if self._online(index):
                return True
        return False

    @staticmethod
    def _keepalive_interval(value):
        # The login response specifies minutes. An online-info response often
        # omits this field and must not invent or overwrite the login interval.
        try:
            if isinstance(value, bool):
                return 0.0
            minutes = float(value)
            if not math.isfinite(minutes) or minutes <= 0:
                return 0.0
            return min(minutes, 1440.0) * 60.0
        except (TypeError, ValueError, OverflowError):
            return 0.0

    def keepalive(self):
        """Send one heartbeat for this in-memory session; never starts a timer.

        True confirms only that the endpoint accepted this request. It is not
        evidence of authentication or Internet access. Scheduling is the caller's
        responsibility and requires a positive ``keepalive_seconds`` value.
        """
        self._check()
        if not self.session_index:
            return False
        response = self.http.request("POST", ORIGIN + "/eportal/InterFace.do?method=keepalive",
                    body=_form({"userIndex": self.session_index}),
                    headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
        self._check()
        if response.status in (200, 204) and not response.body.strip():
            return True
        return _json(response).get("result") == "success"

    def connect(self, credentials: Credentials, log=lambda _: None):
        self.session_index = ""
        self.keepalive_seconds = 0.0
        self._check()
        probe = self.http.request("GET", PROBE)
        self._check()
        if probe.status == 200 and probe.body.strip() == EXPECTED:
            confirmed = self._confirm_online()
            return {"authenticated": confirmed, "ready": True, "connection_kind": "wireless",
                    "message": "JNU 无线网络已连接" if confirmed else "JNU 无线网络已可上网，认证状态未确认"}
        query, mac = portal_context(probe)
        log("正在读取 JNU 登录设置…")
        page = self._api("pageInfo", {"queryString": query})
        # getServices puts its once-encoded context in the URL, unlike login.
        self._check()
        services = _json(self.http.request("POST", ORIGIN + "/eportal/InterFace.do?method=getServices&queryString=" + _encode(query),
                        body=b"", headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}))
        self._check()
        if page.get("validCodeUrl"):
            raise PortalError("学校要求输入验证码，请先在学校登录页面完成验证。")
        if page.get("prefixName") == "true" or services.get("isService") != "false":
            raise PortalError("该账号入口需要选择额外服务，请先使用学校登录页面。")
        if not isinstance(credentials, Credentials):
            raise PortalError("请输入校园账号和密码。")
        if len(credentials.username) > 256 or len(credentials.password) >= 150:
            raise PortalError("账号或密码长度超出该校园登录页的支持范围。")
        flag = page.get("passwordEncrypt")
        if flag not in ("true", "false"):
            raise PortalError("未能确认登录页的密码提交方式，已停止认证。")
        password = (_rsa_password(credentials.password, mac, page) if flag == "true" else credentials.password)
        log("正在通过 JNU 安全登录接口认证…")
        result = self._api("login", {"userId": credentials.username, "password": password,
            "service": "", "queryString": query, "operatorPwd": "", "operatorUserId": "",
            # The actual landing page's hidden input defaults to literal false.
            "validcode": "", "passwordEncrypt": flag}, double=True)
        if result.get("result") != "success":
            # No raw server text: it can echo account, password or session IDs.
            raise PortalError("JNU 未接受本次登录，请检查账号密码或在学校页面查看原因。")
        index = result.get("userIndex", "")
        if not isinstance(index, str) or len(index) > 4096:
            raise PortalError("认证服务器返回的会话格式无效。")
        self.session_index = index
        self.keepalive_seconds = self._keepalive_interval(result.get("keepaliveInterval"))
        confirmed = self._confirm_online(index)
        self._check()
        probe = self.http.request("GET", PROBE)
        self._check()
        ready = probe.status == 200 and probe.body.strip() == EXPECTED
        return {"authenticated": confirmed, "ready": ready, "connection_kind": "wireless",
                "message": "已连接 JNU 无线校园网" if confirmed and ready else
                "JNU 认证成功，网络连通性仍待确认" if confirmed else "JNU 已接受登录，在线状态仍待确认"}
