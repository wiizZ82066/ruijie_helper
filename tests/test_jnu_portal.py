"""Synthetic portal messages only: no live requests, real accounts or sessions."""
import json
import threading
import unittest
from unittest.mock import Mock
from urllib.parse import parse_qs, unquote, urlsplit

from utils.credential_store import Credentials
from utils.interface_http import Response
from utils import jnu_portal as portal


QUERY = "wlanuserip=synthetic-ip&nenabled=1&wlanacname=synthetic-ac&ssid=synthetic-ssid&mac=synthetic-mac&t=wireless-v2&url=https%3A%2F%2Fexample.invalid%2F"
LANDING = portal.ORIGIN + "/eportal/index.jsp?" + QUERY
SECRET = Credentials("synthetic-user+name@example.invalid", "Synthetic +%&密码")
ONLINE_INDEX = "synthetic-current-session"


def result(value, status=200):
    return Response(status, {}, json.dumps(value).encode("utf-8"))


def redirect(location=LANDING):
    return Response(302, {"location": location}, b"")


def available():
    return Response(200, {}, portal.EXPECTED)


class FakeHTTP:
    def __init__(self, responses, hooks=None):
        self.responses = list(responses)
        self.calls = []
        self.hooks = hooks or {}

    def request(self, method, url, body=None, headers=None):
        self.calls.append((method, url, body, headers))
        index = len(self.calls) - 1
        if index in self.hooks:
            self.hooks[index]()
        if not self.responses:
            raise AssertionError("Unexpected extra request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def login_responses(*, page=None, services=None, login=None, online=None, probe=None):
    online_value = online if online is not None else {"result": "success", "userIndex": ONLINE_INDEX}
    confirmed = online_value.get("result") == "success" and online_value.get("userIndex") == ONLINE_INDEX
    return [redirect(),
            result(page if page is not None else {"passwordEncrypt": "false", "validCodeUrl": "", "prefixName": "false"}),
            result(services if services is not None else {"isService": "false"}),
            result(login if login is not None else {"result": "success", "userIndex": ONLINE_INDEX})] + [
            result(online_value) for _ in range(1 if confirmed else 3)] + [
            probe if probe is not None else available()]


def raw_fields(body):
    return dict(pair.split("=", 1) for pair in body.decode("ascii").split("&"))


class ContextTests(unittest.TestCase):
    def test_redirect_and_observed_script_extract_same_context(self):
        expected = (QUERY, "synthetic-mac")
        self.assertEqual(portal.portal_context(redirect()), expected)
        body = ("<script>top.self.location.href='" + LANDING.replace("&", "&amp;") + "'</script>").encode("ascii")
        self.assertEqual(portal.portal_context(Response(200, {}, body)), expected)

    def test_reject_untrusted_origins_schemes_paths_duplicates_and_injection(self):
        for target in (LANDING.replace("https://", "http://"),
                       LANDING.replace("webauthsa.jnu.edu.cn", "webauthsa.jnu.edu.cn.evil.invalid"),
                       LANDING.replace(":8443", ":8443@evil.invalid"),
                       LANDING.replace("https://", "https://" + "user:secret" + "@"),
                       LANDING.replace(":8443", ""), LANDING + "#fragment",
                       LANDING.replace("index.jsp", "other.jsp"), LANDING + "&mac=other",
                       LANDING.replace("mac=synthetic-mac", "mac="), LANDING + "\r\nprivate:secret",
                       "https://webauthsa.jnu.edu.cn:8443/eportal/index.jsp?invalid",
                       LANDING.replace("wlanuserip=synthetic-ip&", "")):
            with self.subTest(target=target):
                with self.assertRaises(portal.PortalError) as caught: portal.portal_context(redirect(target))
                self.assertNotIn("secret", str(caught.exception))
                self.assertNotIn("synthetic", str(caught.exception))

    def test_zero_or_multiple_script_redirects_rejected(self):
        for body in (b"no login here", ("location='" + LANDING + "';location='" + LANDING + "'").encode("ascii")):
            with self.assertRaises(portal.PortalError): portal.portal_context(Response(200, {}, body))


class PortalFlowTests(unittest.TestCase):
    def setup_client(self, responses=None, hooks=None):
        self.cancel = threading.Event()
        self.cancel.wait = Mock(side_effect=lambda _: self.cancel.is_set())
        self.associated = True
        self.logs = []
        self.http = FakeHTTP(login_responses() if responses is None else responses, hooks)
        self.client = portal.PortalClient(self.http, self.cancel, lambda: self.associated)
        return self.client

    def connect(self):
        return self.client.connect(SECRET, self.logs.append)

    def assert_no_login(self):
        self.assertFalse(any(urlsplit(call[1]).query.startswith("method=login") for call in self.http.calls))

    def test_observed_request_encoding_and_unencrypted_flag(self):
        self.setup_client()
        outcome = self.connect()
        self.assertTrue(outcome["authenticated"])
        self.assertTrue(outcome["ready"])
        self.assertEqual(len(self.http.calls), 6)
        first, page, services, login, online, last = self.http.calls
        self.assertEqual((first[0], first[1], first[2]), ("GET", portal.PROBE, None))
        self.assertEqual((last[0], last[1], last[2]), ("GET", portal.PROBE, None))
        self.assertEqual(page[1], portal.ORIGIN + "/eportal/InterFace.do?method=pageInfo")
        self.assertEqual(parse_qs(page[2].decode())["queryString"], [QUERY])
        self.assertEqual(parse_qs(urlsplit(services[1]).query)["queryString"], [QUERY])
        self.assertEqual(services[2], b"")
        self.assertEqual(login[1], portal.ORIGIN + "/eportal/InterFace.do?method=login")
        fields = raw_fields(login[2])
        self.assertEqual(fields["userId"], "synthetic-user%252Bname%2540example.invalid")
        self.assertEqual(fields["password"], "Synthetic%2520%252B%2525%2526%25E5%25AF%2586%25E7%25A0%2581")
        # The observed page's hidden input has value='false'; pageInfo false
        # preserves it. An empty flag is rejected by the real portal.
        self.assertEqual(fields["passwordEncrypt"], "false")
        self.assertEqual(unquote(unquote(fields["queryString"])), QUERY)
        self.assertEqual(set(fields), {"userId", "password", "service", "queryString", "operatorPwd", "operatorUserId", "validcode", "passwordEncrypt"})
        for key in ("service", "operatorPwd", "operatorUserId", "validcode"):
            self.assertEqual(fields[key], "")
        self.assertEqual(parse_qs(online[2].decode())["userIndex"], [ONLINE_INDEX])

    def test_form_matches_encode_uri_component_including_reserved_characters(self):
        # Literal vector follows JavaScript encodeURIComponent, not quote_plus.
        body = portal._form({"x": "a b+&=%/?:;,@中文~!*'()"}, double=True)
        self.assertEqual(body, b"x=a%2520b%252B%2526%253D%2525%252F%253F%253A%253B%252C%2540%25E4%25B8%25AD%25E6%2596%2587~!*'()")

    def test_encryption_enabled_submits_encoded_ciphertext_and_true_flag(self):
        page = {"passwordEncrypt": "true", "validCodeUrl": "", "prefixName": "false",
                "publicKeyModulus": format((1 << 1024) - 109, "x"), "publicKeyExponent": "10001"}
        credentials = Credentials("synthetic-rsa-user", "SyntheticPassword9")
        self.setup_client(login_responses(page=page))
        self.client.connect(credentials, self.logs.append)
        login = self.http.calls[3]
        fields = raw_fields(login[2])
        self.assertEqual(fields["passwordEncrypt"], "true")
        self.assertEqual(unquote(unquote(fields["password"])),
                         portal._rsa_password(credentials.password, "synthetic-mac", page))
        self.assertNotIn(credentials.password.encode(), login[2])
        self.assertNotIn(credentials.password, "\n".join(self.logs))

    def test_credentials_not_sent_on_invalid_redirect(self):
        self.setup_client([redirect("http://evil.invalid/?private-secret")])
        with self.assertRaises(portal.PortalError): self.connect()
        self.assertEqual(len(self.http.calls), 1)
        self.assert_no_login()

    def test_captcha_services_prefix_and_unknown_encryption_stop_before_credentials(self):
        cases = [({"passwordEncrypt": "false", "validCodeUrl": "https://example.invalid/captcha"}, {"isService": "false"}),
                 ({"passwordEncrypt": "false", "prefixName": "true"}, {"isService": "false"}),
                 ({"passwordEncrypt": "false"}, {"isService": "true", "service": "synthetic-extra"}),
                 ({"passwordEncrypt": "false"}, {}),
                 ({"passwordEncrypt": False}, {"isService": "false"}),
                 ({}, {"isService": "false"})]
        for page, services in cases:
            with self.subTest(page=page, services=services):
                self.setup_client(login_responses(page=page, services=services))
                with self.assertRaises(portal.PortalError): self.connect()
                self.assert_no_login()
                self.assertLessEqual(len(self.http.calls), 3)
                for call in self.http.calls:
                    self.assertNotIn(SECRET.username, call[1])
                    self.assertNotIn(SECRET.password.encode(), call[2] or b"")

    def test_each_connection_uses_its_own_bound_probe_context(self):
        self.setup_client()
        self.connect()
        current_context = "current-second-mac"
        other = login_responses()
        other[0] = redirect(LANDING.replace("synthetic-mac", current_context))
        self.setup_client(other)
        self.connect()
        fields = raw_fields(self.http.calls[3][2])
        query = unquote(unquote(fields["queryString"]))
        self.assertIn(current_context, query)
        self.assertNotIn("synthetic-mac", query)

    def test_login_online_and_bound_probe_are_distinct_evidence(self):
        cases = [({"result": "success", "userIndex": ONLINE_INDEX}, available(), True, True),
                 ({"result": "success", "userIndex": ONLINE_INDEX}, redirect(), True, False),
                 ({"result": "fail"}, available(), False, True),
                 ({"result": "fail"}, redirect(), False, False),
                 ({"result": "success", "userIndex": ""}, available(), False, True),
                 ({"result": "success", "userIndex": "synthetic-other-session"}, available(), False, True)]
        for online, probe, authenticated, ready in cases:
            with self.subTest(online=online, ready=ready):
                self.setup_client(login_responses(online=online, probe=probe))
                result_value = self.connect()
                self.assertEqual(result_value["authenticated"], authenticated)
                self.assertEqual(result_value["ready"], ready)
                self.assertEqual(result_value["connection_kind"], "wireless")

    def test_existing_internet_does_not_submit_credentials_or_assume_authentication(self):
        for online, expected in (({"result": "success", "userIndex": ONLINE_INDEX}, True), ({"result": "fail"}, False)):
            attempts = 1 if expected else 3
            self.setup_client([available()] + [result(online) for _ in range(attempts)])
            outcome = self.connect()
            self.assertEqual(outcome["authenticated"], expected)
            self.assertTrue(outcome["ready"])
            self.assertEqual(len(self.http.calls), 1 + attempts)
            self.assertEqual(self.cancel.wait.call_count, attempts - 1)
            self.assert_no_login()
            self.assertEqual(self.http.calls[1][2], b"userIndex=")
            self.assertEqual(self.client.session_index, ONLINE_INDEX if expected else "")
            self.assertEqual(self.client.keepalive_seconds, 0)

    def test_existing_internet_retries_online_status_without_login(self):
        self.setup_client([available(), result({"result": "fail"}),
                           result({"result": "success", "userIndex": ONLINE_INDEX})])
        outcome = self.connect()
        self.assertTrue(outcome["authenticated"])
        self.assertTrue(outcome["ready"])
        self.assertEqual(self.client.session_index, ONLINE_INDEX)
        self.assertEqual(self.client.keepalive_seconds, 0)
        self.assertEqual(len(self.http.calls), 3)
        self.cancel.wait.assert_called_once_with(0.5)
        self.assert_no_login()
        self.assertTrue(all(call[2] == b"userIndex=" for call in self.http.calls[1:]))

    def test_existing_online_retry_wait_cancellation_stops_without_login(self):
        self.setup_client([available(), result({"result": "fail"})])
        self.cancel.wait.side_effect = lambda _: self.cancel.set()
        with self.assertRaises(portal.PortalError): self.connect()
        self.assertEqual(len(self.http.calls), 2)
        self.assert_no_login()

    def test_online_propagation_retries_status_only_then_succeeds(self):
        responses = login_responses()
        responses[4:4] = [result({"result": "fail"}), result({"result": "success", "userIndex": "old-synthetic-session"})]
        self.setup_client(responses)
        outcome = self.connect()
        self.assertTrue(outcome["authenticated"])
        methods = [parse_qs(urlsplit(call[1]).query).get("method", [""])[0] for call in self.http.calls]
        self.assertEqual(methods.count("login"), 1)
        self.assertEqual(methods.count("getOnlineUserInfo"), 3)
        self.assertEqual(self.cancel.wait.call_count, 2)
        self.cancel.wait.assert_called_with(0.5)
        self.assertEqual(self.client.session_index, ONLINE_INDEX)

    def test_unconfirmed_after_three_queries_remains_internet_ready(self):
        self.setup_client(login_responses(online={"result": "fail"}))
        outcome = self.connect()
        self.assertFalse(outcome["authenticated"])
        self.assertTrue(outcome["ready"])
        methods = [parse_qs(urlsplit(call[1]).query).get("method", [""])[0] for call in self.http.calls]
        self.assertEqual(methods.count("login"), 1)
        self.assertEqual(methods.count("getOnlineUserInfo"), 3)
        self.assertEqual(self.cancel.wait.call_count, 2)
        self.assertEqual(self.client.session_index, ONLINE_INDEX)
        self.assertNotIn(ONLINE_INDEX, repr(outcome))
        self.assertNotIn(ONLINE_INDEX, repr(self.client))

    def test_cancel_or_ssid_change_during_retry_wait_stops_before_next_query(self):
        for cancelled in (True, False):
            self.setup_client(login_responses(online={"result": "fail"}))
            def change(_):
                if cancelled:
                    self.cancel.set()
                else:
                    self.associated = False
                return cancelled
            self.cancel.wait.side_effect = change
            with self.assertRaises(portal.PortalError): self.connect()
            self.assertEqual(len(self.http.calls), 5)
            self.assertEqual(self.cancel.wait.call_count, 1)

    def test_keepalive_interval_comes_only_from_login_in_minutes(self):
        self.setup_client(login_responses(login={"result": "success", "userIndex": ONLINE_INDEX, "keepaliveInterval": "2.5"},
                                         online={"result": "success", "userIndex": ONLINE_INDEX, "keepaliveInterval": None}))
        outcome = self.connect()
        self.assertEqual(self.client.keepalive_seconds, 150.0)
        self.assertEqual(self.client.session_index, ONLINE_INDEX)
        self.assertNotIn("keepaliveInterval", outcome)
        # A fresh existing-online check records the current token but does not
        # infer a keepalive schedule from this different endpoint.
        self.http.responses = [available(), result({"result": "success", "userIndex": ONLINE_INDEX, "keepaliveInterval": "5"})]
        self.connect()
        self.assertEqual(self.client.keepalive_seconds, 0)
        self.assertEqual(self.client.session_index, ONLINE_INDEX)

    def test_keepalive_interval_is_finite_positive_and_capped(self):
        for value in (None, "", 0, -1, "nan", "inf", float("-inf"), True, False, {}, [], "private-secret", 10**1000):
            self.assertEqual(portal.PortalClient._keepalive_interval(value), 0)
        for value, expected in ((1, 60), ("0.5", 30), (1440, 86400), (1441, 86400), (1e100, 86400)):
            self.assertEqual(portal.PortalClient._keepalive_interval(value), expected)

    def test_keepalive_uses_current_token_single_encoding_and_never_credentials(self):
        self.setup_client([result({"result": "success"})])
        self.client.session_index = "synthetic+session%&token"
        self.client.keepalive_seconds = 120
        self.assertTrue(self.client.keepalive())
        self.assertEqual(len(self.http.calls), 1)
        method, url, body, headers = self.http.calls[0]
        self.assertEqual(method, "POST")
        self.assertEqual(url, portal.ORIGIN + "/eportal/InterFace.do?method=keepalive")
        self.assertEqual(body, b"userIndex=synthetic%2Bsession%25%26token")
        self.assertEqual(parse_qs(body.decode())["userIndex"], [self.client.session_index])
        self.assertNotIn("password", body.decode())
        self.assertNotIn(self.client.session_index, repr(self.client))

    def test_keepalive_empty_json_failure_and_malformed_responses(self):
        for response, expected in ((Response(200, {}, b""), True), (Response(204, {}, b""), True),
                                   (Response(200, {}, b" \n"), True), (result({"result": "success"}), True),
                                   (result({"result": "fail", "message": "private-secret"}), False),
                                   (result({}), False)):
            self.setup_client([response])
            self.client.session_index = ONLINE_INDEX
            self.assertEqual(self.client.keepalive(), expected)
        for response in (Response(200, {}, b"private-secret"), Response(500, {}, b"private-secret")):
            self.setup_client([response])
            self.client.session_index = ONLINE_INDEX
            with self.assertRaises(portal.PortalError) as caught: self.client.keepalive()
            self.assertNotIn("private-secret", str(caught.exception))

    def test_keepalive_no_session_or_changed_association_never_sends(self):
        self.setup_client([])
        self.assertFalse(self.client.keepalive())
        self.assertEqual(self.http.calls, [])
        self.client.session_index = ONLINE_INDEX
        self.associated = False
        with self.assertRaises(portal.PortalError): self.client.keepalive()
        self.assertEqual(self.http.calls, [])

    def test_keepalive_checks_changes_after_response(self):
        for cancelled in (True, False):
            self.setup_client([Response(200, {}, b"")])
            self.client.session_index = ONLINE_INDEX
            self.http.hooks[0] = self.cancel.set if cancelled else lambda: setattr(self, "associated", False)
            with self.assertRaises(portal.PortalError): self.client.keepalive()
            self.assertEqual(len(self.http.calls), 1)

    def test_server_failures_and_json_errors_do_not_echo_secrets(self):
        malicious = SECRET.username + " " + SECRET.password + " " + QUERY
        cases = [login_responses(login={"result": "fail", "message": malicious}),
                 [redirect(), Response(200, {}, malicious.encode())],
                 [redirect(), result([malicious])],
                 [redirect(), Response(500, {}, malicious.encode())],
                 login_responses(login={"result": "success", "userIndex": {"private": malicious}})]
        for responses in cases:
            self.setup_client(responses)
            with self.assertRaises(portal.PortalError) as caught: self.connect()
            visible = str(caught.exception) + repr(caught.exception) + "\n".join(self.logs) + repr(self.client)
            for value in (SECRET.username, SECRET.password, QUERY, ONLINE_INDEX):
                self.assertNotIn(value, visible)

    def test_credentials_length_guard_before_login(self):
        for credentials in (object(), Credentials("x" * 257, "synthetic"), Credentials("synthetic", "x" * 150)):
            self.setup_client()
            with self.assertRaises(portal.PortalError): self.client.connect(credentials)
            self.assert_no_login()

    def test_cancellation_and_ssid_change_before_every_step(self):
        for cancelled in (True, False):
            for request_index in range(6):
                self.setup_client()
                self.http.hooks[request_index] = self.cancel.set if cancelled else lambda: setattr(self, "associated", False)
                with self.subTest(cancelled=cancelled, request_index=request_index):
                    with self.assertRaises(portal.PortalError): self.connect()
                    self.assertEqual(len(self.http.calls), request_index + 1)
        self.setup_client()
        self.cancel.set()
        with self.assertRaises(portal.PortalError): self.connect()
        self.assertEqual(self.http.calls, [])

    def test_change_during_existing_online_check_cannot_return_success(self):
        for cancelled in (True, False):
            self.setup_client([available(), result({"result": "success", "userIndex": ONLINE_INDEX})])
            self.http.hooks[1] = self.cancel.set if cancelled else lambda: setattr(self, "associated", False)
            with self.assertRaises(portal.PortalError): self.connect()


class RSATests(unittest.TestCase):
    def test_short_known_arithmetic_vector_reversal_endianness_and_digit_padding(self):
        page = {"publicKeyModulus": format((1 << 1024) - 109, "x"), "publicKeyExponent": "3"}
        # Reverse A>B -> B>A. Little-endian is 0x413e42. Its cube is less than
        # the synthetic modulus; independent integer multiplication gives this.
        self.assertEqual(portal._rsa_password("A", "B", page), "00043cd709e77f854b08")

    def test_multiblock_known_vector_from_independent_pycryptodome_public_operation(self):
        page = {"publicKeyModulus": format((1 << 1024) - 109, "x"), "publicKeyExponent": "10001"}
        # Fixed synthetic vector independently calculated using Crypto RSA's
        # public operation, 126-byte blocks and sum(byte * 256**offset).
        expected = ("ee205ab367336631b0ec0d4094fb0865152629b58723d9e6a99b786129f0f7ed9f125f0971eee50c2d94ccd5d8be23c05bc4d2df618f86efec24ebd42b6e572841ddbf4a0b6344bc1370aee4b0dce34e2bb0901609a9cc0a91b72bb19c7471d823f55c2e93c98c9ad1ea0b7f19cd6163010811a56990da56888a91c227c26c90 "
                    "ec8479e0053d29e452c8350cfd075a67b7a06cf441e320c069b83e3da9b6e5d09514cac1c3ab37e61610341ff28ed6b453cf7b39d2bf18be6caa628166f3ca499e402446a1ab6251e143d7f68c7cd91b74e23e90ad5beed042a54c1795982fb8b44760d1018ec353a0d5e695cb6214bcce098b7189a3473aade637f6ad178b6b")
        self.assertEqual(portal._rsa_password("S" * 140, "02:11:22:33:44:55", page), expected)

    def test_unsupported_keys_and_non_ascii_fail_without_echo(self):
        good = {"publicKeyModulus": format((1 << 1024) - 109, "x"), "publicKeyExponent": "10001"}
        cases = [("synthetic", {}), ("synthetic", dict(good, publicKeyExponent="1")),
                 ("synthetic", dict(good, publicKeyModulus="ff")),
                 ("synthetic", dict(good, publicKeyModulus="g" * 256)),
                 ("synthetic", dict(good, publicKeyModulus=format((1 << 1024) - 110, "x"))),
                 ("private密码", good)]
        for password, page in cases:
            with self.assertRaises(portal.PortalError) as caught: portal._rsa_password(password, "synthetic-mac", page)
            self.assertNotIn(password, str(caught.exception))
            self.assertNotIn("synthetic-mac", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
