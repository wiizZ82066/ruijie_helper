"""Track one verified compatibility session and its physical Ethernet exit."""
import threading
import time

from utils import wired_network as network
from utils.auth_runtime import _running_core
from utils.interface_http import InterfaceHTTP, InterfaceHTTPError
from utils.wired_native_handoff import NativeHandoff
from utils.connection_events import DiagnosticMessage


class NativeSessionMonitor:
    def __init__(self, directory, session, guid, log=lambda _: None):
        self.directory, self.session, self.guid = directory, session, guid
        self.log = log
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._next_probe = 0
        self._failures = 0
        self.state = dict(connection_kind='wired', backend='native', active=True,
                          authenticated=False, ready=False, retryable=False,
                          message='正在确认兼容认证结果…')

    def verify(self, cancel=None):
        with self._lock:
            reason = 'online'
            online = False
            try:
                if not network.link_up(self.guid):
                    reason = 'link_down'
                elif _running_core(self.directory / '8021x.exe') != self.session:
                    reason = 'native_session_ended'
                else:
                    cfg = network.config(self.guid)
                    if not network.has_lease(cfg):
                        reason = 'lease_missing'
                    else:
                        response = InterfaceHTTP(cfg['index'], cfg['addresses'][0], cfg['dns'],
                                                 cancel or self._stop).request(
                            'GET', 'http://www.msftconnecttest.com/connecttest.txt')
                        online = response.status == 200 and response.body.strip() == b'Microsoft Connect Test'
                        reason = 'online' if online else 'unexpected_response'
            except InterfaceHTTPError as error:
                reason = error.kind
            except Exception as error:
                reason = type(error).__name__
            if self._stop.is_set() or cancel is not None and cancel.is_set():
                online, reason = False, 'cancelled'
            self._failures = 0 if online else self._failures + 1
            retryable = not online and reason != 'cancelled'
            self.state.update(authenticated=online, ready=online, retryable=retryable,
                reason=reason, message='已连接校园网 · 兼容认证' if online else '兼容认证出口不可用，等待重新连接…')
            self._next_probe = time.monotonic() + (30 if online else 5)
            self.log(DiagnosticMessage('native_internet_probe', self.state['message'],
                ready=online, reason=reason, retryable=retryable))
            return dict(self.state)

    def snapshot(self):
        with self._lock:
            if self._stop.is_set():
                return dict(self.state)
            # Link/process loss is immediate; costly exit probes are throttled.
            try:
                intact = network.link_up(self.guid) and _running_core(self.directory / '8021x.exe') == self.session
            except Exception:
                intact = False
            if not intact:
                self.state.update(ready=False, authenticated=False, retryable=True,
                                  message='兼容认证连接已断开，等待重新连接…')
            elif time.monotonic() >= self._next_probe:
                previous_ready = self.state['ready']
                self.verify()
                # A single HTTP timeout should not restart a healthy core.
                if previous_ready and self._failures == 1:
                    self.state['retryable'] = False
            return dict(self.state)

    def close(self):
        self._stop.set()
        with self._lock:
            if _running_core(self.directory / '8021x.exe') == self.session:
                NativeHandoff(restart_on_failure=False).pause()
            self.state.update(active=False, ready=False, authenticated=False, retryable=False,
                              message='已断开校园网')
