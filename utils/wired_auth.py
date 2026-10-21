"""Independent wired session lifecycle. One worker exclusively owns its pcap handle."""
import threading
import time
from utils import wired_network as network
from utils.wired_eapol import State, EthernetEapol, PAE_GROUP
from utils.wired_session import MinimalVendorSession
from utils.wired_transport import Pcap, ProbeError
from utils.wired_native_handoff import NativeHandoff, native_absent
from utils.interface_http import InterfaceHTTP, InterfaceHTTPError
from utils.connection_events import ProgressMessage, DiagnosticMessage


class RecoverableError(RuntimeError):
    """A link/lease interruption; credentials have not been rejected."""


class WiredClient:
    def __init__(self, guid, service='internet'):
        self.guid, self.service = guid, service
        self._stop=threading.Event()
        self._initial=threading.Event()
        self._lock=threading.Lock()
        self._thread=None
        self._error=None
        self._log=lambda _: None
        self._probe_reason='not_checked'
        self._auth_round=0
        self._status={'connection_kind':'wired','authenticated':False,'ready':False,
                      'active':False,'retryable':False,'message':'尚未连接校园网'}

    def snapshot(self):
        with self._lock:
            return dict(self._status)

    def _set(self, **values):
        with self._lock:
            changed=any(self._status.get(k)!=v for k,v in values.items())
            self._status.update(values)
            state=dict(self._status)
        if changed:
            self._log(DiagnosticMessage('session_state',state['message'],
                **{k:state.get(k) for k in ('authenticated','ready','active','retryable')}))

    def connect(self, credentials, cancel, log=lambda _:None):
        if self._thread is not None:
            raise RuntimeError('认证会话已启动。')
        self._thread=threading.Thread(target=self._run,args=(credentials,log),name='campus-wired',daemon=True)
        self._thread.start()
        while not self._initial.wait(.1):
            if cancel.is_set():
                self._stop.set()
        if cancel.is_set():
            self.close()
            return {'connection_kind':'wired','authenticated':False,'ready':False,'active':False,'message':'已取消连接'}
        if self._error:
            raise RuntimeError(self._error)
        return self.snapshot()

    def close(self):
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(50)
            if self._thread.is_alive():
                raise RuntimeError('正在等待网络操作结束，请稍后重试。')

    def _check(self):
        if self._stop.is_set():
            raise InterruptedError()
        if not native_absent():
            raise RuntimeError('检测到其他认证客户端启动，独立认证已停止。')
        if not network.link_up(self.guid):
            raise RecoverableError('有线连接已断开，等待网络恢复…')

    def _configuration(self, original):
        current=network.config(self.guid)
        network.same_interface(original,current)
        self._describe_config(current)
        return current

    def _describe_config(self, cfg):
        self._log(DiagnosticMessage('adapter_config','已读取所选有线网卡配置',
            dhcp=cfg['dhcp']=='Enabled',address_count=len(cfg['addresses']),
            gateway_count=len(cfg['gateways']),dns_count=len(cfg['dns']),lease=network.has_lease(cfg)))

    def _internet(self,cfg):
        began=time.monotonic()
        http_status=0
        if not network.has_lease(cfg):
            self._probe_reason='lease_missing'
            self._log(DiagnosticMessage('internet_probe','缺少完整网络地址，跳过出口检测',reason=self._probe_reason))
            return False
        try:
            result=InterfaceHTTP(cfg['index'],cfg['addresses'][0],cfg['dns'],self._stop).request(
                'GET','http://www.msftconnecttest.com/connecttest.txt')
            http_status=result.status
            online=result.status==200 and result.body.strip()==b'Microsoft Connect Test'
            self._probe_reason='online' if online else 'unexpected_response'
            return online
        except InterfaceHTTPError as error:
            self._probe_reason=error.kind
            return False
        except Exception:
            self._probe_reason='probe_error'
            return False
        finally:
            self._log(DiagnosticMessage('internet_probe','有线出口检测：'+self._probe_reason,
                reason=self._probe_reason,http_status=http_status,duration_ms=round((time.monotonic()-began)*1000)))

    def _authenticate(self, capture, cfg, credentials, *, initial=False, request=None, seed=bytes(16)):
        began=time.monotonic()
        self._auth_round+=1
        self._log(DiagnosticMessage('eap_start','开始有线认证交互',attempt=self._auth_round,initial=initial))
        session=MinimalVendorSession(cfg,credentials.username,credentials.password.encode('ascii'),self.service,
            initial_dhcp_phase=initial,timeout=30,max_start_attempts=3,max_requests=32)
        session.seed=seed
        try:
            start=session.start(time.monotonic())
            if request is None:
                capture.send(start.frame)
            else:
                action=session.receive(request,time.monotonic())
                if action.kind=='send': capture.send(action.frame)
            next_check=0
            packets=0
            while session.state in session._active:
                if self._stop.is_set(): raise InterruptedError()
                if time.monotonic()>=next_check:
                    self._check(); next_check=time.monotonic()+2
                raw=capture.receive()
                if raw is not None:
                    packets+=1
                    if packets>512: raise RuntimeError('认证报文过多，请稍后重试。')
                    # Our own outgoing extensions are outside the receive codec.
                    if raw[6:12]==cfg['mac_bytes']: continue
                    action=session.receive(raw,time.monotonic())
                else:
                    action=session.tick(time.monotonic())
                    self._stop.wait(.02)
                if action.kind=='send': capture.send(action.frame)
            if session.state is not State.AUTHENTICATED:
                if session.state is State.FAILED:
                    raise RuntimeError('账号认证未通过，请检查账号和密码。')
                raise RecoverableError('校园网认证超时，等待重试…')
            if session.success is None or session.success.hello_enabled:
                raise RuntimeError('该网络需要尚未支持的保活方式，请在设置中选择兼容认证。')
            self._log(DiagnosticMessage('eap_success','有线认证交互通过',attempt=self._auth_round,
                packets=packets,duration_ms=round((time.monotonic()-began)*1000)))
            return session
        except BaseException as error:
            self._log(DiagnosticMessage('eap_failed','有线认证交互结束',attempt=self._auth_round,
                error_type=type(error).__name__,duration_ms=round((time.monotonic()-began)*1000)))
            try:
                action=session.logoff()
                if action.kind=='send': capture.send(action.frame)
            except Exception:
                pass
            finally:
                session.cancel()
            raise

    def _run(self, credentials, log):
        self._log=log
        capture=session=None
        handoff=NativeHandoff(restart_on_failure=False)
        try:
            # Validate credentials and driver before pausing the existing client.
            if not credentials.username.isascii() or not credentials.password.isascii() or len(credentials.password)>240:
                raise RuntimeError('独立认证目前仅支持 ASCII 账号密码（密码不超过240字节），可选择兼容认证。')
            log(ProgressMessage('network','正在识别有线网卡…'))
            cfg=network.config(self.guid)
            self._describe_config(cfg)
            capture=Pcap(cfg)
            log(DiagnosticMessage('driver_ready','抓包驱动已打开'))
            self._check_cancel()
            log(ProgressMessage('prepare','正在准备独立有线认证…'))
            handoff.pause()
            log(DiagnosticMessage('handoff_complete','已确认独立认证可使用有线网卡'))
            self._set(active=True,message='正在认证校园账号…')
            capture.send(EthernetEapol(PAE_GROUP,cfg['mac_bytes'],2).encode())
            # Drain the old session's outcome before assigning fresh identifiers.
            deadline=time.monotonic()+.5
            while time.monotonic()<deadline:
                self._check_cancel(); capture.receive(); self._stop.wait(.02)
            log(ProgressMessage('authenticate','正在认证校园账号…'))
            session=self._authenticate(capture,cfg,credentials,initial=cfg['dhcp']=='Enabled')
            log(ProgressMessage('address','认证通过，正在确认网络地址…'))
            if cfg['dhcp']=='Enabled':
                if not network.has_lease(cfg):
                    log(ProgressMessage('address','认证通过，正在获取网络地址…'))
                    current=self._wait_for_lease(cfg)
                else:
                    current=self._configuration(cfg)
                    if not network.has_lease(current):
                        current=self._wait_for_lease(cfg)
                seed=session.seed
                session.cancel()
                session=self._authenticate(capture,current,credentials,seed=seed)
                cfg=current
            self._check()
            log(ProgressMessage('verify','正在验证有线出口是否可上网…'))
            online=self._internet(cfg)
            if not online and cfg['dhcp']=='Enabled':
                # Repair a retained lease without modifying TUN or other adapters.
                log(ProgressMessage('address','网络未就绪，正在更新地址并重新认证（1/1）…'))
                current=self._wait_for_lease(cfg)
                action=session.logoff()
                if action.kind=='send': capture.send(action.frame)
                session.cancel()
                session=self._authenticate(capture,current,credentials)
                cfg=current
                log(ProgressMessage('verify','正在重新验证有线出口…'))
                online=self._internet(cfg)
            if not online:
                raise RecoverableError('有线出口无法上网（'+self._probe_reason+'），等待重新连接…')
            self._check_cancel()
            handoff.forget()
            self._set(authenticated=True,ready=online,active=True,
                message='已连接校园网 · 独立有线认证' if online else '校园账号已认证，网络尚未就绪')
            log(ProgressMessage('complete','已连接校园网 · 独立有线认证'))
            self._initial.set()
            log(DiagnosticMessage('monitor_start','开始监测链路和出口连通性'))
            next_link=0
            next_probe=time.monotonic()+30
            reauth=[]
            probe_failures=0
            while True:
                before_wait=time.monotonic()
                if self._stop.wait(.05): break
                if time.monotonic()-before_wait>15:
                    raise RecoverableError('系统已唤醒，正在恢复校园网…')
                now=time.monotonic()
                if now>=next_link:
                    self._check(); next_link=time.monotonic()+2
                raw=capture.receive()
                if raw and len(raw)>=23 and raw[:6]==cfg['mac_bytes'] and raw[6:12]==session.peer and raw[12:16]==b'\x88\x8e\x01\x00':
                    length=int.from_bytes(raw[16:18],'big')
                    if 18+length<=len(raw) and int.from_bytes(raw[20:22],'big')==length:
                        if raw[18]==4:
                            raise RecoverableError('校园网已结束当前会话，等待重新连接…')
                        if raw[18]==1 and length>=5 and raw[22] in (1,4):
                            reauth=[t for t in reauth if now-t<60]
                            if len(reauth)>=3:
                                raise RuntimeError('校园网频繁要求重新认证，请稍后手动连接。')
                            reauth.append(now)
                            self._set(ready=False,message='校园网正在重新认证…')
                            current=self._configuration(cfg)
                            session.cancel()
                            session=self._authenticate(capture,current,credentials,request=raw)
                            cfg=current; next_probe=0
                if now>=next_probe:
                    current=self._configuration(cfg)
                    # A changed lease needs explicit reauthentication, not a
                    # false online indication based on a new unrelated address.
                    if current['addresses']!=cfg['addresses']:
                        raise RecoverableError('有线网络地址已变化，正在重新连接…')
                    online=self._internet(current)
                    probe_failures=0 if online else probe_failures+1
                    self._set(ready=online,message='已连接校园网 · 独立有线认证' if online else '有线出口暂时不可用，正在复查…')
                    if probe_failures>=2:
                        raise RecoverableError('有线出口连续检测失败（'+self._probe_reason+'），等待重新连接…')
                    next_probe=time.monotonic()+(30 if online else 5)
        except InterruptedError:
            self._set(authenticated=False,ready=False,active=False,message='已断开校园网')
        except Exception as error:
            # Only our own curated errors may reach UI; ctypes/OS exceptions can
            # contain paths, addresses or supplied inputs.
            retryable = isinstance(error, (RecoverableError, network.NetworkUnavailable)) or (
                isinstance(error, ProbeError) and error.retryable)
            reason = error.kind if isinstance(error, ProbeError) else (
                'network_unavailable' if isinstance(error, network.NetworkUnavailable) else type(error).__name__)
            message = str(error) if type(error) in (RuntimeError, RecoverableError, network.NetworkUnavailable, ProbeError) else (
                '独立认证未完成，请检查驱动、网卡或选择兼容认证。')
            log(DiagnosticMessage('session_error', message, reason=reason,
                                  error_type=type(error).__name__, retryable=retryable))
            self._set(authenticated=False,ready=False,active=False,message=message,
                      retryable=retryable, reason=reason,
                      fallback_allowed=retryable or isinstance(error, ProbeError))
            log(message)
            if not self._initial.is_set(): self._error=message
        finally:
            if session is not None:
                try:
                    action=session.logoff()
                    if capture is not None and action.kind=='send': capture.send(action.frame)
                except Exception:
                    pass
                finally:
                    session.cancel()
            if capture is not None:
                try: capture.close()
                except Exception: pass
            handoff.forget()
            log(DiagnosticMessage('session_closed','认证会话资源已释放',cancelled=self._stop.is_set()))
            credentials=None
            self._set(active=False,authenticated=False,ready=False)
            if self._stop.is_set(): self._set(message='已断开校园网')
            self._initial.set()

    def _check_cancel(self):
        if self._stop.is_set(): raise InterruptedError()

    def _wait_for_lease(self, original):
        # DHCP and DNS may appear after EAP success. Renew only this interface;
        # bounded retries allow delayed boot services without changing routes.
        for attempt in range(3):
            self._check()
            began=time.monotonic()
            self._log(DiagnosticMessage('dhcp_renew_start','更新所选有线网卡地址',attempt=attempt+1))
            try:
                network.acquire_lease(self.guid)
                self._log(DiagnosticMessage('dhcp_renew_result','地址更新请求已完成',attempt=attempt+1,
                    outcome='requested',duration_ms=round((time.monotonic()-began)*1000)))
            except (RuntimeError, TimeoutError) as error:
                self._log(DiagnosticMessage('dhcp_renew_result','地址更新请求未完成，继续核验当前地址',
                    attempt=attempt+1,outcome='failed',error_type=type(error).__name__,
                    duration_ms=round((time.monotonic()-began)*1000)))
            self._check_cancel()
            current=self._configuration(original)
            if network.has_lease(current): return current
            if attempt < 2 and self._stop.wait(2*(attempt+1)):
                raise InterruptedError()
        raise RecoverableError('认证已通过，暂未取得网络地址，等待重试…')
