"""Campus EAP-MD5 session with true credentials and minimal vendor fields.

Does not claim to be 8021x.exe and omits unimplemented integrity properties.
The runtime owns DHCP, monitoring and explicit logoff. IP alone is not success.
"""
from dataclasses import replace
import ipaddress
from utils.wired_eapol import Md5Supplicant, EthernetEapol, EapPacket, ProtocolError, State
from utils.wired_vendor import network_prefix, password_field, extension, success_parameters


class MinimalVendorSession(Md5Supplicant):
    def __init__(self, config, username, password, service, *, initial_dhcp_phase=False, **kwargs):
        super().__init__(config['mac_bytes'], username, password, **kwargs)
        if not username.isascii() or not password.isascii():
            raise ValueError('独立认证目前仅支持 ASCII 账号密码，请选择兼容认证。')
        if len(password)>240:
            raise ValueError('密码长度超出独立认证支持范围。')
        if not initial_dhcp_phase and (len(config['addresses']) != 1 or len(config['prefixes']) != 1 or not config['dns'] or len(config['gateways']) != 1):
            raise ValueError('未取得明确的有线网络地址、网关或 DNS。')
        permanent = bytes.fromhex(config['permanentMac'].replace('-', '').replace(':', ''))
        if len(permanent) != 6 or permanent[0] & 1:
            raise ValueError('invalid permanent MAC')
        self._native_user = username.encode('ascii')
        self._vendor_password = bytearray(password)
        self.seed = bytes(16)
        self.config = dict(config)
        if initial_dhcp_phase:
            for key, fallback in [('addresses',['0.0.0.0']),('prefixes',[0]),('gateways',['0.0.0.0']),('dns',['0.0.0.0'])]:
                if not self.config.get(key):
                    self.config[key]=fallback
        self.permanent_mac = permanent
        self.service = service.encode('ascii')
        if not self.service or len(self.service)>32:
            raise ValueError('unsupported service length')
        self.success = None
        self.initial_dhcp_phase = initial_dhcp_phase
        self._decorated = {}

    def decorate(self, action):
        if action.kind != 'send':
            return action
        raw = action.frame
        # Preserve exact extension bytes for request retransmissions.
        if raw in self._decorated:
            return replace(action, frame=self._decorated[raw])
        length = int.from_bytes(raw[16:18], 'big')
        cfg = self.config
        mask = str(ipaddress.IPv4Network('0.0.0.0/'+str(cfg['prefixes'][0])).netmask)
        prefix = network_prefix(cfg['dhcp']=='Enabled', '0.0.0.0' if self.initial_dhcp_phase else cfg['addresses'][0], mask, cfg['gateways'][0], cfg['dns'][0])
        props = [(0x2d, self.permanent_mac),
                 (0x2f, password_field(self._native_user, bytes(self._vendor_password), self.seed)),
                 (0x39, self.service.ljust(32,b'\0')),
                 (0x76, ';'.join(cfg['dns'][1:]).encode('ascii'))]
        suffix = extension(prefix, b'CampusAuthenticator', b'\x01\x00\x00\x00', 0, props)
        encoded = raw[:18+length]+suffix
        if len(encoded)>1514:
            raise ProtocolError('oversized vendor frame')
        self._decorated[raw] = encoded
        return replace(action, frame=encoded)

    def start(self, now):
        return self.decorate(super().start(now))

    def tick(self, now):
        return self.decorate(super().tick(now))

    def receive(self, raw, now):
        prior_state = self.state
        candidate = None
        incoming_seed = None
        try:
            if len(raw)>=22 and raw[12:16] == b'\x88\x8e\x01\x00' and raw[:6] == self.local_mac:
                n = int.from_bytes(raw[16:18], 'big')
                packet = raw[18:18+n]
                if 18+n <= len(raw) and len(packet)>=4 and int.from_bytes(packet[2:4],'big')==n:
                    if packet[0]==3 and n>4:
                        if len(raw)>1514 or len(raw)>max(60,18+n) or (len(raw)!=60 and any(raw[18+n:])):
                            raise ValueError('invalid vendor success frame size')
                        candidate = success_parameters(packet[4:])
                        raw = EthernetEapol(raw[:6],raw[6:12],0,EapPacket(3,packet[1]).encode()).encode()
                    elif packet[0]==1 and len(packet)>=22 and packet[4:6]==b'\x04\x10':
                        incoming_seed=packet[6:22]
        except ValueError:
            return self._effect('ignored', 'malformed vendor success')
        action = super().receive(raw, now)
        if action.kind=='send' and incoming_seed is not None:
            self.seed=incoming_seed
        if prior_state in self._active and action.kind=='status' and action.state is State.AUTHENTICATED:
            self.success=candidate
        return self.decorate(action)

    def _wipe(self):
        super()._wipe()
        if hasattr(self, '_vendor_password'):
            self._vendor_password[:]=bytes(len(self._vendor_password))
            self._vendor_password.clear()
            self._decorated.clear()
