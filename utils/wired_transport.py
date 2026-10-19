"""Own-interface non-promiscuous EAPOL transport. Uses an installed packet driver."""
import ctypes as C
import os
from pathlib import Path

class ProbeError(RuntimeError):
    pass

class Header(C.Structure):
    _fields_ = [('sec', C.c_int32), ('usec', C.c_int32),
                ('caplen', C.c_uint32), ('length', C.c_uint32)]


class Bpf(C.Structure):
    _fields_ = [('length', C.c_uint32), ('instructions', C.c_void_p)]


class Device(C.Structure):
    pass


Device._fields_ = [('next', C.POINTER(Device)), ('name', C.c_char_p),
                   ('description', C.c_char_p), ('addresses', C.c_void_p),
                   ('flags', C.c_uint32)]


class Pcap:
    def __init__(self, config):
        self.handle = None
        self.mac = config['mac_bytes']
        system = Path(os.environ['WINDIR']) / 'System32'
        if (system / 'Npcap' / 'wpcap.dll').is_file():
            system = system / 'Npcap'
        if not (system / 'wpcap.dll').is_file():
            raise ProbeError('未找到抓包驱动，请安装兼容的 Npcap（WinPcap API）后重试。')
        # Explicit system path; dependencies search the DLL directory and System32.
        self.dll = C.CDLL(str(system / 'wpcap.dll'), winmode=0x100 | 0x800)
        signatures = {
            'pcap_findalldevs': ([C.POINTER(C.POINTER(Device)), C.c_char_p], C.c_int),
            'pcap_freealldevs': ([C.POINTER(Device)], None),
            'pcap_open_live': ([C.c_char_p, C.c_int, C.c_int, C.c_int, C.c_char_p], C.c_void_p),
            'pcap_datalink': ([C.c_void_p], C.c_int),
            'pcap_compile': ([C.c_void_p, C.POINTER(Bpf), C.c_char_p, C.c_int, C.c_uint32], C.c_int),
            'pcap_setfilter': ([C.c_void_p, C.POINTER(Bpf)], C.c_int),
            'pcap_freecode': ([C.POINTER(Bpf)], None),
            'pcap_setnonblock': ([C.c_void_p, C.c_int, C.c_char_p], C.c_int),
            'pcap_next_ex': ([C.c_void_p, C.POINTER(C.POINTER(Header)), C.POINTER(C.POINTER(C.c_ubyte))], C.c_int),
            'pcap_sendpacket': ([C.c_void_p, C.c_void_p, C.c_int], C.c_int),
            'pcap_close': ([C.c_void_p], None),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.dll, name)
            function.argtypes, function.restype = args, result
        err = C.create_string_buffer(256)
        first = C.POINTER(Device)()
        if self.dll.pcap_findalldevs(C.byref(first), err):
            raise ProbeError('pcap_enumeration_failed')
        wanted = ('\\Device\\NPF_{' + config['guid'] + '}').encode('ascii')
        selected = None
        try:
            current, count = first, 0
            while current and count < 256:
                if current.contents.name.lower() == wanted.lower():
                    selected = current.contents.name
                current, count = current.contents.next, count + 1
        finally:
            self.dll.pcap_freealldevs(first)
        if selected is None:
            raise ProbeError('target_not_available_in_pcap')
        self.handle = self.dll.pcap_open_live(selected, 2048, 0, 100, err)
        if not self.handle:
            raise ProbeError('pcap_open_failed')
        try:
            if self.dll.pcap_datalink(self.handle) != 1:
                raise ProbeError('not_ethernet_datalink')
            self.set_filter()
            if self.dll.pcap_setnonblock(self.handle, 1, err):
                raise ProbeError('nonblocking_capture_failed')
        except BaseException:
            self.close()
            raise

    def set_filter(self, udp_ports=()):
        ports = sorted(set(udp_ports))
        if len(ports) > 16 or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
            raise ProbeError('invalid_native_port_filter')
        address = ':'.join(f'{x:02x}' for x in self.mac)
        expression = f'(ether proto 0x888e and (ether host {address} or ether dst 01:80:c2:00:00:03))'
        if ports:
            expression += f" or (ether host {address} and ip and udp and ({' or '.join(f'port {p}' for p in ports)}))"
        program = Bpf()
        if self.dll.pcap_compile(self.handle, C.byref(program), expression.encode(), 1, 0xffffffff):
            raise ProbeError('capture_filter_compile_failed')
        try:
            if self.dll.pcap_setfilter(self.handle, C.byref(program)):
                raise ProbeError('capture_filter_failed')
        finally:
            self.dll.pcap_freecode(C.byref(program))

    def receive(self):
        header, body = C.POINTER(Header)(), C.POINTER(C.c_ubyte)()
        code = self.dll.pcap_next_ex(self.handle, C.byref(header), C.byref(body))
        if code == 0:
            return None
        if code != 1:
            raise ProbeError('capture_read_failed')
        count = header.contents.caplen
        if count < 18 or count > 2048 or count != header.contents.length:
            return None
        return C.string_at(body, count)

    def send(self, frame):
        if not 18 <= len(frame) <= 1514 or frame[6:12] != self.mac or frame[12:14] != b'\x88\x8e':
            raise ProbeError('outgoing_frame_outside_scope')
        buffer = C.create_string_buffer(frame)
        if self.dll.pcap_sendpacket(self.handle, buffer, len(frame)):
            raise ProbeError('send_failed')

    def close(self):
        if self.handle:
            self.dll.pcap_close(self.handle)
            self.handle = None
