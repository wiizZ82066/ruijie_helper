"""Read-only driver checks. Installation is explained in the bundled guide."""
import ctypes as C
import os
from pathlib import Path
import subprocess
import sys

DOWNLOAD_PAGE = 'https://npcap.com/#download'
MESSAGES = {
    'ready': '有线驱动已就绪',
    'missing': '有线连接需要安装驱动',
    'broken': '有线驱动未能正常加载',
    'denied': '请以管理员身份重新打开助手',
    'no_interfaces': '驱动已安装，暂未发现可用接口',
    'unknown': '暂时无法确认有线驱动状态',
    'blocked': '安全防护阻止了环境检测，请查看 Windows 保护历史记录',
}


EXIT_CODES = {'ready': 0, 'missing': 10, 'broken': 11, 'denied': 12, 'no_interfaces': 13, 'unknown': 14, 'blocked': 15}


def result(state):
    return {'state': state, 'message': MESSAGES[state]}


def probe_driver():
    """Runs in a short-lived process: no capture, packets or DLL locks in UI."""
    from utils.wired_transport import Device
    system = Path(os.environ['WINDIR']) / 'System32'
    directory = system / 'Npcap' if (system / 'Npcap' / 'wpcap.dll').is_file() else system
    if not (directory / 'wpcap.dll').is_file():
        return result('missing')
    try:
        dll = C.CDLL(str(directory / 'wpcap.dll'), winmode=0x100 | 0x800)
        # These exports are required by the actual wired transport.
        for name in ('pcap_open_live', 'pcap_datalink', 'pcap_compile', 'pcap_setfilter',
                     'pcap_freecode', 'pcap_setnonblock', 'pcap_next_ex',
                     'pcap_sendpacket', 'pcap_close'):
            getattr(dll, name)
        dll.pcap_findalldevs.argtypes = [C.POINTER(C.POINTER(Device)), C.c_char_p]
        dll.pcap_findalldevs.restype = C.c_int
        dll.pcap_freealldevs.argtypes = [C.POINTER(Device)]
        dll.pcap_freealldevs.restype = None
        first = C.POINTER(Device)()
        error = C.create_string_buffer(256)
        code = dll.pcap_findalldevs(C.byref(first), error)
        try:
            if code:
                denied = any(s in error.value.lower() for s in (b'access denied', b'access is denied', b'permission denied'))
                return result('denied' if denied else 'broken')
            return result('ready' if first else 'no_interfaces')
        finally:
            if first:
                dll.pcap_freealldevs(first)
    except OSError as error:
        if getattr(error, 'winerror', None) in (225, 226):
            return result('blocked')
        return result('denied' if getattr(error, 'winerror', None) == 5 else 'broken')
    except AttributeError:
        return result('broken')


def check_driver():
    command = [sys.executable]
    if not getattr(sys, 'frozen', False):
        command.append(str(Path(__file__).resolve().parents[1] / 'campus_flet.py'))
    command.append('--check-driver')
    try:
        completed = subprocess.run(command, capture_output=True, timeout=12,
                                   creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        # Windowed executables have no stdout. Exit codes also avoid leaking
        # paths, native strings or adapter identifiers between processes.
        state = next((key for key, code in EXIT_CODES.items() if code == completed.returncode), 'unknown')
        return result(state)
    except OSError as error:
        return result('blocked' if getattr(error, 'winerror', None) in (225, 226) else 'unknown')
    except (ValueError, subprocess.TimeoutExpired):
        return result('unknown')
