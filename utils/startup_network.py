"""Read-only admission checks for silent logon; never starts authentication."""
import re
import subprocess
import urllib.request


def internet_available():
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open('http://www.msftconnecttest.com/connecttest.txt', timeout=4) as response:
            return response.status == 200 and response.read(128).strip() == b'Microsoft Connect Test'
    except Exception:
        return False


def jnu_available():
    from utils.wireless_network import current_jnu, _WlanClient
    try:
        if current_jnu():
            return True
        with _WlanClient() as wlan:
            if not any(wlan.has_profile(guid) for guid in wlan.interfaces()):
                return False
        result = subprocess.run(['netsh.exe', 'wlan', 'show', 'networks'],
            capture_output=True, timeout=8, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        # SSID headers and JNU are ASCII in every supported console codepage.
        return result.returncode == 0 and bool(re.search(rb'(?m)^\s*SSID\s+\d+\s*:\s*JNU\s*\r?$', result.stdout))
    except Exception:
        return False


def decision(values, target):
    if internet_available():
        return {'connect': False, 'reason': 'already_online', 'message': '当前网络已可上网'}
    if target[0] == 'wired' or values.get('connection_mode') != 'wired' and jnu_available():
        return {'connect': True, 'reason': 'campus_available', 'message': '检测到可用校园网'}
    return {'connect': False, 'reason': 'campus_unavailable', 'message': '等待可用校园网'}
