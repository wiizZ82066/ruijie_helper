"""Pause only a verified installed native client when handing the link to ours.

Never installs/patches client files or changes service startup configuration.
No installed client is required. Saved launch arguments stay in memory only.
"""
import hashlib
from pathlib import Path
import subprocess
import psutil
from utils.wired_network import _run

KNOWN_CORES = {
    'e8061b2a454d8e8472a7d01b08023e2c7108da44fab7913dc0b129444ef9e039',
    'baf9d6d4a238edf6594dd4040cff4796a5033636a3a45ebf82fa9077c9389446',
}


def service_state():
    try:
        return psutil.win_service_get('RJSuService').as_dict()
    except psutil.NoSuchProcess:
        return None


def native_absent():
    if any((p.info['name'] or '').lower() in ('8021x.exe','ruijiesupplicant.exe')
           for p in psutil.process_iter(['name'])):
        return False
    service=service_state()
    return service is None or service['status']=='stopped'


class NativeHandoff:
    def __init__(self, *, restart_on_failure=True):
        self.restart_on_failure=restart_on_failure
        self.core=None
        self.service_stopped=False

    def pause(self):
        cores=[]
        for p in psutil.process_iter(['name']):
            name=(p.info['name'] or '').lower()
            if name=='ruijiesupplicant.exe':
                raise RuntimeError('请先从锐捷界面退出客户端，再连接独立认证。')
            if name!='8021x.exe':
                continue
            try:
                path=Path(p.exe()).resolve()
                if hashlib.sha256(path.read_bytes()).hexdigest() not in KNOWN_CORES:
                    raise RuntimeError('另一个认证客户端正在运行，请先退出它再连接。')
                cores.append((p,path,p.cmdline(),p.cwd()))
            except psutil.NoSuchProcess:
                continue
        if len(cores)>1:
            raise RuntimeError('多个认证客户端正在运行，请先退出它们。')
        service=service_state()
        service_process=None
        if service and service['status']!='stopped':
            if service['status']!='running':
                raise RuntimeError('原认证服务正在切换状态，请稍后重试。')
            service_process=psutil.Process(service['pid'])
            path=Path(service_process.exe()).resolve()
            core_path=path.parent/'8021x.exe'
            if (path.name.lower()!='suservice.exe' or
                Path(service['binpath'].strip('"')).resolve()!=path or
                not core_path.is_file() or hashlib.sha256(core_path.read_bytes()).hexdigest() not in KNOWN_CORES or
                (cores and cores[0][1].parent!=path.parent)):
                raise RuntimeError('无法核验正在运行的锐捷服务，请退出原客户端后重试。')
        if cores:
            self.core=cores[0]
        try:
            if service_process is not None:
                self.service_stopped=True
                service_process.terminate(); service_process.wait(8)
            if self.core and self.core[0].is_running():
                self.core[0].terminate(); self.core[0].wait(8)
            if not native_absent():
                raise RuntimeError('原客户端仍在运行，未开始独立认证。')
        except BaseException:
            if self.restart_on_failure:
                self.restore()
            else:
                self.forget()
            raise

    def restore(self):
        # Used only when initial independent login fails, not on user logoff.
        try:
            if self.core and not self.core[0].is_running():
                subprocess.Popen(self.core[2],executable=str(self.core[1]),cwd=self.core[3],
                                 creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if self.service_stopped:
                _run("Start-Service -Name RJSuService; @{ok=$true}|ConvertTo-Json -Compress")
        finally:
            self.core=None
            self.service_stopped=False

    def forget(self):
        self.core=None
        self.service_stopped=False
