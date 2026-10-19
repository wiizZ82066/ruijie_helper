"""Read-only sleep detection, independent of wall-clock corrections.

GetTickCount64 includes sleep; QueryUnbiasedInterruptTime excludes it:
https://learn.microsoft.com/en-us/windows/win32/sysinfo/windows-time
"""
import ctypes
import sys


class ResumeWatch:
    def __init__(self, reader=None):
        self.reader = reader
        self.previous = None
        if reader is None and sys.platform == 'win32':
            try:
                kernel = ctypes.WinDLL('kernel32', use_last_error=True)
                tick = kernel.GetTickCount64
                tick.argtypes, tick.restype = [], ctypes.c_uint64
                awake = kernel.QueryUnbiasedInterruptTime
                awake.argtypes, awake.restype = [ctypes.POINTER(ctypes.c_uint64)], ctypes.c_int

                def read():
                    value = ctypes.c_uint64()
                    if not awake(ctypes.byref(value)):
                        raise OSError('System clock unavailable')
                    return tick()/1000, value.value/10_000_000
                self.reader = read
            except (OSError, AttributeError):
                pass
        self.poll()

    def poll(self):
        if self.reader is None:
            return False
        try:
            current = self.reader()
        except OSError:
            self.previous = None
            return False
        previous, self.previous = self.previous, current
        if previous is None:
            return False
        total, awake = current[0]-previous[0], current[1]-previous[1]
        # Allow timer quantization, and seed again after clock discontinuity.
        return total >= 0 and awake >= 0 and total-awake > 1
