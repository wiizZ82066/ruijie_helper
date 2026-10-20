"""User-visible stages and bounded, local-only diagnostic events."""
from datetime import datetime
import json
from pathlib import Path
import re
import threading

STAGES = ('network', 'prepare', 'authenticate', 'address', 'verify', 'complete')
STAGE_LABELS = dict(zip(STAGES, ('检查网络', '准备连接', '账号认证', '获取地址', '验证网络', '已连接')))


class DiagnosticMessage(str):
    def __new__(cls, event, message, **fields):
        value = super().__new__(cls, message)
        value.event, value.fields = event, fields
        return value


class ProgressMessage(str):
    def __new__(cls, stage, message):
        value = super().__new__(cls, message)
        value.stage = stage
        value.step = STAGES.index(stage) + 1 if stage in STAGES else 0
        value.total = len(STAGES)
        return value


def scrub(message):
    text = str(message)
    text = re.sub(r'https?://\S+', '[url]', text, flags=re.I)
    text = re.sub(r'(?i)\b(?:username|userid|password|passwd|userindex|token|secret|cookie|authorization|querystring)\b\s*["\x27]?\s*[:=]\s*[^\r\n]+', '[sensitive field]', text)
    text = re.sub(r'(?i)\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b', '[interface]', text)
    text = re.sub(r'(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b', '[mac]', text)
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[ip]', text)
    text = re.sub(r'(?i)\b[a-z]:[\\/][^\r\n"<>]*', '[local path]', text)
    return text[:2000]


class LocalJournal:
    """At most four 256-KiB files; no uploads, raw packets or account profiles."""
    def __init__(self, directory, redact=lambda x: x, limit=256*1024):
        self.directory = Path(directory)
        self.path = self.directory / 'connection.log'
        self.redact, self.limit = redact, limit
        self._lock = threading.Lock()
        self.available = True

    def write(self, event, message, **fields):
        record = {'time': datetime.now().astimezone().isoformat(timespec='milliseconds'),
                  'event': str(event)[:40], 'message': scrub(self.redact(message))}
        for key in ('attempt', 'stage', 'ready', 'authenticated', 'retryable', 'reason', 'elapsed_ms',
                    'session', 'sequence', 'operation', 'outcome', 'duration_ms', 'error_type',
                    'dhcp', 'address_count', 'gateway_count', 'dns_count', 'lease', 'initial',
                    'requests', 'packets', 'http_status', 'cancelled', 'active', 'enabled'):
            value = fields.get(key)
            if isinstance(value, (str, bool, int, float)):
                record[key] = scrub(self.redact(value)) if isinstance(value, str) else value
        line = json.dumps(record, ensure_ascii=False) + '\n'
        try:
            with self._lock:
                self.directory.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size + len(line.encode('utf-8')) > self.limit:
                    for number in (3, 2, 1):
                        source = self.path if number == 1 else self.path.with_suffix('.log.'+str(number-1))
                        target = self.path.with_suffix('.log.'+str(number))
                        if source.exists(): source.replace(target)
                with self.path.open('a', encoding='utf-8') as stream:
                    stream.write(line)
                self.available = True
        except OSError:
            self.available = False  # Diagnostic disk errors must not break login.
