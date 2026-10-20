import json
import unittest
from unittest.mock import patch
from fixture_support import fixture_directory
from utils.connection_events import LocalJournal, ProgressMessage, DiagnosticMessage


class JournalTests(unittest.TestCase):
    def test_detailed_events_share_session_and_measure_stage_without_credentials(self):
        from utils.auth_service import CampusService
        from utils.credential_store import Credentials
        root=fixture_directory(self,'journal-stage')
        service=CampusService(data_dir=root)
        service._remember(credentials=Credentials('synthetic-user','synthetic-password'))
        with patch('utils.auth_service.time.monotonic',return_value=10) as clock:
            emit=service._logger(None)
            emit(ProgressMessage('network','检测网卡'))
            clock.return_value=12
            emit(ProgressMessage('authenticate','认证'))
            emit(DiagnosticMessage('internet_probe','synthetic-user synthetic-password',
                reason='timeout',duration_ms=20,packet='secret-packet',dns_count=2))
        text=service.journal.path.read_text(encoding='utf-8')
        records=[json.loads(line) for line in text.splitlines()]
        self.assertEqual(len({r['session'] for r in records}),1)
        self.assertEqual(records[1]['duration_ms'],2000)
        self.assertEqual(records[-1]['reason'],'timeout')
        self.assertEqual(records[-1]['dns_count'],2)
        self.assertNotIn('packet',records[-1])
        for value in ('synthetic-user','synthetic-password','secret-packet'):
            self.assertNotIn(value,text)

    def test_redaction_allowlist_and_rotation(self):
        root=fixture_directory(self,'journal')
        journal=LocalJournal(root,lambda s:str(s).replace('synthetic-account','[account]'),limit=500)
        for n in range(20):
            journal.write('probe','synthetic-account 192.0.2.1 https://example.test/?token=private',
                          ready=False,attempt=n,packet='must-not-persist')
        files=list(root.iterdir())
        self.assertEqual(len(files),4)
        for file in files:
            text=file.read_text(encoding='utf-8')
            for secret in ('synthetic-account','192.0.2.1','private','must-not-persist'):
                self.assertNotIn(secret,text)
            self.assertLessEqual(file.stat().st_size,500)
            for line in text.splitlines(): self.assertFalse(json.loads(line)['ready'])

    def test_write_failure_does_not_break_authentication(self):
        root=fixture_directory(self,'journal-error')
        journal=LocalJournal(root)
        with patch('pathlib.Path.open',side_effect=PermissionError):
            journal.write('test','safe')
        self.assertFalse(journal.available)
        journal.write('test','safe')
        self.assertTrue(journal.available)

    def test_stage_is_compatible_with_plain_log_callbacks(self):
        message=ProgressMessage('authenticate','认证中')
        self.assertEqual(message,'认证中')
        self.assertEqual((message.step,message.total),(3,6))
