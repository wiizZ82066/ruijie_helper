import unittest
from unittest.mock import Mock
from utils.resume_watch import ResumeWatch


class ResumeWatchTests(unittest.TestCase):
    def test_short_sleep_and_hibernation_are_detected_once(self):
        reader=Mock(side_effect=[(100,80),(105,82),(107,84),(3709,86),(3711,88)])
        monitor=ResumeWatch(reader)
        self.assertTrue(monitor.poll())
        self.assertFalse(monitor.poll())
        self.assertTrue(monitor.poll())
        self.assertFalse(monitor.poll())

    def test_busy_awake_process_and_timer_jitter_are_not_sleep(self):
        monitor=ResumeWatch(Mock(side_effect=[(100,80),(160,140.015),(162,142)]))
        self.assertFalse(monitor.poll())
        self.assertFalse(monitor.poll())

    def test_read_failure_reseeds_without_false_wake(self):
        monitor=ResumeWatch(Mock(side_effect=[(100,80),OSError(),(200,82),(202,84)]))
        self.assertFalse(monitor.poll())
        self.assertFalse(monitor.poll())
        self.assertFalse(monitor.poll())
