import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from utils.ui_tasks import TaskCoordinator


class TaskCoordinatorTests(unittest.TestCase):
    def test_independent_reads_are_immediately_admitted(self):
        tasks = TaskCoordinator()
        reads = [tasks.begin_read(key) for key in ("adapters", "startup", "hotspot")]
        self.assertTrue(all(tasks.accept_read(ticket) for ticket in reads))
        self.assertFalse(tasks.mutation_busy)

    def test_newer_read_discards_older_value_and_error_for_same_key(self):
        tasks = TaskCoordinator()
        old = tasks.begin_read("hotspot")
        other = tasks.begin_read("startup")
        latest = tasks.begin_read("hotspot")
        self.assertFalse(tasks.accept_read(old))
        self.assertTrue(tasks.accept_read(latest))
        self.assertTrue(tasks.accept_read(other))

    def test_mutation_does_not_wait_for_reads_and_invalidates_their_results(self):
        tasks = TaskCoordinator()
        old = tasks.begin_read("hotspot")
        mutation = tasks.begin_mutation()
        self.assertIsNotNone(mutation)
        self.assertFalse(tasks.accept_read(old))
        self.assertIsNone(tasks.begin_read("startup"))
        self.assertTrue(tasks.finish_mutation(mutation))
        self.assertFalse(tasks.accept_read(old))
        self.assertTrue(tasks.accept_read(tasks.begin_read("hotspot")))

    def test_mutations_are_serial_and_rejection_does_not_change_epoch(self):
        tasks = TaskCoordinator()
        first = tasks.begin_mutation()
        self.assertIsNone(tasks.begin_mutation())
        self.assertEqual(tasks.epoch, first.epoch)
        self.assertTrue(tasks.finish_mutation(first))
        second = tasks.begin_mutation()
        self.assertGreater(second.epoch, first.epoch)
        self.assertFalse(tasks.finish_mutation(first))
        self.assertTrue(tasks.mutation_busy)
        self.assertTrue(tasks.accept_mutation(second))

    def test_selection_change_invalidates_only_related_reads(self):
        tasks = TaskCoordinator()
        old = tasks.begin_read("hotspot")
        other = tasks.begin_read("startup")
        tasks.invalidate_read("hotspot")
        self.assertFalse(tasks.accept_read(old))
        self.assertTrue(tasks.accept_read(other))

    def test_close_suppresses_every_callback_without_aborting_worker_cleanup(self):
        tasks = TaskCoordinator()
        read = tasks.begin_read("adapters")
        write = tasks.begin_mutation()
        tasks.close()
        epoch = tasks.epoch
        tasks.close()
        self.assertEqual(tasks.epoch, epoch)
        self.assertTrue(tasks.mutation_busy)
        self.assertFalse(tasks.accept_read(read))
        self.assertFalse(tasks.accept_mutation(write))
        self.assertFalse(tasks.finish_mutation(write))
        self.assertFalse(tasks.mutation_busy)
        self.assertIsNone(tasks.begin_read("adapters"))
        self.assertIsNone(tasks.begin_mutation())

    def test_only_one_concurrent_writer_gets_admission(self):
        tasks = TaskCoordinator()
        barrier = threading.Barrier(8)
        def reserve(_):
            barrier.wait(timeout=2)
            return tasks.begin_mutation()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(reserve, range(8)))
        self.assertEqual(sum(ticket is not None for ticket in results), 1)
        self.assertEqual(tasks.epoch, 1)

    def test_missing_or_wrong_token_never_releases_current_writer(self):
        tasks = TaskCoordinator()
        read = tasks.begin_read("hotspot")
        mutation = tasks.begin_mutation()
        for invalid in (None, object(), read):
            self.assertFalse(tasks.finish_mutation(invalid))
            self.assertFalse(tasks.accept_mutation(invalid))
        self.assertTrue(tasks.accept_mutation(mutation))

    def test_empty_or_nonstring_read_key_is_rejected(self):
        tasks = TaskCoordinator()
        for value in (None, "", 3):
            with self.assertRaises(ValueError):
                tasks.begin_read(value)
            with self.assertRaises(ValueError):
                tasks.invalidate_read(value)


if __name__ == "__main__":
    unittest.main()
