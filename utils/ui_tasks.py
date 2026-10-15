"""UI-independent admission and freshness tokens for asynchronous workers.

Run work with the UI's executor. Apply values *and errors* only after checking
their token on the UI thread, without awaiting between the check and update.
Closing this coordinator suppresses callbacks; it never cancels a privileged
operation midway through its rollback or cleanup.
"""
from dataclasses import dataclass
import threading


@dataclass(frozen=True)
class ReadTicket:
    key: str
    generation: int
    epoch: int


@dataclass(frozen=True)
class MutationTicket:
    generation: int
    epoch: int


class TaskCoordinator:
    def __init__(self):
        self._lock = threading.RLock()
        self._epoch = 0
        self._closed = False
        self._reads = {}
        self._generation = 0
        self._mutation = None

    @property
    def epoch(self):
        with self._lock:
            return self._epoch

    @property
    def closed(self):
        with self._lock:
            return self._closed

    @property
    def mutation_busy(self):
        with self._lock:
            return self._mutation is not None

    def begin_read(self, key: str) -> ReadTicket | None:
        if not isinstance(key, str) or not key:
            raise ValueError("A read task requires a nonempty key")
        with self._lock:
            if self._closed or self._mutation is not None:
                return None
            generation = self._reads.get(key, 0) + 1
            self._reads[key] = generation
            return ReadTicket(key, generation, self._epoch)

    def accept_read(self, ticket: ReadTicket | None) -> bool:
        with self._lock:
            return (isinstance(ticket, ReadTicket) and not self._closed
                    and self._mutation is None and ticket.epoch == self._epoch
                    and self._reads.get(ticket.key) == ticket.generation)

    def invalidate_read(self, key: str) -> None:
        """Discard in-flight reads when their selection/source context changes."""
        if not isinstance(key, str) or not key:
            raise ValueError("A read task requires a nonempty key")
        with self._lock:
            self._reads[key] = self._reads.get(key, 0) + 1

    def begin_mutation(self) -> MutationTicket | None:
        """Reserve the single write slot before any persistence or other effects."""
        with self._lock:
            if self._closed or self._mutation is not None:
                return None
            self._epoch += 1
            self._generation += 1
            self._mutation = MutationTicket(self._generation, self._epoch)
            return self._mutation

    def accept_mutation(self, ticket: MutationTicket | None) -> bool:
        """Check progress/results while leaving the write slot reserved."""
        with self._lock:
            return (isinstance(ticket, MutationTicket) and not self._closed
                    and self._mutation == ticket)

    def finish_mutation(self, ticket: MutationTicket | None) -> bool:
        """Release only this write slot; return whether its callback is current.

        The matching worker must call this in finally even after close(). A
        stale worker can never release a newer worker's reservation.
        """
        with self._lock:
            if not isinstance(ticket, MutationTicket) or self._mutation != ticket:
                return False
            self._mutation = None
            return not self._closed

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._epoch += 1
                self._reads.clear()
