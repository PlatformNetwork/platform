"""GPU lease ledger for the single-GPU Swarm worker (Task 10).

This is the assignment/capacity bookkeeping side of GPU scheduling on the
Docker/Swarm backend. It reuses the established platform patterns instead of
inventing a new scheduler:

* Capacity semantics mirror
  :class:`platform_network.gpu.capabilities.ResourceCapabilityChecker`
  (refusal reason ``gpu_capacity_insufficient`` when the request exceeds the
  remaining capacity).
* Concurrency model mirrors
  :class:`platform_network.master.workload_ledger.WorkloadLedger`: broker
  handlers are synchronous ``def`` FastAPI endpoints executed on the anyio
  threadpool, so acquire/release arrive on multiple OS threads and the
  check-and-acquire must be atomic under a single :class:`threading.Lock`.

Leases are keyed by the workload's stable name (the Swarm service name) so
the holder that acquired around ``docker service create`` can release on
every exit path — cleanup, failed create, or job completion. The default
capacity is 1: the migration targets exactly one single-GPU worker node (no
multi-GPU/multi-worker generality, per plan Task 10).
"""

from __future__ import annotations

import threading


class GpuLeaseError(RuntimeError):
    """Raised when a GPU lease operation is invalid."""


class GpuCapacityError(GpuLeaseError):
    """Raised when acquiring a lease would exceed the GPU capacity."""

    def __init__(self, key: str, *, requested: int, in_use: int, capacity: int):
        super().__init__(
            f"gpu_capacity_insufficient: workload {key!r} requested "
            f"{requested} GPU(s) but {in_use}/{capacity} are leased"
        )
        self.key = key
        self.requested = requested
        self.in_use = in_use
        self.capacity = capacity


class GpuLeaseLedger:
    """Thread-safe GPU capacity ledger (atomic check-and-acquire)."""

    def __init__(self, capacity: int = 1) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise GpuLeaseError("GPU capacity must be a positive integer")
        self._capacity = capacity
        self._lock = threading.Lock()
        self._leases: dict[str, int] = {}

    @property
    def capacity(self) -> int:
        """Total GPU units this worker advertises."""

        return self._capacity

    @property
    def in_use(self) -> int:
        """GPU units currently leased."""

        with self._lock:
            return sum(self._leases.values())

    @property
    def available(self) -> int:
        """GPU units still acquirable."""

        with self._lock:
            return self._capacity - sum(self._leases.values())

    def acquire(self, key: str, gpu_count: int = 1) -> None:
        """Lease ``gpu_count`` GPU units under ``key``.

        Raises:
            GpuLeaseError: on an empty key, a non-positive count, or a
                duplicate lease key.
            GpuCapacityError: when granting the lease would exceed capacity
                (the second concurrent GPU workload on a capacity-1 worker).
        """

        if not key:
            raise GpuLeaseError("GPU lease key cannot be empty")
        if (
            isinstance(gpu_count, bool)
            or not isinstance(gpu_count, int)
            or gpu_count < 1
        ):
            raise GpuLeaseError("gpu_count must be a positive integer")
        with self._lock:
            if key in self._leases:
                raise GpuLeaseError(f"GPU lease {key!r} is already held")
            in_use = sum(self._leases.values())
            if in_use + gpu_count > self._capacity:
                raise GpuCapacityError(
                    key, requested=gpu_count, in_use=in_use, capacity=self._capacity
                )
            self._leases[key] = gpu_count

    def release(self, key: str) -> bool:
        """Release the lease held under ``key``. Idempotent."""

        with self._lock:
            return self._leases.pop(key, None) is not None
