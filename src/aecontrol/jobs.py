from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

from aecontrol.engine import EvaluationEngine, load_suite
from aecontrol.hardware import detect_worker_capabilities
from aecontrol.models import EvaluationJob, WorkerCapabilities
from aecontrol.store import ArtifactStore


class EvaluationWorker:
    """Claims durable jobs and writes runs before acknowledging completion."""

    def __init__(
        self,
        store: ArtifactStore,
        worker_id: str,
        lease_seconds: int = 120,
        capabilities: WorkerCapabilities | None = None,
        capability_provider: Callable[[], WorkerCapabilities] | None = None,
    ) -> None:
        if lease_seconds < 3:
            msg = "lease_seconds must be at least 3"
            raise ValueError(msg)
        self.store = store
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        if capabilities is not None and capability_provider is not None:
            raise ValueError("provide capabilities or capability_provider, not both")
        self._capability_provider = capability_provider
        if capabilities is None:
            self._capability_provider = capability_provider or detect_worker_capabilities
            capabilities = self._capability_provider()
        self.capabilities = capabilities

    def _refresh_capabilities(self) -> WorkerCapabilities:
        if self._capability_provider is not None:
            self.capabilities = self._capability_provider()
        return self.capabilities

    async def run_once(self) -> EvaluationJob | None:
        capabilities = await asyncio.to_thread(self._refresh_capabilities)
        await asyncio.to_thread(self.store.register_worker, self.worker_id, capabilities)
        job = await asyncio.to_thread(
            self.store.lease_job, self.worker_id, self.lease_seconds, capabilities
        )
        if job is None:
            return None

        heartbeat_stop = asyncio.Event()
        heartbeat = asyncio.create_task(self._heartbeat(job, heartbeat_stop))
        try:
            run = await EvaluationEngine().run(load_suite(Path(job.suite_path)), job.agent_version)
            await asyncio.to_thread(self.store.save_run, run)
            return await asyncio.to_thread(
                self.store.complete_job, job.job_id, self.worker_id, run.run_id
            )
        except Exception as error:
            message = f"{type(error).__name__}: {error}"
            try:
                return await asyncio.to_thread(
                    self.store.fail_job, job.job_id, self.worker_id, message
                )
            except RuntimeError:
                return await asyncio.to_thread(self.store.get_job, job.job_id)
        finally:
            heartbeat_stop.set()
            await heartbeat

    async def run_forever(self, poll_seconds: float = 1.0) -> None:
        if poll_seconds <= 0:
            msg = "poll_seconds must be positive"
            raise ValueError(msg)
        while True:
            job = await self.run_once()
            if job is None:
                await asyncio.sleep(poll_seconds)

    async def _heartbeat(self, job: EvaluationJob, stop: asyncio.Event) -> None:
        interval = self.lease_seconds / 3
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except TimeoutError:
                try:
                    capabilities = await asyncio.to_thread(self._refresh_capabilities)
                    await asyncio.to_thread(
                        self.store.register_worker, self.worker_id, capabilities
                    )
                    await asyncio.to_thread(
                        self.store.renew_job_lease,
                        job.job_id,
                        self.worker_id,
                        self.lease_seconds,
                    )
                except RuntimeError:
                    return
