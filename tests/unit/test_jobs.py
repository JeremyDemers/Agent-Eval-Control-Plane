from __future__ import annotations

import asyncio
from typing import cast

import pytest

from aecontrol.hardware import detect_worker_capabilities
from aecontrol.jobs import EvaluationWorker
from aecontrol.models import EvaluationJob, JobStatus, WorkerCapabilities, WorkerRecord, utc_now
from aecontrol.store import ArtifactStore


class FakeStore:
    def __init__(self, job: EvaluationJob | None = None) -> None:
        self.job = job
        self.renewals = 0

    def register_worker(self, worker_id: str, capabilities: WorkerCapabilities) -> WorkerRecord:
        return WorkerRecord(
            worker_id=worker_id,
            capabilities=capabilities,
            registered_at=utc_now(),
            last_seen_at=utc_now(),
        )

    def lease_job(
        self,
        worker_id: str,
        lease_seconds: int,
        capabilities: WorkerCapabilities,
    ) -> EvaluationJob | None:
        return self.job

    def renew_job_lease(self, job_id: object, worker_id: str, lease_seconds: int) -> EvaluationJob:
        self.renewals += 1
        assert self.job is not None
        return self.job


@pytest.mark.asyncio
async def test_worker_reports_empty_queue_and_validates_settings() -> None:
    store = cast(ArtifactStore, FakeStore())
    worker = EvaluationWorker(
        store, "worker-1", lease_seconds=3, capabilities=detect_worker_capabilities()
    )

    assert await worker.run_once() is None
    with pytest.raises(ValueError, match="poll_seconds must be positive"):
        await worker.run_forever(0)
    with pytest.raises(ValueError, match="lease_seconds must be at least 3"):
        EvaluationWorker(store, "worker-1", lease_seconds=2)
    with pytest.raises(ValueError, match="capabilities or capability_provider"):
        EvaluationWorker(
            store,
            "worker-1",
            capabilities=detect_worker_capabilities(),
            capability_provider=detect_worker_capabilities,
        )


@pytest.mark.asyncio
async def test_worker_refreshes_dynamic_capabilities() -> None:
    fake_store = FakeStore()
    snapshots = iter(
        [
            detect_worker_capabilities({"sample": "initial"}),
            detect_worker_capabilities({"sample": "refreshed"}),
        ]
    )
    worker = EvaluationWorker(
        cast(ArtifactStore, fake_store), "worker-1", capability_provider=lambda: next(snapshots)
    )

    await worker.run_once()

    assert worker.capabilities.labels == {"sample": "refreshed"}


@pytest.mark.asyncio
async def test_worker_renews_active_lease() -> None:
    job = EvaluationJob(suite_path="suite.yaml", agent_version="baseline")
    fake_store = FakeStore(job)
    worker = EvaluationWorker(cast(ArtifactStore, fake_store), "worker-1", lease_seconds=3)
    stop = asyncio.Event()

    heartbeat = asyncio.create_task(worker._heartbeat(job, stop))
    await asyncio.sleep(1.1)
    stop.set()
    await heartbeat

    assert fake_store.renewals == 1


@pytest.mark.asyncio
async def test_worker_returns_current_job_when_lease_is_lost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = EvaluationJob(
        suite_path="examples/suites/coding_repair.yaml",
        agent_version="baseline",
        status=JobStatus.CANCELLED,
    )

    class LeaseLostStore(FakeStore):
        def fail_job(self, job_id: object, worker_id: str, error: str) -> EvaluationJob:
            raise RuntimeError("lease lost")

        def get_job(self, job_id: object) -> EvaluationJob:
            assert self.job is not None
            return self.job

    async def fail_run(*_args: object, **_kwargs: object) -> None:
        raise ValueError("evaluation failed")

    monkeypatch.setattr("aecontrol.jobs.EvaluationEngine.run", fail_run)
    worker = EvaluationWorker(cast(ArtifactStore, LeaseLostStore(job)), "worker-1")

    result = await worker.run_once()

    assert result is not None
    assert result.status == JobStatus.CANCELLED
