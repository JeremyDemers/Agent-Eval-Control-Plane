import json
import logging

import pytest

from aecontrol.tracing import (
    ActiveSpan,
    LocalSpanBackend,
    current_traceparent,
    new_trace,
    parse_traceparent,
    reset_span_backend,
    set_span_backend,
    span,
)


def test_traceparent_validation_and_child_generation() -> None:
    parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    parsed = parse_traceparent(parent)
    assert parsed is not None
    child = new_trace(parent)
    assert child.trace_id == parsed.trace_id
    assert child.span_id != parsed.span_id
    assert child.parent_span_id == parsed.span_id
    assert child.flags == parsed.flags
    assert parse_traceparent("00-" + "0" * 32 + "-" + "1" * 16 + "-01") is None
    assert parse_traceparent("not-a-trace") is None


def test_span_restores_context_and_logs_failure(caplog: pytest.LogCaptureFixture) -> None:
    with (
        caplog.at_level(logging.INFO, logger="uvicorn.error.aecontrol.traces"),
        pytest.raises(RuntimeError),
        span("worker.test", job_id="job-1") as context,
    ):
        assert current_traceparent() == context.traceparent
        raise RuntimeError("expected")
    assert current_traceparent() is None
    record = json.loads(caplog.records[-1].message)
    assert record["name"] == "worker.test"
    assert record["outcome"] == "error"
    assert record["job_id"] == "job-1"


class _FailingBackend(LocalSpanBackend):
    def start(self, name: str, parent: str | None, attributes: dict[str, object]) -> ActiveSpan:
        raise RuntimeError("exporter unavailable")


class _TrackingBackend(LocalSpanBackend):
    def __init__(self) -> None:
        self.finished = False

    def finish(self, active: ActiveSpan, outcome: str, error: BaseException | None) -> None:
        self.finished = True


def test_span_falls_back_when_backend_start_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    set_span_backend(_FailingBackend())
    try:
        with (
            caplog.at_level(logging.ERROR, logger="uvicorn.error.aecontrol.traces"),
            span("fallback") as context,
        ):
            assert parse_traceparent(context.traceparent) is not None
    finally:
        reset_span_backend()
    assert "using local context" in caplog.text


def test_span_finishes_on_backend_that_started_it() -> None:
    backend = _TrackingBackend()
    set_span_backend(backend)
    try:
        with span("stable-backend"):
            reset_span_backend()
    finally:
        reset_span_backend()
    assert backend.finished is True
