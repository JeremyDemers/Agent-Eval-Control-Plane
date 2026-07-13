import json
import logging

import pytest

from aecontrol.tracing import current_traceparent, new_trace, parse_traceparent, span


def test_traceparent_validation_and_child_generation() -> None:
    parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    parsed = parse_traceparent(parent)
    assert parsed is not None
    child = new_trace(parent)
    assert child.trace_id == parsed.trace_id
    assert child.span_id != parsed.span_id
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
