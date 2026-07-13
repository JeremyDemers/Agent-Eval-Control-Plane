from __future__ import annotations

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

from aecontrol.telemetry import (
    OpenTelemetrySpanBackend,
    record_http_response,
    telemetry_configuration_from_environment,
)
from aecontrol.tracing import set_span_backend, shutdown_span_backend, span

PARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"


def test_http_span_exports_w3c_parent_and_semantic_attributes() -> None:
    exporter = InMemorySpanExporter()
    set_span_backend(OpenTelemetrySpanBackend(exporter, service_name="test-api", batch=False))
    try:
        with span(
            "http.request",
            PARENT,
            method="POST",
            path="/api/v1/jobs",
            ignored={"prompt": "secret"},
        ) as context:
            assert context.trace_id == PARENT.split("-")[1]
            assert context.parent_span_id == PARENT.split("-")[2]
    finally:
        shutdown_span_backend()

    exported = exporter.get_finished_spans()
    assert len(exported) == 1
    finished = exported[0]
    assert finished.context is not None
    assert finished.parent is not None
    assert f"{finished.context.span_id:016x}" == context.span_id
    assert f"{finished.parent.span_id:016x}" == PARENT.split("-")[2]
    assert finished.kind is SpanKind.SERVER
    assert finished.attributes is not None
    assert finished.attributes["http.request.method"] == "POST"
    assert finished.attributes["url.path"] == "/api/v1/jobs"
    assert "aecontrol.ignored" not in finished.attributes
    assert finished.attributes["aecontrol.outcome"] == "ok"
    assert finished.status.status_code is StatusCode.UNSET
    assert finished.resource.attributes["service.name"] == "test-api"


def test_http_span_marks_server_errors() -> None:
    exporter = InMemorySpanExporter()
    set_span_backend(OpenTelemetrySpanBackend(exporter, batch=False))
    try:
        with span("http.request"):
            record_http_response(503)
    finally:
        shutdown_span_backend()

    finished = exporter.get_finished_spans()[0]
    assert finished.attributes is not None
    assert finished.attributes["http.response.status_code"] == 503
    assert finished.status.status_code is StatusCode.ERROR


def test_worker_span_exports_error_without_exception_message() -> None:
    exporter = InMemorySpanExporter()
    set_span_backend(OpenTelemetrySpanBackend(exporter, batch=False))
    try:
        with (
            pytest.raises(RuntimeError, match="sensitive detail"),
            span(
                "evaluation.job",
                PARENT,
                job_id="job-1",
                worker_id="worker-1",
                agent_version="candidate",
            ),
        ):
            raise RuntimeError("sensitive detail")
    finally:
        shutdown_span_backend()

    finished = exporter.get_finished_spans()[0]
    assert finished.kind is SpanKind.CONSUMER
    assert finished.attributes is not None
    assert finished.attributes["aecontrol.job.id"] == "job-1"
    assert finished.attributes["aecontrol.worker.id"] == "worker-1"
    assert finished.attributes["aecontrol.agent.version"] == "candidate"
    assert finished.attributes["aecontrol.outcome"] == "error"
    assert finished.status.status_code is StatusCode.ERROR
    assert finished.status.description == "RuntimeError"


def test_telemetry_configuration_is_opt_in_and_sanitized() -> None:
    assert telemetry_configuration_from_environment({}).enabled is False
    assert (
        telemetry_configuration_from_environment(
            {
                "OTEL_EXPORTER_OTLP_ENDPOINT": "https://token:secret@collector.example:4318",
                "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
            }
        ).endpoint_host
        == "collector.example"
    )
    assert (
        telemetry_configuration_from_environment(
            {
                "OTEL_SDK_DISABLED": "true",
                "OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example:4318",
            }
        ).mode
        == "json-log"
    )


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ({"OTEL_EXPORTER_OTLP_ENDPOINT": "collector:4318"}, "absolute HTTP"),
        (
            {
                "OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318",
                "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc",
            },
            "http/protobuf",
        ),
    ],
)
def test_telemetry_configuration_rejects_unsupported_values(
    environment: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        telemetry_configuration_from_environment(environment)
