from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from contextvars import Token
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import cast
from urllib.parse import urlsplit

from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
)
from opentelemetry.trace import (
    NonRecordingSpan,
    Span,
    SpanContext,
    SpanKind,
    Status,
    StatusCode,
    TraceFlags,
)
from opentelemetry.util.types import AttributeValue

from aecontrol.tracing import (
    ActiveSpan,
    TraceContext,
    parse_traceparent,
    set_span_backend,
    shutdown_span_backend,
)

SUPPORTED_PROTOCOL = "http/protobuf"


@dataclass(frozen=True)
class TelemetryConfiguration:
    enabled: bool
    mode: str
    protocol: str | None = None
    endpoint_host: str | None = None


@dataclass(frozen=True)
class _OpenTelemetryState:
    span: Span
    token: Token[Context]


def _package_version() -> str:
    try:
        return version("aecontrol")
    except PackageNotFoundError:
        return "development"


def _is_true(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


def telemetry_configuration_from_environment(
    environment: Mapping[str, str] | None = None,
) -> TelemetryConfiguration:
    env = environment if environment is not None else os.environ
    if _is_true(env.get("OTEL_SDK_DISABLED")):
        return TelemetryConfiguration(enabled=False, mode="json-log")

    traces_endpoint = env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "").strip()
    base_endpoint = env.get("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip()
    endpoint = traces_endpoint or base_endpoint
    if not endpoint:
        return TelemetryConfiguration(enabled=False, mode="json-log")

    protocol = (
        (
            env.get("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
            or env.get("OTEL_EXPORTER_OTLP_PROTOCOL")
            or SUPPORTED_PROTOCOL
        )
        .strip()
        .lower()
    )
    if protocol != SUPPORTED_PROTOCOL:
        raise ValueError(
            "AgentEval supports OTLP trace export over http/protobuf; "
            f"received protocol {protocol!r}"
        )

    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("OTLP endpoint must be an absolute HTTP(S) URL")
    return TelemetryConfiguration(
        enabled=True,
        mode="otlp/http",
        protocol=protocol,
        endpoint_host=parsed.hostname,
    )


class OpenTelemetrySpanBackend:
    def __init__(
        self,
        exporter: SpanExporter | None = None,
        *,
        service_name: str = "aecontrol",
        batch: bool = True,
    ) -> None:
        resource = Resource.create(
            {
                "service.name": service_name,
                "service.version": _package_version(),
            }
        )
        self._provider = TracerProvider(resource=resource)
        processor = (
            BatchSpanProcessor(exporter or OTLPSpanExporter())
            if batch
            else SimpleSpanProcessor(exporter or OTLPSpanExporter())
        )
        self._provider.add_span_processor(processor)
        self._tracer = self._provider.get_tracer("aecontrol")

    def start(self, name: str, parent: str | None, attributes: dict[str, object]) -> ActiveSpan:
        parent_context = None
        parsed_parent = parse_traceparent(parent)
        if parsed_parent is not None:
            span_context = SpanContext(
                trace_id=int(parsed_parent.trace_id, 16),
                span_id=int(parsed_parent.span_id, 16),
                is_remote=True,
                trace_flags=TraceFlags(int(parsed_parent.flags, 16)),
            )
            parent_context = trace.set_span_in_context(NonRecordingSpan(span_context))

        otel_span = self._tracer.start_span(
            name,
            context=parent_context,
            kind=_span_kind(name),
            attributes=_semantic_attributes(attributes),
        )
        context = otel_span.get_span_context()
        token = otel_context.attach(trace.set_span_in_context(otel_span))
        return ActiveSpan(
            TraceContext(
                trace_id=f"{context.trace_id:032x}",
                span_id=f"{context.span_id:016x}",
                flags=f"{int(context.trace_flags):02x}",
                parent_span_id=parsed_parent.span_id if parsed_parent else None,
            ),
            _OpenTelemetryState(otel_span, token),
        )

    def finish(self, active: ActiveSpan, outcome: str, error: BaseException | None) -> None:
        if not isinstance(active.state, _OpenTelemetryState):
            return
        otel_span = active.state.span
        try:
            otel_span.set_attribute("aecontrol.outcome", outcome)
            if error is not None:
                otel_span.set_status(Status(StatusCode.ERROR, type(error).__name__))
            otel_span.end()
        finally:
            otel_context.detach(active.state.token)

    def shutdown(self) -> None:
        self._provider.shutdown()


def _span_kind(name: str) -> SpanKind:
    if name == "http.request":
        return SpanKind.SERVER
    if name == "evaluation.job":
        return SpanKind.CONSUMER
    return SpanKind.INTERNAL


def _semantic_attributes(attributes: Mapping[str, object]) -> dict[str, AttributeValue]:
    names = {
        "method": "http.request.method",
        "path": "url.path",
        "job_id": "aecontrol.job.id",
        "worker_id": "aecontrol.worker.id",
        "agent_version": "aecontrol.agent.version",
    }
    sanitized: dict[str, AttributeValue] = {}
    for key, value in attributes.items():
        if _is_attribute_value(value):
            sanitized[names.get(key, f"aecontrol.{key}")] = cast(AttributeValue, value)
    return sanitized


def _is_attribute_value(value: object) -> bool:
    if isinstance(value, (bool, str, bytes, int, float)):
        return True
    return (
        isinstance(value, Sequence)
        and not isinstance(value, str)
        and all(isinstance(item, (bool, str, bytes, int, float)) for item in value)
    )


def configure_telemetry_from_environment() -> TelemetryConfiguration:
    configuration = telemetry_configuration_from_environment()
    shutdown_span_backend()
    if not configuration.enabled:
        return configuration
    service_name = os.getenv("OTEL_SERVICE_NAME", "aecontrol").strip() or "aecontrol"
    set_span_backend(OpenTelemetrySpanBackend(service_name=service_name))
    return configuration


def shutdown_telemetry() -> None:
    shutdown_span_backend()


def record_http_response(status_code: int) -> None:
    current_span = trace.get_current_span()
    current_span.set_attribute("http.response.status_code", status_code)
    if status_code >= 500:
        current_span.set_status(Status(StatusCode.ERROR))
