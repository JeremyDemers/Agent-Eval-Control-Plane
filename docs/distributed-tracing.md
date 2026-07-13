# Distributed Tracing

AgentEval accepts and emits the W3C `traceparent` header. Valid inbound trace IDs and sampling flags
are preserved while the API creates a directly parented server span. Invalid or unsupported headers
start a new version `00` trace.

Queued evaluations persist both `traceparent` and `X-Request-ID` in PostgreSQL. A worker creates a
consumer span as a child of that durable context, preserving correlation across process boundaries,
queue delay, and lease retries.

```text
client span -> HTTP server span -> PostgreSQL job -> worker evaluation span
```

## OTLP Export

JSON span logging remains the zero-configuration default. Set a standard OTLP endpoint to enable the
OpenTelemetry SDK's batched OTLP/HTTP protobuf exporter in both API and worker processes:

```bash
export OTEL_SERVICE_NAME=aecontrol
export OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
uv run aecontrol worker
```

`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` overrides the generic endpoint. The generic endpoint is treated
as a base URL and the exporter appends `/v1/traces`; the trace-specific endpoint is used as supplied.
Standard `OTEL_EXPORTER_OTLP_HEADERS`, timeout, certificate, compression, and batch processor
variables are handled by the OpenTelemetry exporter. Set `OTEL_SDK_DISABLED=true` to force the local
JSON-log backend.

`uv run aecontrol doctor` reports only the exporter mode and destination hostname. It never prints
endpoint credentials or headers. Exported attributes are deliberately bounded to request method and
path plus job, worker, agent-version, and outcome metadata. Request bodies, prompts, trajectories,
exception messages, authorization headers, and OTLP credentials are excluded. Export failures do not
fail evaluations, and normal API/worker shutdown flushes the batch processor.

Trace context is diagnostic metadata, not an authentication or authorization mechanism.
