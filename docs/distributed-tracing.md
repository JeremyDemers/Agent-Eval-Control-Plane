# Distributed Tracing

AgentEval accepts and emits the W3C `traceparent` header. Valid inbound trace IDs are preserved while
the API creates a new server span. Invalid or unsupported headers are ignored and replaced with a new
version `00` context.

Queued evaluations persist both `traceparent` and `X-Request-ID` in PostgreSQL. A worker creates its
evaluation span as a child of that durable context, preserving correlation even when execution occurs
in another process or after a lease retry. Structured span records include trace ID, span ID, duration,
outcome, job ID, worker ID, and agent version.

```text
client span -> HTTP server span -> PostgreSQL job -> worker evaluation span
```

The implementation deliberately has no mandatory collector dependency. Local runs write JSON span
records through Python logging; production process supervisors can route them to the same log backend
as request events. An OpenTelemetry collector/exporter adapter remains a roadmap item. Trace context
is diagnostic metadata, not an authentication or authorization mechanism.
