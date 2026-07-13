from __future__ import annotations

import json
import logging
import re
import secrets
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Protocol

TRACEPARENT_PATTERN = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
trace_logger = logging.getLogger("uvicorn.error.aecontrol.traces")
_current_traceparent: ContextVar[str | None] = ContextVar("traceparent", default=None)


@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    span_id: str
    flags: str = "01"
    parent_span_id: str | None = None

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{self.flags}"


def parse_traceparent(value: str | None) -> TraceContext | None:
    if not value:
        return None
    match = TRACEPARENT_PATTERN.fullmatch(value.strip().lower())
    if match is None or match[1] == "0" * 32 or match[2] == "0" * 16:
        return None
    return TraceContext(match[1], match[2], match[3])


def new_trace(parent: str | None = None) -> TraceContext:
    parsed = parse_traceparent(parent)
    return TraceContext(
        parsed.trace_id if parsed else secrets.token_hex(16),
        secrets.token_hex(8),
        parsed.flags if parsed else "01",
        parsed.span_id if parsed else None,
    )


@dataclass(frozen=True)
class ActiveSpan:
    context: TraceContext
    state: object | None = None


class SpanBackend(Protocol):
    def start(self, name: str, parent: str | None, attributes: dict[str, object]) -> ActiveSpan: ...

    def finish(self, active: ActiveSpan, outcome: str, error: BaseException | None) -> None: ...

    def shutdown(self) -> None: ...


class LocalSpanBackend:
    def start(self, name: str, parent: str | None, attributes: dict[str, object]) -> ActiveSpan:
        del name, attributes
        return ActiveSpan(new_trace(parent))

    def finish(self, active: ActiveSpan, outcome: str, error: BaseException | None) -> None:
        del active, outcome, error

    def shutdown(self) -> None:
        pass


_backend_lock = threading.Lock()
_span_backend: SpanBackend = LocalSpanBackend()


def set_span_backend(backend: SpanBackend) -> SpanBackend:
    global _span_backend
    with _backend_lock:
        previous = _span_backend
        _span_backend = backend
    return previous


def reset_span_backend() -> None:
    set_span_backend(LocalSpanBackend())


def shutdown_span_backend() -> None:
    global _span_backend
    with _backend_lock:
        backend = _span_backend
        _span_backend = LocalSpanBackend()
    try:
        backend.shutdown()
    except Exception:
        trace_logger.exception("trace backend failed to shut down")


def current_traceparent() -> str | None:
    return _current_traceparent.get()


def attach_trace(traceparent: str) -> Token[str | None]:
    if parse_traceparent(traceparent) is None:
        raise ValueError("invalid W3C traceparent")
    return _current_traceparent.set(traceparent)


def detach_trace(token: Token[str | None]) -> None:
    _current_traceparent.reset(token)


@contextmanager
def span(name: str, parent: str | None = None, **attributes: object) -> Iterator[TraceContext]:
    resolved_parent = parent or current_traceparent()
    backend = _span_backend
    try:
        active = backend.start(name, resolved_parent, attributes)
    except Exception:
        trace_logger.exception("trace backend failed to start span; using local context")
        backend = LocalSpanBackend()
        active = backend.start(name, resolved_parent, attributes)
    context = active.context
    token = attach_trace(context.traceparent)
    started = time.perf_counter()
    outcome = "ok"
    caught_error: BaseException | None = None
    try:
        yield context
    except BaseException as error:
        outcome = "error"
        caught_error = error
        raise
    finally:
        try:
            backend.finish(active, outcome, caught_error)
        except Exception:
            trace_logger.exception("trace backend failed to finish span")
        trace_logger.info(
            json.dumps(
                {
                    "event": "span",
                    "name": name,
                    "trace_id": context.trace_id,
                    "span_id": context.span_id,
                    "parent_span_id": context.parent_span_id,
                    "outcome": outcome,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    **attributes,
                },
                separators=(",", ":"),
            )
        )
        detach_trace(token)
