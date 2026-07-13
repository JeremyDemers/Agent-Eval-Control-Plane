from __future__ import annotations

import json
import logging
import re
import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass

TRACEPARENT_PATTERN = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
trace_logger = logging.getLogger("uvicorn.error.aecontrol.traces")
_current_traceparent: ContextVar[str | None] = ContextVar("traceparent", default=None)


@dataclass(frozen=True)
class TraceContext:
    trace_id: str
    span_id: str
    flags: str = "01"

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
    return TraceContext(parsed.trace_id if parsed else secrets.token_hex(16), secrets.token_hex(8))


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
    context = new_trace(parent or current_traceparent())
    token = attach_trace(context.traceparent)
    started = time.perf_counter()
    outcome = "ok"
    try:
        yield context
    except Exception:
        outcome = "error"
        raise
    finally:
        trace_logger.info(
            json.dumps(
                {
                    "event": "span",
                    "name": name,
                    "trace_id": context.trace_id,
                    "span_id": context.span_id,
                    "outcome": outcome,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                    **attributes,
                },
                separators=(",", ":"),
            )
        )
        detach_trace(token)
