from __future__ import annotations

from importlib.metadata import entry_points
from typing import ClassVar, Protocol, TypeVar

from aecontrol.models import AgentInput, AgentOutput, DatasetCase, EvaluationResult


class ExecutionContext(Protocol):
    @property
    def agent_version(self) -> str: ...


class RuntimeAdapter(Protocol):
    name: ClassVar[str]

    async def execute(self, request: AgentInput, context: ExecutionContext) -> AgentOutput: ...


class Evaluator(Protocol):
    name: ClassVar[str]

    async def evaluate(self, case: DatasetCase, execution: AgentOutput) -> EvaluationResult: ...


T = TypeVar("T")


class PluginRegistry[T]:
    def __init__(self) -> None:
        self._items: dict[str, T] = {}

    def register(self, name: str, item: T) -> T:
        if name in self._items:
            msg = f"plugin already registered: {name}"
            raise ValueError(msg)
        self._items[name] = item
        return item

    def get(self, name: str) -> T:
        try:
            return self._items[name]
        except KeyError as exc:
            msg = f"unknown plugin: {name}"
            raise KeyError(msg) from exc

    def list(self) -> list[str]:
        return sorted(self._items)

    def discover_entry_points(self, group: str) -> None:
        for entry_point in entry_points(group=group):
            plugin = entry_point.load()
            name = getattr(plugin, "name", entry_point.name)
            self.register(str(name), plugin)
