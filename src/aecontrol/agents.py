from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import ClassVar, Protocol, cast

from aecontrol.models import AgentVersion, DatasetCase
from aecontrol.sandbox import fixed_source, insecure_security_source

BASELINE_VERSION = AgentVersion(
    name="coding-repair-agent",
    version="baseline",
    description="Deterministic reference agent that applies the expected minimal repair.",
)
REGRESSED_VERSION = AgentVersion(
    name="coding-repair-agent",
    version="candidate_regressed",
    description=(
        "Candidate with a subtle security validation regression on two critical cases while "
        "retaining similar aggregate performance."
    ),
)
FIXED_VERSION = AgentVersion(
    name="coding-repair-agent",
    version="candidate_fixed",
    description="Corrected candidate that restores validation behavior on the critical slice.",
)


class CodingRepairAgent(Protocol):
    version: AgentVersion

    def repair(self, case: DatasetCase) -> str: ...


@dataclass(frozen=True)
class BaselineCodingAgent:
    version: ClassVar[AgentVersion] = BASELINE_VERSION

    def repair(self, case: DatasetCase) -> str:
        return fixed_source(case)


@dataclass(frozen=True)
class RegressedCodingAgent:
    version: ClassVar[AgentVersion] = REGRESSED_VERSION

    def repair(self, case: DatasetCase) -> str:
        if case.case_id in {"SEC-01", "SEC-04"}:
            return insecure_security_source(case)
        return fixed_source(case)


@dataclass(frozen=True)
class FixedCodingAgent:
    version: ClassVar[AgentVersion] = FIXED_VERSION

    def repair(self, case: DatasetCase) -> str:
        return fixed_source(case)


AGENT_FACTORIES: dict[str, Callable[[], CodingRepairAgent]] = {
    "baseline": cast(Callable[[], CodingRepairAgent], BaselineCodingAgent),
    "candidate_regressed": cast(Callable[[], CodingRepairAgent], RegressedCodingAgent),
    "candidate_fixed": cast(Callable[[], CodingRepairAgent], FixedCodingAgent),
}


def get_coding_agent(version: str) -> CodingRepairAgent:
    try:
        return AGENT_FACTORIES[version]()
    except KeyError as exc:
        known = ", ".join(sorted(AGENT_FACTORIES))
        msg = f"unknown coding agent version {version!r}; expected one of: {known}"
        raise KeyError(msg) from exc


def list_agent_versions() -> list[AgentVersion]:
    return [factory().version for _, factory in sorted(AGENT_FACTORIES.items())]
