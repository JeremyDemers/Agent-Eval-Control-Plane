from __future__ import annotations

import asyncio
from pathlib import Path
from typing import cast

import yaml

from aecontrol.datasets import load_jsonl_dataset
from aecontrol.evaluators import EVALUATOR_CLASSES
from aecontrol.models import (
    AgentInput,
    CaseResult,
    DatasetCase,
    EvaluationRun,
    EvaluationSuite,
    utc_now,
)
from aecontrol.plugins import Evaluator
from aecontrol.runtime import DeterministicCodingRuntime, RuntimeContext


def load_suite(path: Path) -> EvaluationSuite:
    data = yaml.safe_load(path.read_text())
    return EvaluationSuite.model_validate(data)


class EvaluationEngine:
    def __init__(self) -> None:
        self._runtime = DeterministicCodingRuntime()
        self._evaluators: dict[str, Evaluator] = {
            cls.name: cast(Evaluator, cls()) for cls in EVALUATOR_CLASSES
        }

    async def run(self, suite: EvaluationSuite, agent_version: str) -> EvaluationRun:
        started = utc_now()
        dataset = load_jsonl_dataset(Path(suite.dataset_path))
        semaphore = asyncio.Semaphore(suite.concurrency)

        async def run_case(case: DatasetCase) -> CaseResult:
            async with semaphore:
                case_started = utc_now()
                request = AgentInput(case_id=case.case_id, variables={"case": case})
                output = await self._runtime.execute(
                    request, RuntimeContext(agent_version=agent_version)
                )
                results = [
                    await self._evaluators[name].evaluate(case, output) for name in suite.evaluators
                ]
                return CaseResult(
                    case=case,
                    agent_version=agent_version,
                    status=output.status,
                    started_at=case_started,
                    completed_at=utc_now(),
                    output=output,
                    evaluator_results=results,
                )

        case_results = await asyncio.gather(*(run_case(case) for case in dataset.cases))
        return EvaluationRun(
            suite_name=suite.name,
            dataset_name=dataset.name,
            dataset_version=dataset.version,
            agent_version=agent_version,
            started_at=started,
            completed_at=utc_now(),
            case_results=list(case_results),
        )
