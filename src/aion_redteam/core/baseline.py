"""Baselines: gate CI on regressions rather than on absolute state.

``run`` exits non-zero whenever anything fails. Against a real agent something always
fails, so a team that wires the harness into CI on day one has a permanently red build
and turns the gate off in week two. A dead gate catches nothing.

A baseline records the verdicts a target is *known* to produce. Comparing a run against
it separates "this was already broken" from "this just broke", which is the distinction
CI actually needs. Fix the known failures over time; block on the new ones today.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field, ValidationError

from aion_redteam.core.result import RunResult, Verdict
from aion_redteam.core.scenario import Severity

# Verdicts that count as a finding. ERROR and TIMEOUT are harness/infrastructure noise,
# not evidence about the agent, so they never make something a regression.
FINDING_VERDICTS = frozenset({Verdict.FAIL, Verdict.FLAKY})

# Ordering for --fail-on thresholds.
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class Baseline(BaseModel):
    """The verdicts a target is known to produce, as of some accepted run."""

    created_at: datetime = Field(default_factory=datetime.now)
    target_name: str
    adapter: str
    scenario_verdicts: dict[str, Verdict] = Field(default_factory=dict)

    @classmethod
    def from_result(cls, result: RunResult) -> Baseline:
        """Build a baseline capturing every scenario verdict in ``result``."""
        return cls(
            target_name=result.target_name,
            adapter=result.adapter,
            scenario_verdicts={
                s.scenario_id: s.verdict for s in result.scenario_results
            },
        )


class BaselineDiff(BaseModel):
    """What changed between a run and its baseline."""

    new_failures: list[str] = Field(default_factory=list)
    fixed: list[str] = Field(default_factory=list)
    unchanged: list[str] = Field(default_factory=list)
    # Scenarios the baseline has never seen. Failing ones are reported separately
    # rather than counted as regressions: a scenario added since the baseline was
    # accepted was never passing, so it did not regress.
    new_scenarios: list[str] = Field(default_factory=list)

    @property
    def has_regressions(self) -> bool:
        """Whether any scenario went from passing to failing."""
        return bool(self.new_failures)


def load_baseline(path: Path) -> Baseline | None:
    """Load a baseline file.

    Args:
        path: Path to a baseline JSON file.

    Returns:
        The baseline, or ``None`` when the file does not exist — an absent baseline is
        a normal first-run state, not an error.

    Raises:
        ValueError: If the file exists but cannot be parsed as a baseline.
    """
    if not path.is_file():
        return None
    try:
        return Baseline.model_validate_json(path.read_text(encoding="utf-8"))
    except ValidationError as exc:
        raise ValueError(f"{path} is not a valid baseline file: {exc}") from exc


def compare(result: RunResult, baseline: Baseline) -> BaselineDiff:
    """Compare a run against a baseline.

    Args:
        result: The run just completed.
        baseline: The accepted reference verdicts.

    Returns:
        The :class:`BaselineDiff` between them.
    """
    diff = BaselineDiff()
    for scenario in result.scenario_results:
        now_failing = scenario.verdict in FINDING_VERDICTS
        known = baseline.scenario_verdicts.get(scenario.scenario_id)

        if known is None:
            diff.new_scenarios.append(scenario.scenario_id)
            continue

        was_failing = known in FINDING_VERDICTS
        if now_failing and not was_failing:
            diff.new_failures.append(scenario.scenario_id)
        elif was_failing and not now_failing:
            diff.fixed.append(scenario.scenario_id)
        else:
            diff.unchanged.append(scenario.scenario_id)
    return diff


def at_or_above(result: RunResult, scenario_ids: list[str], threshold: Severity) -> list[str]:
    """Filter scenario ids down to those at or above a severity threshold.

    Args:
        result: The run the ids came from, used to look up each severity.
        scenario_ids: Ids to filter.
        threshold: Minimum severity to keep.

    Returns:
        The subset of ``scenario_ids`` whose severity meets ``threshold``.
    """
    severities = {s.scenario_id: s.severity for s in result.scenario_results}
    minimum = _SEVERITY_ORDER[threshold]
    return [
        sid
        for sid in scenario_ids
        if sid in severities and _SEVERITY_ORDER[severities[sid]] >= minimum
    ]


__all__ = [
    "FINDING_VERDICTS",
    "Baseline",
    "BaselineDiff",
    "at_or_above",
    "compare",
    "load_baseline",
]
