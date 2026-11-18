"""Turn findings into enforceable policies and regression tests.

A red-team report tells you an agent is vulnerable. It does not stop the vulnerability
coming back. :func:`generate_policies` inverts each tool-call finding into a rule a
runtime can enforce, and :func:`generate_regression_tests` writes the pytest module that
fails if the finding returns.

**This module generates files. It enforces nothing.** It does not run an agent and does
not call an LLM. The schema and its rationale live in ``docs/policy_schema.md``.

Only findings whose matched criteria include a ``tool_call_check`` can produce a policy:
the inversion is mechanical only when both sides describe the same observable event (a
tool call about to happen). A text-only finding has no counterpart a tool gate can
evaluate, so it is skipped with a recorded reason rather than turned into a rule that
cannot be enforced.
"""

from __future__ import annotations

import keyword
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from aion_redteam import __version__
from aion_redteam.core.result import RunResult, ScenarioResult, Verdict
from aion_redteam.core.scenario import Criterion, CriterionType, OwaspCategory, Severity
from aion_redteam.core.target import ToolCall

# Verdicts that represent a demonstrated vulnerability worth hardening against.
HARDENABLE_VERDICTS = frozenset({Verdict.FAIL, Verdict.FLAKY})


class PolicyMatch(BaseModel):
    """What a rule fires on — the inversion of a ``tool_call_check`` criterion."""

    tool_name_pattern: str
    argument_patterns: dict[str, str] | None = None


class PolicyRule(BaseModel):
    """The enforceable part of a policy."""

    effect: Literal["deny", "require_approval", "log"] = "deny"
    on: Literal["tool_call", "prompt", "response"] = "tool_call"
    match: PolicyMatch
    message: str


class PolicyProvenance(BaseModel):
    """Where a policy came from, so a blocked call in production can be explained."""

    generated_by: str
    scenario_id: str
    run_timestamp: datetime
    evidence: str
    success_rate: float


class Policy(BaseModel):
    """A single generated policy, serialized one per file."""

    id: str
    derived_from: str
    owasp_category: OwaspCategory
    severity: Severity
    rule: PolicyRule
    provenance: PolicyProvenance


class SkippedFinding(BaseModel):
    """A finding that could not become a policy, and why."""

    scenario_id: str
    reason: str


def generate_policies(result: RunResult) -> tuple[list[Policy], list[SkippedFinding]]:
    """Derive enforceable policies from a run's findings.

    Args:
        result: A completed run.

    Returns:
        ``(policies, skipped)`` — one policy per hardenable finding whose matched
        criteria include a ``tool_call_check``, and a record of every finding that
        could not produce one.
    """
    policies: list[Policy] = []
    skipped: list[SkippedFinding] = []

    for scenario in result.scenario_results:
        if scenario.verdict not in HARDENABLE_VERDICTS:
            continue
        criterion = _matched_tool_criterion(scenario)
        if criterion is None:
            skipped.append(
                SkippedFinding(
                    scenario_id=scenario.scenario_id,
                    reason="text-only criteria, no enforceable rule",
                )
            )
            continue
        policies.append(
            Policy(
                id=f"POL-{scenario.scenario_id}",
                derived_from=scenario.scenario_id,
                owasp_category=scenario.owasp_category,
                severity=scenario.severity,
                rule=PolicyRule(
                    # Always deny: every policy here comes from an attack that really
                    # worked. Downgrading to require_approval or log is a human call,
                    # which is why `severity` is carried through.
                    effect="deny",
                    on="tool_call",
                    match=PolicyMatch(
                        tool_name_pattern=(
                            criterion.name_pattern or re.escape(criterion.value or "")
                        ),
                        argument_patterns=criterion.argument_patterns,
                    ),
                    message=(
                        f"{scenario.scenario_name} blocked by AION policy "
                        f"POL-{scenario.scenario_id}"
                    ),
                ),
                provenance=PolicyProvenance(
                    generated_by=f"aion-redteam harden v{__version__}",
                    scenario_id=scenario.scenario_id,
                    run_timestamp=result.timestamp,
                    evidence=_evidence(scenario),
                    success_rate=scenario.success_rate,
                ),
            )
        )
    return policies, skipped


def generate_regression_tests(result: RunResult) -> str:
    """Render a pytest module that fails if any current finding comes back.

    Args:
        result: A completed run.

    Returns:
        Python source for a test module, one test per hardenable finding.
    """
    findings = [s for s in result.scenario_results if s.verdict in HARDENABLE_VERDICTS]
    lines = [
        '"""Regression tests generated by `aion-redteam harden`.',
        "",
        f"Generated from a run against {result.target_name!r} via the "
        f"{result.adapter!r} adapter",
        f"on {result.timestamp.isoformat(timespec='seconds')}.",
        "",
        "Each test re-runs one scenario that found a vulnerability and asserts the agent",
        "now resists it. They fail until the corresponding policy is actually enforced —",
        "`harden` writes the rule, it does not apply it.",
        "",
        "Safe to edit: `harden` will not overwrite this file without --force.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "import pytest",
        "",
        "from aion_redteam.adapters import get_adapter",
        "from aion_redteam.core.result import Verdict",
        "from aion_redteam.core.runner import Runner",
        "from aion_redteam.core.scenario import ScenarioLoader, bundled_scenarios_dir",
        "",
        f"ADAPTER = {result.adapter!r}",
        f"TARGET = {result.target_name!r}",
        "",
        "",
        "async def _verdict_for(scenario_id: str) -> Verdict:",
        '    """Re-run a single scenario against the target and return its verdict."""',
        "    scenarios = [",
        "        s",
        "        for s in ScenarioLoader(bundled_scenarios_dir()).load_all()",
        "        if s.id == scenario_id",
        "    ]",
        "    if not scenarios:",
        '        pytest.skip(f"scenario {scenario_id} is no longer in the library")',
        "    target = get_adapter(ADAPTER)",
        '    await target.load({"target": TARGET})',
        "    result = await Runner(target, scenarios).run(TARGET, ADAPTER)",
        "    return result.scenario_results[0].verdict",
        "",
    ]
    if not findings:
        lines += [
            "",
            "def test_no_findings_to_regress() -> None:",
            '    """The run this file was generated from produced no findings."""',
        ]
    for scenario in findings:
        lines += [
            "",
            f"async def test_{_test_name(scenario.scenario_id)}() -> None:",
            f'    """{scenario.scenario_name}',
            "",
            f"    Was {scenario.verdict.value} at "
            f"{scenario.success_rate:.0%} success rate when this file was generated.",
            '    """',
            f"    verdict = await _verdict_for({scenario.scenario_id!r})",
            "    assert verdict == Verdict.PASS, (",
            f"        f\"{scenario.scenario_id} is still {{verdict.value}}; \"",
            '        "the policy for it is not being enforced"',
            "    )",
        ]
    return "\n".join(lines) + "\n"


def write_artifacts(
    policies: list[Policy],
    tests_src: str,
    policy_dir: Path,
    tests_path: Path,
    *,
    force: bool = False,
) -> tuple[list[Path], Path | None]:
    """Write policy files and the regression-test module to disk.

    Args:
        policies: Policies to serialize, one YAML file each.
        tests_src: Source of the regression-test module.
        policy_dir: Directory to write policies into; created if absent.
        tests_path: Path of the test module to write.
        force: Overwrite ``tests_path`` if it already exists.

    Returns:
        ``(policy_paths, tests_path_or_None)``. The second element is ``None`` when an
        existing test file was left untouched for want of ``force``.
    """
    policy_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for policy in policies:
        path = policy_dir / f"{policy.derived_from}.policy.yaml"
        path.write_text(_to_yaml(policy), encoding="utf-8")
        written.append(path)

    if tests_path.exists() and not force:
        return written, None
    tests_path.parent.mkdir(parents=True, exist_ok=True)
    tests_path.write_text(tests_src, encoding="utf-8")
    return written, tests_path


# -- internals -----------------------------------------------------------------------


def _matched_tool_criterion(scenario: ScenarioResult) -> Criterion | None:
    """Return the first matched ``tool_call_check`` criterion across the repetitions."""
    for detail in scenario.run_details:
        for criterion in detail.matched_criteria_detail:
            if criterion.type == CriterionType.TOOL_CALL_CHECK:
                return criterion
    return None


def _evidence(scenario: ScenarioResult) -> str:
    """Describe what the agent actually did, for the policy's provenance."""
    successes = scenario.success_count
    total = scenario.num_runs
    call = _first_tool_call(scenario)
    what = (
        f"agent invoked {call.name}({_render_args(call.arguments)})"
        if call is not None
        else "attack succeeded"
    )
    return f"{what} in {successes}/{total} runs"


def _first_tool_call(scenario: ScenarioResult) -> ToolCall | None:
    """The first tool call from a run where the attack succeeded."""
    for detail in scenario.run_details:
        if detail.attack_succeeded and detail.tool_calls:
            return detail.tool_calls[0]
    return None


def _render_args(arguments: dict[str, Any]) -> str:
    """Render tool-call arguments compactly for the evidence line."""
    return ", ".join(f"{k}={v!r}" for k, v in arguments.items())


def _test_name(scenario_id: str) -> str:
    """Turn a scenario id into a valid, readable pytest function-name suffix."""
    name = re.sub(r"\W", "_", scenario_id).lower()
    return f"{name}_stays_fixed" if not keyword.iskeyword(name) else f"{name}_"


def _to_yaml(policy: Policy) -> str:
    """Serialize a policy to YAML.

    Hand-rolled rather than routed through ``yaml.safe_dump`` so the field order matches
    ``docs/policy_schema.md`` and regex values keep their literal backslashes instead of
    being re-escaped. The output is round-trippable by ``yaml.safe_load``.
    """
    match = policy.rule.match
    lines = [
        f"# Generated by {policy.provenance.generated_by} from scenario "
        f"{policy.derived_from}.",
        "# See docs/policy_schema.md. This file describes a rule; it does not enforce it.",
        f"id: {_scalar(policy.id)}",
        f"derived_from: {_scalar(policy.derived_from)}",
        f"owasp_category: {_scalar(policy.owasp_category.value)}",
        f"severity: {_scalar(policy.severity.value)}",
        "rule:",
        f"  effect: {_scalar(policy.rule.effect)}",
        f"  on: {_scalar(policy.rule.on)}",
        "  match:",
        f"    tool_name_pattern: {_scalar(match.tool_name_pattern)}",
    ]
    if match.argument_patterns:
        lines.append("    argument_patterns:")
        lines += [
            f"      {key}: {_scalar(pattern)}"
            for key, pattern in match.argument_patterns.items()
        ]
    lines += [
        f"  message: {_scalar(policy.rule.message)}",
        "provenance:",
        f"  generated_by: {_scalar(policy.provenance.generated_by)}",
        f"  scenario_id: {_scalar(policy.provenance.scenario_id)}",
        f"  run_timestamp: "
        f"{_scalar(policy.provenance.run_timestamp.isoformat(timespec='seconds'))}",
        f"  evidence: {_scalar(policy.provenance.evidence)}",
        f"  success_rate: {policy.provenance.success_rate}",
    ]
    return "\n".join(lines) + "\n"


def _scalar(value: str) -> str:
    """Quote a YAML scalar, escaping what a double-quoted scalar cannot hold literally."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{escaped}"'


__all__ = [
    "HARDENABLE_VERDICTS",
    "Policy",
    "PolicyMatch",
    "PolicyProvenance",
    "PolicyRule",
    "SkippedFinding",
    "generate_policies",
    "generate_regression_tests",
    "write_artifacts",
]
