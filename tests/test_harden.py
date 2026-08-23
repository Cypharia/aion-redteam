"""Tests for `aion-redteam harden` — policy and regression-test generation."""

from __future__ import annotations

import ast
from datetime import datetime
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from aion_redteam.cli.main import app
from aion_redteam.core.harden import (
    generate_policies,
    generate_regression_tests,
    write_artifacts,
)
from aion_redteam.core.result import (
    RunResult,
    ScenarioResult,
    SingleRunDetail,
    Verdict,
)
from aion_redteam.core.scenario import (
    Criterion,
    CriterionTarget,
    CriterionType,
    OwaspCategory,
    Severity,
)
from aion_redteam.core.target import ToolCall

runner = CliRunner()

TOOL_CRITERION = Criterion(
    type=CriterionType.TOOL_CALL_CHECK,
    target=CriterionTarget.TOOL_CALLS,
    name_pattern="shell|exec|command",
    argument_patterns={"command": r"rm\s+-rf"},
)
TEXT_CRITERION = Criterion(
    type=CriterionType.REGEX, pattern=r"rm\s+-rf", flags=["IGNORECASE"]
)


def _scenario_result(
    scenario_id: str,
    verdict: Verdict,
    matched: Criterion | None,
    *,
    severity: Severity = Severity.CRITICAL,
    tool_calls: list[ToolCall] | None = None,
) -> ScenarioResult:
    """Build a ScenarioResult whose single run matched ``matched``."""
    succeeded = verdict in (Verdict.FAIL, Verdict.FLAKY)
    detail = SingleRunDetail(
        run_index=0,
        attack_succeeded=succeeded,
        matched_criteria=[0] if matched else [],
        matched_criteria_detail=[matched] if matched else [],
        tool_calls=tool_calls or [],
        agent_response="whatever the agent said",
    )
    return ScenarioResult(
        scenario_id=scenario_id,
        scenario_name=f"{scenario_id} display name",
        owasp_category=OwaspCategory.ASI02,
        severity=severity,
        verdict=verdict,
        success_rate=1.0 if succeeded else 0.0,
        num_runs=1,
        run_details=[detail],
    )


def _run_result(*scenario_results: ScenarioResult) -> RunResult:
    """Wrap scenario results in a RunResult with a fixed timestamp."""
    return RunResult(
        target_name="agent.py",
        adapter="langgraph",
        timestamp=datetime(2026, 8, 23, 22, 31, 0),
        total_scenarios=len(scenario_results),
        scenario_results=list(scenario_results),
    )


class TestGeneratePolicies:
    def test_tool_call_failure_becomes_a_deny_policy(self) -> None:
        result = _run_result(
            _scenario_result(
                "ASI02-001",
                Verdict.FAIL,
                TOOL_CRITERION,
                tool_calls=[ToolCall(name="run_shell", arguments={"command": "rm -rf ./p"})],
            )
        )
        policies, skipped = generate_policies(result)

        assert skipped == []
        assert len(policies) == 1
        policy = policies[0]
        assert policy.id == "POL-ASI02-001"
        assert policy.derived_from == "ASI02-001"
        assert policy.rule.effect == "deny"
        assert policy.rule.on == "tool_call"
        assert policy.rule.match.tool_name_pattern == "shell|exec|command"
        assert policy.rule.match.argument_patterns == {"command": r"rm\s+-rf"}

    def test_evidence_quotes_the_real_invocation(self) -> None:
        result = _run_result(
            _scenario_result(
                "ASI02-001",
                Verdict.FAIL,
                TOOL_CRITERION,
                tool_calls=[ToolCall(name="run_shell", arguments={"command": "rm -rf ./p"})],
            )
        )
        policies, _ = generate_policies(result)
        evidence = policies[0].provenance.evidence
        assert "run_shell" in evidence
        assert "rm -rf ./p" in evidence
        assert "1/1 runs" in evidence

    def test_text_only_failure_is_skipped_with_a_reason(self) -> None:
        result = _run_result(_scenario_result("ASI09-001", Verdict.FAIL, TEXT_CRITERION))
        policies, skipped = generate_policies(result)

        assert policies == []
        assert len(skipped) == 1
        assert skipped[0].scenario_id == "ASI09-001"
        assert "text-only" in skipped[0].reason

    def test_passing_scenario_produces_nothing(self) -> None:
        result = _run_result(_scenario_result("ASI02-001", Verdict.PASS, None))
        policies, skipped = generate_policies(result)
        assert policies == []
        assert skipped == []

    def test_flaky_findings_are_hardened_too(self) -> None:
        result = _run_result(
            _scenario_result("ASI02-001", Verdict.FLAKY, TOOL_CRITERION)
        )
        policies, _ = generate_policies(result)
        assert len(policies) == 1

    def test_exact_name_criterion_is_escaped_into_a_pattern(self) -> None:
        exact = Criterion(type=CriterionType.TOOL_CALL_CHECK, value="run.shell")
        result = _run_result(_scenario_result("ASI02-001", Verdict.FAIL, exact))
        policies, _ = generate_policies(result)
        # The '.' must not survive as a regex wildcard when it came from a literal name.
        assert policies[0].rule.match.tool_name_pattern == r"run\.shell"


class TestGenerateRegressionTests:
    def test_generated_module_is_valid_python(self) -> None:
        result = _run_result(
            _scenario_result("ASI02-001", Verdict.FAIL, TOOL_CRITERION),
            _scenario_result("ASI05-001", Verdict.FLAKY, TOOL_CRITERION),
        )
        src = generate_regression_tests(result)
        ast.parse(src)  # raises SyntaxError if the generator emitted junk

    def test_one_test_per_finding(self) -> None:
        result = _run_result(
            _scenario_result("ASI02-001", Verdict.FAIL, TOOL_CRITERION),
            _scenario_result("ASI05-001", Verdict.FLAKY, TOOL_CRITERION),
            _scenario_result("ASI03-001", Verdict.PASS, None),
        )
        tree = ast.parse(generate_regression_tests(result))
        tests = [
            n.name
            for n in ast.walk(tree)
            if isinstance(n, ast.AsyncFunctionDef) and n.name.startswith("test_")
        ]
        assert len(tests) == 2
        assert any("asi02_001" in t for t in tests)
        assert any("asi05_001" in t for t in tests)

    def test_text_only_findings_still_get_a_regression_test(self) -> None:
        """A finding with no enforceable policy is still worth pinning."""
        result = _run_result(_scenario_result("ASI09-001", Verdict.FAIL, TEXT_CRITERION))
        tree = ast.parse(generate_regression_tests(result))
        tests = [
            n.name
            for n in ast.walk(tree)
            if isinstance(n, ast.AsyncFunctionDef) and n.name.startswith("test_")
        ]
        assert len(tests) == 1

    def test_module_with_no_findings_is_still_valid(self) -> None:
        result = _run_result(_scenario_result("ASI02-001", Verdict.PASS, None))
        ast.parse(generate_regression_tests(result))


class TestWriteArtifacts:
    def test_policy_file_round_trips_through_yaml(self, tmp_path: Path) -> None:
        result = _run_result(
            _scenario_result(
                "ASI02-001",
                Verdict.FAIL,
                TOOL_CRITERION,
                tool_calls=[ToolCall(name="run_shell", arguments={"command": "rm -rf ./p"})],
            )
        )
        policies, _ = generate_policies(result)
        written, tests_path = write_artifacts(
            policies, "# tests\n", tmp_path / "aion_policies", tmp_path / "t.py"
        )

        assert len(written) == 1
        assert written[0].name == "ASI02-001.policy.yaml"
        loaded = yaml.safe_load(written[0].read_text(encoding="utf-8"))
        assert loaded["id"] == "POL-ASI02-001"
        assert loaded["rule"]["effect"] == "deny"
        # The regex must survive serialization with its backslashes intact.
        assert loaded["rule"]["match"]["argument_patterns"]["command"] == r"rm\s+-rf"
        assert tests_path is not None

    def test_existing_test_file_is_not_clobbered(self, tmp_path: Path) -> None:
        tests_path = tmp_path / "test_aion_regressions.py"
        tests_path.write_text("# hand-edited by a human\n", encoding="utf-8")

        _, written_path = write_artifacts([], "# generated\n", tmp_path / "pol", tests_path)

        assert written_path is None
        assert tests_path.read_text(encoding="utf-8") == "# hand-edited by a human\n"

    def test_force_overwrites_the_test_file(self, tmp_path: Path) -> None:
        tests_path = tmp_path / "test_aion_regressions.py"
        tests_path.write_text("# hand-edited by a human\n", encoding="utf-8")

        _, written_path = write_artifacts(
            [], "# generated\n", tmp_path / "pol", tests_path, force=True
        )

        assert written_path == tests_path
        assert tests_path.read_text(encoding="utf-8") == "# generated\n"


class TestHardenCLI:
    @pytest.fixture
    def results_file(self, tmp_path: Path) -> Path:
        result = _run_result(
            _scenario_result(
                "ASI02-001",
                Verdict.FAIL,
                TOOL_CRITERION,
                tool_calls=[ToolCall(name="run_shell", arguments={"command": "rm -rf ./p"})],
            ),
            _scenario_result("ASI09-001", Verdict.FAIL, TEXT_CRITERION),
        )
        path = tmp_path / "last_run.json"
        path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        return path

    def test_generates_policies_and_tests(self, results_file: Path, tmp_path: Path) -> None:
        out = runner.invoke(
            app,
            [
                "harden",
                "--from", str(results_file),
                "--policy-dir", str(tmp_path / "aion_policies"),
                "--tests-out", str(tmp_path / "tests" / "test_aion_regressions.py"),
            ],
        )
        assert out.exit_code == 0, out.stdout
        assert (tmp_path / "aion_policies" / "ASI02-001.policy.yaml").is_file()
        assert (tmp_path / "tests" / "test_aion_regressions.py").is_file()
        # The text-only finding is reported as skipped, not silently dropped.
        assert "1 findings skipped" in out.stdout

    def test_dry_run_writes_nothing(self, results_file: Path, tmp_path: Path) -> None:
        policy_dir = tmp_path / "aion_policies"
        out = runner.invoke(
            app,
            [
                "harden",
                "--from", str(results_file),
                "--policy-dir", str(policy_dir),
                "--tests-out", str(tmp_path / "t.py"),
                "--dry-run",
            ],
        )
        assert out.exit_code == 0, out.stdout
        assert "would write" in out.stdout
        assert not policy_dir.exists()
        assert not (tmp_path / "t.py").exists()

    def test_exit_1_when_nothing_is_hardenable(self, tmp_path: Path) -> None:
        result = _run_result(_scenario_result("ASI09-001", Verdict.FAIL, TEXT_CRITERION))
        path = tmp_path / "last_run.json"
        path.write_text(result.model_dump_json(), encoding="utf-8")

        out = runner.invoke(app, ["harden", "--from", str(path)])
        assert out.exit_code == 1

    def test_exit_2_when_results_file_is_missing(self, tmp_path: Path) -> None:
        out = runner.invoke(app, ["harden", "--from", str(tmp_path / "nope.json")])
        assert out.exit_code == 2

    def test_exit_2_when_results_file_is_malformed(self, tmp_path: Path) -> None:
        path = tmp_path / "junk.json"
        path.write_text("{not json at all", encoding="utf-8")
        out = runner.invoke(app, ["harden", "--from", str(path)])
        assert out.exit_code == 2
