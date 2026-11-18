"""Tests for baselines — gating CI on regressions rather than on absolute state."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from aion_redteam.cli.main import app
from aion_redteam.core.baseline import Baseline, compare, load_baseline
from aion_redteam.core.result import RunResult, ScenarioResult, Verdict
from aion_redteam.core.scenario import OwaspCategory, Severity

runner = CliRunner()


def _result(**verdicts: tuple[Verdict, Severity]) -> RunResult:
    """Build a RunResult from ``scenario_id=(verdict, severity)`` pairs.

    Scenario ids use underscores as kwargs then convert to the ``ASI01-001`` form.
    """
    results = [
        ScenarioResult(
            scenario_id=sid.replace("_", "-"),
            scenario_name=sid,
            owasp_category=OwaspCategory.ASI02,
            severity=severity,
            verdict=verdict,
            success_rate=1.0 if verdict in (Verdict.FAIL, Verdict.FLAKY) else 0.0,
            num_runs=1,
        )
        for sid, (verdict, severity) in verdicts.items()
    ]
    counts = {v: sum(1 for r in results if r.verdict == v) for v in Verdict}
    return RunResult(
        target_name="agent.py",
        adapter="langgraph",
        total_scenarios=len(results),
        passed=counts[Verdict.PASS],
        failed=counts[Verdict.FAIL],
        flaky=counts[Verdict.FLAKY],
        errors=counts[Verdict.ERROR],
        timeouts=counts[Verdict.TIMEOUT],
        scenario_results=results,
    )


CRIT = Severity.CRITICAL
MED = Severity.MEDIUM


class TestCompare:
    def test_identical_run_is_all_unchanged(self) -> None:
        result = _result(ASI02_001=(Verdict.FAIL, CRIT), ASI03_001=(Verdict.PASS, CRIT))
        diff = compare(result, Baseline.from_result(result))
        assert diff.new_failures == []
        assert diff.fixed == []
        assert sorted(diff.unchanged) == ["ASI02-001", "ASI03-001"]
        assert not diff.has_regressions

    def test_pass_to_fail_is_a_regression(self) -> None:
        baseline = Baseline.from_result(_result(ASI02_001=(Verdict.PASS, CRIT)))
        diff = compare(_result(ASI02_001=(Verdict.FAIL, CRIT)), baseline)
        assert diff.new_failures == ["ASI02-001"]
        assert diff.has_regressions

    def test_fail_to_pass_is_a_fix(self) -> None:
        baseline = Baseline.from_result(_result(ASI02_001=(Verdict.FAIL, CRIT)))
        diff = compare(_result(ASI02_001=(Verdict.PASS, CRIT)), baseline)
        assert diff.fixed == ["ASI02-001"]
        assert not diff.has_regressions

    def test_fail_to_flaky_is_unchanged(self) -> None:
        """Both are findings; churn between them is not a regression."""
        baseline = Baseline.from_result(_result(ASI02_001=(Verdict.FAIL, CRIT)))
        diff = compare(_result(ASI02_001=(Verdict.FLAKY, CRIT)), baseline)
        assert diff.unchanged == ["ASI02-001"]

    def test_scenario_absent_from_baseline_is_new_not_a_regression(self) -> None:
        baseline = Baseline.from_result(_result(ASI02_001=(Verdict.PASS, CRIT)))
        result = _result(ASI02_001=(Verdict.PASS, CRIT), ASI09_001=(Verdict.FAIL, CRIT))
        diff = compare(result, baseline)
        assert diff.new_scenarios == ["ASI09-001"]
        assert diff.new_failures == []
        assert not diff.has_regressions

    def test_errors_are_not_findings(self) -> None:
        """ERROR is harness noise, not evidence about the agent."""
        baseline = Baseline.from_result(_result(ASI02_001=(Verdict.PASS, CRIT)))
        diff = compare(_result(ASI02_001=(Verdict.ERROR, CRIT)), baseline)
        assert diff.new_failures == []
        assert diff.unchanged == ["ASI02-001"]


class TestLoadBaseline:
    def test_missing_file_is_none_not_an_error(self, tmp_path: Path) -> None:
        assert load_baseline(tmp_path / "absent.json") is None

    def test_malformed_file_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "baseline.json"
        path.write_text('{"nope": true}', encoding="utf-8")
        with pytest.raises(ValueError, match="not a valid baseline"):
            load_baseline(path)

    def test_round_trip(self, tmp_path: Path) -> None:
        original = Baseline.from_result(_result(ASI02_001=(Verdict.FAIL, CRIT)))
        path = tmp_path / "baseline.json"
        path.write_text(original.model_dump_json(), encoding="utf-8")
        loaded = load_baseline(path)
        assert loaded is not None
        assert loaded.scenario_verdicts == {"ASI02-001": Verdict.FAIL}


class TestBaselineAcceptCLI:
    def test_accept_writes_a_baseline(self, tmp_path: Path) -> None:
        results = tmp_path / "last_run.json"
        results.write_text(
            _result(
                ASI02_001=(Verdict.FAIL, CRIT), ASI03_001=(Verdict.PASS, CRIT)
            ).model_dump_json(),
            encoding="utf-8",
        )
        out_path = tmp_path / "baseline.json"

        out = runner.invoke(
            app,
            ["baseline", "accept", "--from", str(results), "--output", str(out_path)],
        )
        assert out.exit_code == 0, out.stdout
        loaded = load_baseline(out_path)
        assert loaded is not None
        assert loaded.scenario_verdicts["ASI02-001"] == Verdict.FAIL
        assert "1 known findings" in out.stdout

    def test_accept_exit_2_without_results(self, tmp_path: Path) -> None:
        out = runner.invoke(
            app, ["baseline", "accept", "--from", str(tmp_path / "nope.json")]
        )
        assert out.exit_code == 2


class TestExitCodes:
    """`run`'s gate, exercised through the same helper the command uses."""

    @staticmethod
    def _exit(result: RunResult, baseline_path: Path | None, fail_on: str = "any") -> int:
        from aion_redteam.cli.main import FailOn, _exit_code_for

        return _exit_code_for(result, baseline_path, FailOn(fail_on))

    def _write_baseline(self, tmp_path: Path, result: RunResult) -> Path:
        path = tmp_path / "baseline.json"
        path.write_text(Baseline.from_result(result).model_dump_json(), encoding="utf-8")
        return path

    def test_without_baseline_any_finding_fails(self) -> None:
        assert self._exit(_result(ASI02_001=(Verdict.FAIL, CRIT)), None) == 1
        assert self._exit(_result(ASI02_001=(Verdict.PASS, CRIT)), None) == 0

    def test_unchanged_run_against_baseline_exits_zero(self, tmp_path: Path) -> None:
        """The headline promise: running twice with no changes is green the second time."""
        result = _result(ASI02_001=(Verdict.FAIL, CRIT), ASI03_001=(Verdict.PASS, CRIT))
        assert self._exit(result, self._write_baseline(tmp_path, result)) == 0

    def test_regression_exits_one(self, tmp_path: Path) -> None:
        baseline = self._write_baseline(tmp_path, _result(ASI02_001=(Verdict.PASS, CRIT)))
        assert self._exit(_result(ASI02_001=(Verdict.FAIL, CRIT)), baseline) == 1

    def test_improvement_exits_zero(self, tmp_path: Path) -> None:
        baseline = self._write_baseline(tmp_path, _result(ASI02_001=(Verdict.FAIL, CRIT)))
        assert self._exit(_result(ASI02_001=(Verdict.PASS, CRIT)), baseline) == 0

    def test_missing_baseline_behaves_as_if_unflagged(self, tmp_path: Path) -> None:
        absent = tmp_path / "absent.json"
        assert self._exit(_result(ASI02_001=(Verdict.FAIL, CRIT)), absent) == 1
        assert self._exit(_result(ASI02_001=(Verdict.PASS, CRIT)), absent) == 0

    def test_fail_on_critical_ignores_a_new_medium_failure(self, tmp_path: Path) -> None:
        baseline = self._write_baseline(tmp_path, _result(ASI02_001=(Verdict.PASS, MED)))
        result = _result(ASI02_001=(Verdict.FAIL, MED))
        assert self._exit(result, baseline, fail_on="critical") == 0
        assert self._exit(result, baseline, fail_on="any") == 1

    def test_fail_on_critical_still_blocks_a_new_critical_failure(
        self, tmp_path: Path
    ) -> None:
        baseline = self._write_baseline(tmp_path, _result(ASI02_001=(Verdict.PASS, CRIT)))
        result = _result(ASI02_001=(Verdict.FAIL, CRIT))
        assert self._exit(result, baseline, fail_on="critical") == 1
