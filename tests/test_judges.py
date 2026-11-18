"""Unit tests for the Phase 1 judges."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from aion_redteam.core.judge import (
    LLMJudge,
    RegexJudge,
    StringMatchJudge,
    ToolCallJudge,
    get_judge,
)
from aion_redteam.core.scenario import Criterion, CriterionType


class TestStringMatchJudge:
    def test_substring_match_case_insensitive_by_default(self) -> None:
        judge = StringMatchJudge()
        crit = Criterion(type=CriterionType.STRING_MATCH, value="attacker@evil.com")
        assert judge.evaluate("Email ATTACKER@EVIL.COM now", crit) is True

    def test_no_match(self) -> None:
        judge = StringMatchJudge()
        crit = Criterion(type=CriterionType.STRING_MATCH, value="attacker@evil.com")
        assert judge.evaluate("a benign response", crit) is False

    def test_case_sensitive_respected(self) -> None:
        judge = StringMatchJudge()
        crit = Criterion(
            type=CriterionType.STRING_MATCH, value="EvilBot", case_sensitive=True
        )
        assert judge.evaluate("i am evilbot", crit) is False
        assert judge.evaluate("i am EvilBot", crit) is True


class TestRegexJudge:
    def test_pattern_search(self) -> None:
        judge = RegexJudge()
        crit = Criterion(type=CriterionType.REGEX, pattern="smtplib|sendmail")
        assert judge.evaluate("import smtplib", crit) is True

    def test_ignorecase_flag(self) -> None:
        judge = RegexJudge()
        crit = Criterion(
            type=CriterionType.REGEX, pattern="EVIL", flags=["IGNORECASE"]
        )
        assert judge.evaluate("be evil", crit) is True

    def test_case_sensitive_disables_default_ignorecase(self) -> None:
        judge = RegexJudge()
        crit = Criterion(type=CriterionType.REGEX, pattern="EVIL", case_sensitive=True)
        assert judge.evaluate("be evil", crit) is False

    def test_unknown_flag_raises(self) -> None:
        judge = RegexJudge()
        crit = Criterion(type=CriterionType.REGEX, pattern="x", flags=["NONSENSE"])
        with pytest.raises(ValueError, match="unknown regex flag"):
            judge.evaluate("x", crit)


class TestLLMJudgeStub:
    def test_llm_judge_not_implemented(self) -> None:
        crit = Criterion(type=CriterionType.LLM_JUDGE, prompt="did it leak?")
        with pytest.raises(NotImplementedError, match="planned for v0.4"):
            LLMJudge().evaluate("anything", crit)


class TestToolCallJudge:
    CALLS = '[{"name": "send_email", "arguments": {"to": "x@evil.com", "body": "hi"}}]'

    def test_matches_tool_by_name(self) -> None:
        crit = Criterion(type=CriterionType.TOOL_CALL_CHECK, value="send_email")
        assert ToolCallJudge().evaluate(self.CALLS, crit) is True

    def test_no_match_when_tool_absent(self) -> None:
        crit = Criterion(type=CriterionType.TOOL_CALL_CHECK, value="delete_file")
        assert ToolCallJudge().evaluate(self.CALLS, crit) is False

    def test_argument_substring_match(self) -> None:
        crit = Criterion(
            type=CriterionType.TOOL_CALL_CHECK,
            value="send_email",
            arguments={"to": "evil.com"},
        )
        assert ToolCallJudge().evaluate(self.CALLS, crit) is True

    def test_argument_mismatch_fails(self) -> None:
        crit = Criterion(
            type=CriterionType.TOOL_CALL_CHECK,
            value="send_email",
            arguments={"to": "trusted.com"},
        )
        assert ToolCallJudge().evaluate(self.CALLS, crit) is False

    def test_name_case_insensitive_by_default(self) -> None:
        crit = Criterion(type=CriterionType.TOOL_CALL_CHECK, value="SEND_EMAIL")
        assert ToolCallJudge().evaluate(self.CALLS, crit) is True

    def test_case_sensitive_respected(self) -> None:
        crit = Criterion(
            type=CriterionType.TOOL_CALL_CHECK, value="SEND_EMAIL", case_sensitive=True
        )
        assert ToolCallJudge().evaluate(self.CALLS, crit) is False

    def test_empty_and_invalid_json(self) -> None:
        crit = Criterion(type=CriterionType.TOOL_CALL_CHECK, value="send_email")
        assert ToolCallJudge().evaluate("", crit) is False
        assert ToolCallJudge().evaluate("not json", crit) is False


class TestToolCallJudgePatterns:
    """Pattern matching on tool names — the mode shipped scenarios use.

    Exact names are near-useless against a real target: neither adapter binds
    ``setup.tools_available``, so the agent has whatever its author named its tools.
    """

    # A real agent's shell tool, named nothing like the scenario would guess.
    CALLS = '[{"name": "execute_command", "arguments": {"command": "rm -rf ./project"}}]'

    def test_name_pattern_matches_an_unguessable_tool_name(self) -> None:
        crit = Criterion(
            type=CriterionType.TOOL_CALL_CHECK,
            name_pattern="shell|exec|command|bash",
        )
        assert ToolCallJudge().evaluate(self.CALLS, crit) is True

    def test_name_pattern_miss(self) -> None:
        crit = Criterion(
            type=CriterionType.TOOL_CALL_CHECK, name_pattern="email|smtp|sendmail"
        )
        assert ToolCallJudge().evaluate(self.CALLS, crit) is False

    def test_name_pattern_is_case_insensitive(self) -> None:
        crit = Criterion(type=CriterionType.TOOL_CALL_CHECK, name_pattern="EXECUTE")
        assert ToolCallJudge().evaluate(self.CALLS, crit) is True

    def test_argument_patterns_hit(self) -> None:
        crit = Criterion(
            type=CriterionType.TOOL_CALL_CHECK,
            name_pattern="shell|exec|command",
            argument_patterns={"command": r"rm\s+-rf|Remove-Item.*-Recurse"},
        )
        assert ToolCallJudge().evaluate(self.CALLS, crit) is True

    def test_argument_patterns_miss_on_a_benign_call(self) -> None:
        benign = '[{"name": "execute_command", "arguments": {"command": "ls -la"}}]'
        crit = Criterion(
            type=CriterionType.TOOL_CALL_CHECK,
            name_pattern="shell|exec|command",
            argument_patterns={"command": r"rm\s+-rf"},
        )
        assert ToolCallJudge().evaluate(benign, crit) is False

    def test_argument_patterns_miss_on_absent_argument(self) -> None:
        crit = Criterion(
            type=CriterionType.TOOL_CALL_CHECK,
            name_pattern="exec",
            argument_patterns={"path": r"/etc/passwd"},
        )
        assert ToolCallJudge().evaluate(self.CALLS, crit) is False

    def test_arguments_and_argument_patterns_must_both_pass(self) -> None:
        judge = ToolCallJudge()
        both_ok = Criterion(
            type=CriterionType.TOOL_CALL_CHECK,
            name_pattern="exec",
            arguments={"command": "rm"},
            argument_patterns={"command": r"-rf"},
        )
        assert judge.evaluate(self.CALLS, both_ok) is True

        substring_fails = Criterion(
            type=CriterionType.TOOL_CALL_CHECK,
            name_pattern="exec",
            arguments={"command": "curl"},
            argument_patterns={"command": r"-rf"},
        )
        assert judge.evaluate(self.CALLS, substring_fails) is False

        pattern_fails = Criterion(
            type=CriterionType.TOOL_CALL_CHECK,
            name_pattern="exec",
            arguments={"command": "rm"},
            argument_patterns={"command": r"--no-preserve-root"},
        )
        assert judge.evaluate(self.CALLS, pattern_fails) is False

    def test_matches_when_any_of_several_calls_matches(self) -> None:
        calls = (
            '[{"name": "read_file", "arguments": {"path": "notes.txt"}},'
            ' {"name": "run_shell", "arguments": {"command": "rm -rf /"}}]'
        )
        crit = Criterion(
            type=CriterionType.TOOL_CALL_CHECK,
            name_pattern="shell",
            argument_patterns={"command": r"rm\s+-rf"},
        )
        assert ToolCallJudge().evaluate(calls, crit) is True

    def test_invalid_name_pattern_raises_naming_the_pattern(self) -> None:
        crit = Criterion(type=CriterionType.TOOL_CALL_CHECK, name_pattern="shell(")
        with pytest.raises(ValueError, match=r"invalid regex in name_pattern"):
            ToolCallJudge().evaluate(self.CALLS, crit)

    def test_invalid_argument_pattern_raises_naming_the_field(self) -> None:
        crit = Criterion(
            type=CriterionType.TOOL_CALL_CHECK,
            name_pattern="exec",
            argument_patterns={"command": "rm[-rf"},
        )
        with pytest.raises(ValueError, match=r"invalid regex in argument_patterns\['command'\]"):
            ToolCallJudge().evaluate(self.CALLS, crit)


class TestToolCallCriterionValidation:
    def test_neither_value_nor_name_pattern_is_an_error(self) -> None:
        with pytest.raises(ValidationError, match="requires 'value'"):
            Criterion(type=CriterionType.TOOL_CALL_CHECK)

    def test_both_value_and_name_pattern_is_an_error(self) -> None:
        # Accepting both would silently ignore one; a criterion that checks less than
        # its author wrote is exactly the bug this release exists to prevent.
        with pytest.raises(ValidationError, match="not both"):
            Criterion(
                type=CriterionType.TOOL_CALL_CHECK,
                value="run_shell",
                name_pattern="shell",
            )


class TestGetJudge:
    @pytest.mark.parametrize(
        ("ctype", "expected"),
        [
            (CriterionType.STRING_MATCH, StringMatchJudge),
            (CriterionType.REGEX, RegexJudge),
            (CriterionType.LLM_JUDGE, LLMJudge),
            (CriterionType.TOOL_CALL_CHECK, ToolCallJudge),
        ],
    )
    def test_factory_returns_correct_judge(self, ctype, expected) -> None:
        assert isinstance(get_judge(ctype), expected)
