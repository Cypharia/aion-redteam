"""Judges: pluggable evaluators that decide whether a single criterion matched.

A judge answers one question: *given this slice of the agent's behaviour, did this
criterion match?* The runner picks the slice (response text, tool calls, or trace)
based on ``criterion.target`` and hands the judge a plain string.

Phase 1 ships :class:`StringMatchJudge` and :class:`RegexJudge`. :class:`LLMJudge` and
:class:`ToolCallJudge` are stubs that raise until their respective phases land.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any

from aion_redteam.core.scenario import Criterion, CriterionType

# Named regex flags accepted in scenario YAML (``flags: ["IGNORECASE", ...]``).
_REGEX_FLAGS: dict[str, re.RegexFlag] = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
    "ASCII": re.ASCII,
}


def _compile_pattern(pattern: str, field: str) -> re.Pattern[str]:
    """Compile a scenario-supplied regex, naming the offending pattern on failure.

    Args:
        pattern: The regex from the scenario YAML.
        field: The criterion field it came from, for the error message.

    Returns:
        The compiled, case-insensitive pattern.

    Raises:
        ValueError: If ``pattern`` is not a valid regex.
    """
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise ValueError(f"invalid regex in {field}: {pattern!r} ({exc})") from exc


class Judge(ABC):
    """Abstract base class for all judges."""

    @abstractmethod
    def evaluate(self, response: str, criterion: Criterion) -> bool:
        """Return ``True`` if ``criterion`` matches ``response``.

        Args:
            response: The agent-behaviour slice selected by ``criterion.target``.
            criterion: The criterion to evaluate.

        Returns:
            ``True`` when the criterion matches (i.e. the attack indicator is present).
        """
        raise NotImplementedError


class StringMatchJudge(Judge):
    """Substring match. Case-insensitive unless ``criterion.case_sensitive`` is set."""

    def evaluate(self, response: str, criterion: Criterion) -> bool:
        """Check whether ``criterion.value`` is a substring of ``response``."""
        if criterion.value is None:
            raise ValueError("string_match criterion requires 'value'")
        if criterion.case_sensitive:
            return criterion.value in response
        return criterion.value.casefold() in response.casefold()


class RegexJudge(Judge):
    """Regex search using ``criterion.pattern`` with optional named ``flags``."""

    def evaluate(self, response: str, criterion: Criterion) -> bool:
        """Search ``response`` for ``criterion.pattern``."""
        if criterion.pattern is None:
            raise ValueError("regex criterion requires 'pattern'")
        flags = self._resolve_flags(criterion)
        return re.search(criterion.pattern, response, flags) is not None

    @staticmethod
    def _resolve_flags(criterion: Criterion) -> int:
        """Combine named regex flags from the criterion into a single bitmask."""
        bitmask = 0
        for name in criterion.flags:
            try:
                bitmask |= _REGEX_FLAGS[name.upper()]
            except KeyError as exc:
                valid = ", ".join(sorted(_REGEX_FLAGS))
                raise ValueError(
                    f"unknown regex flag {name!r}; valid flags: {valid}"
                ) from exc
        if not criterion.case_sensitive and not (bitmask & re.IGNORECASE):
            bitmask |= re.IGNORECASE
        return bitmask


class LLMJudge(Judge):
    """Scores agent output with an LLM. Planned for v0.4."""

    def evaluate(self, response: str, criterion: Criterion) -> bool:
        """Not implemented; planned for v0.4."""
        raise NotImplementedError("LLMJudge is not implemented yet; planned for v0.4.")


class ToolCallJudge(Judge):
    """Checks whether the agent invoked a specific tool, optionally with given arguments.

    The runner feeds this judge a JSON array of the agent's tool calls
    (``[{"name": ..., "arguments": {...}}, ...]`` from
    :meth:`TargetResponse.tool_calls_as_json`).

    A criterion names the tool one of two ways:

    * ``value`` — an exact tool name, compared honouring ``case_sensitive``.
    * ``name_pattern`` — a regex searched against the tool name. Prefer this in shipped
      scenarios: neither adapter binds ``setup.tools_available`` to the agent, so the
      target has whatever tools its author wrote (``execute_command``, ``bash``,
      ``shell_tool``, …) and an exact name will rarely match.

    The match can then be narrowed by ``arguments`` (each named argument must *contain*
    the given substring) and/or ``argument_patterns`` (each named argument must *match*
    the given regex). When both are present, both must pass.

    Tool-name and argument patterns are always case-insensitive: tool names are
    identifiers whose casing convention varies per codebase, and argument patterns match
    command text where casing varies per platform (``rm -rf`` vs ``Remove-Item``).
    """

    def evaluate(self, response: str, criterion: Criterion) -> bool:
        """Return ``True`` if a matching tool call is present.

        Raises:
            ValueError: If the criterion names no tool, or carries an invalid regex.
        """
        if criterion.value is None and criterion.name_pattern is None:
            raise ValueError(
                "tool_call_check criterion requires 'value' (an exact tool name) "
                "or 'name_pattern' (a regex over tool names)"
            )
        try:
            calls = json.loads(response) if response else []
        except json.JSONDecodeError:
            return False
        if not isinstance(calls, list):
            return False
        # Compiled once per evaluation rather than once per tool call: an agent can make
        # many calls in a run, and the patterns are identical across all of them.
        name_re = (
            _compile_pattern(criterion.name_pattern, "name_pattern")
            if criterion.name_pattern is not None
            else None
        )
        arg_res = {
            key: _compile_pattern(pattern, f"argument_patterns[{key!r}]")
            for key, pattern in (criterion.argument_patterns or {}).items()
        }
        return any(self._matches(call, criterion, name_re, arg_res) for call in calls)

    def _matches(
        self,
        call: Any,
        criterion: Criterion,
        name_re: re.Pattern[str] | None,
        arg_res: dict[str, re.Pattern[str]],
    ) -> bool:
        """Check one tool-call record against the criterion and its compiled patterns."""
        if not isinstance(call, dict):
            return False
        if not self._name_matches(str(call.get("name", "")), criterion, name_re):
            return False
        if not criterion.arguments and not arg_res:
            return True
        args = call.get("arguments") or {}
        if not isinstance(args, dict):
            return False
        if criterion.arguments and not all(
            expected in str(args.get(key, "")) for key, expected in criterion.arguments.items()
        ):
            return False
        return all(
            regex.search(str(args.get(key, ""))) is not None for key, regex in arg_res.items()
        )

    @staticmethod
    def _name_matches(
        name: str, criterion: Criterion, name_re: re.Pattern[str] | None
    ) -> bool:
        """Compare a tool name to the criterion, by pattern if given, else exactly."""
        if name_re is not None:
            return name_re.search(name) is not None
        target = criterion.value or ""
        if criterion.case_sensitive:
            return name == target
        return name.casefold() == target.casefold()


_JUDGE_REGISTRY: dict[CriterionType, type[Judge]] = {
    CriterionType.STRING_MATCH: StringMatchJudge,
    CriterionType.REGEX: RegexJudge,
    CriterionType.LLM_JUDGE: LLMJudge,
    CriterionType.TOOL_CALL_CHECK: ToolCallJudge,
}


def get_judge(criterion_type: CriterionType) -> Judge:
    """Return a judge instance for the given criterion type.

    Args:
        criterion_type: The criterion type to evaluate.

    Returns:
        A ready-to-use :class:`Judge`.

    Raises:
        KeyError: If no judge is registered for ``criterion_type``.
    """
    return _JUDGE_REGISTRY[criterion_type]()
