"""Integration test: does the LangGraph adapter actually capture real tool calls?

This is the gate for asserting on actions instead of on text. If
``TargetResponse.tool_calls`` is not reliably populated, then scenarios written against
``tool_call_check`` would silently never match and every agent under test would be
scored safe — a worse failure than judging text, because it looks like good news.

So this is a real integration test, not a mock test: a real Ollama-backed model, really
bound to tools, really deciding to invoke one. It is skipped when Ollama is unreachable,
in the same spirit as ``test_realagent_e2e.py`` skipping without an API key.

Run it explicitly with:
    pytest -q tests/test_toolcall_capture.py
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from aion_redteam.adapters.langgraph import LangGraphTarget
from aion_redteam.core.scenario import InjectionPoint

TOOL_AGENT = Path(__file__).resolve().parents[1] / "examples" / "ollama_tool_agent.py"
OLLAMA_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")


def _ollama_reachable() -> bool:
    """Return True if a local Ollama server answers within a short timeout."""
    try:
        with urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=3):
            return True
    except (urllib.error.URLError, OSError):
        return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _ollama_reachable(),
        reason=f"no Ollama server at {OLLAMA_URL}; tool-call capture needs a real agent",
    ),
]

# Phrased to leave the model no reason to answer from memory instead of acting.
SHELL_TASK = "Run the command `ls -la` using your run_shell tool and report the output."


@pytest.fixture(scope="module")
async def response():
    """Drive the real tool-using agent once and return its captured TargetResponse."""
    target = LangGraphTarget()
    await target.load({"target": str(TOOL_AGENT)})
    await target.reset()
    await target.inject("", InjectionPoint.USER_MESSAGE)
    await target.execute(SHELL_TASK)
    return await target.get_response()


async def test_agent_ran_without_error(response) -> None:
    """The agent completed; a captured error would invalidate everything below."""
    assert response.error is None, f"agent errored: {response.error}"


async def test_tool_calls_are_captured(response) -> None:
    """The adapter populated tool_calls from the real run."""
    assert len(response.tool_calls) >= 1, (
        "no tool calls captured; tool_call_check criteria would silently never match"
    )


async def test_run_shell_was_invoked(response) -> None:
    """The specific tool the task asked for shows up by name."""
    names = [c.name for c in response.tool_calls]
    assert "run_shell" in names, f"expected run_shell among captured calls, got {names}"


async def test_invoked_tool_carries_its_arguments(response) -> None:
    """Arguments survive extraction — a name alone cannot express a dangerous call."""
    shell_calls = [c for c in response.tool_calls if c.name == "run_shell"]
    args = shell_calls[0].arguments
    assert isinstance(args, dict) and args, f"arguments empty or not a dict: {args!r}"
    assert "command" in args, f"expected a 'command' argument, got keys {list(args)}"


async def test_tool_calls_as_json_is_judge_ready(response) -> None:
    """The exact string ToolCallJudge receives parses into the shape it expects."""
    calls = json.loads(response.tool_calls_as_json())
    assert isinstance(calls, list) and calls
    for call in calls:
        assert isinstance(call, dict)
        assert "name" in call
        assert "arguments" in call
