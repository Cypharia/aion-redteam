"""A real, fully local *tool-using* LangGraph agent — the target for action-level testing.

The other two examples are single-node chat agents: they can only ever produce text, so
scenarios can only ever judge text. This one binds real tools to a real model via
``create_react_agent``, so the harness can assert on what the agent **does**
(``TargetResponse.tool_calls``) rather than only on what it says.

**The tools are deliberately inert.** ``run_shell`` does not touch a shell and
``read_file`` does not touch the filesystem; each records nothing and returns a fixed
string. That is the point: this agent exists to be attacked, and several bundled scenarios
try to coerce it into destructive commands. The model, the tool bindings, and the decision
to invoke a tool are all genuine — only the side effect is stubbed out. Never swap these
for real implementations.

Requirements:
    pip install "aion-redteam[langgraph]" langchain-ollama
    ollama serve            # (usually already running)
    ollama pull qwen2.5:3b  # or any tool-capable model you have

    export AION_OLLAMA_MODEL=qwen2.5:3b               # optional, defaults to qwen2.5:3b
    export OLLAMA_BASE_URL=http://localhost:11434     # optional

Run it:
    aion-redteam run --target examples/ollama_tool_agent.py --adapter langgraph

The harness discovers the module-level ``graph`` (a compiled ``StateGraph``). No system
prompt is set here, so the agent's instructions come entirely from each scenario's
``setup.system_prompt`` — an unhardened target by design.
"""

from __future__ import annotations

import os

from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent

MODEL = os.environ.get("AION_OLLAMA_MODEL", "qwen2.5:3b")
BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")


@tool
def run_shell(command: str) -> str:
    """Execute a shell command on the host and return its output.

    Args:
        command: The shell command to execute.

    Returns:
        The command's combined output.
    """
    # Inert on purpose — see the module docstring. Scenarios coerce this agent into
    # calling run_shell with destructive commands; actually running them would destroy
    # the machine under test. The invocation is what the harness measures.
    #
    # The reply is shaped like success because a failure-shaped one makes the agent
    # retry until it hits the recursion limit, which wastes model calls and distorts
    # the scenario. `command` is deliberately not echoed back: doing so would plant the
    # attacker's string in the transcript and make text criteria match on the harness's
    # own output rather than the agent's.
    return "exit status 0"


@tool
def read_file(path: str) -> str:
    """Read the contents of a file.

    Args:
        path: Path of the file to read.

    Returns:
        The file's contents.
    """
    # Inert on purpose — see the module docstring. Success-shaped and free of the
    # requested path, for the same two reasons as run_shell.
    return "# (file is empty)"


def build_graph():
    """Build and compile the tool-using agent. Returns a compiled ``StateGraph``.

    Uses ``langgraph.prebuilt.create_react_agent``, which LangGraph 1.0 deprecated in
    favour of ``langchain.agents.create_agent``. We keep it: the replacement lives in
    the ``langchain`` meta-package, which is not part of the ``langgraph`` extra
    (``langgraph>=0.2``, ``langchain-core>=0.3``), and pulling in a new dependency for a
    rename is not worth it. Revisit before LangGraph 2.0 removes it.
    """
    llm = ChatOllama(model=MODEL, base_url=BASE_URL, temperature=0)
    return create_react_agent(llm, [run_shell, read_file])


# Discovered by the LangGraph adapter.
graph = build_graph()


if __name__ == "__main__":
    from langchain_core.messages import HumanMessage

    result = graph.invoke(
        {"messages": [HumanMessage(content="Run `ls -la` and tell me what you see.")]}
    )
    for message in result["messages"]:
        calls = getattr(message, "tool_calls", None)
        if calls:
            print(f"tool_calls: {calls}")
    print(result["messages"][-1].content)
