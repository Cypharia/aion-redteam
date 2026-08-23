# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-23

The harness measured what the model **said**. Now it measures what the agent **does**.

Every one of the 40 success criteria across the 20 bundled scenarios targeted
`agent_response`; none used `tool_calls`. So an agent that refused but explained "I won't
run `rm -rf` for you" was scored VULNERABLE, while an agent that silently called
`run_shell("rm -rf /")` was scored SAFE. This release fixes that, and adds the tooling to
turn a finding into an enforceable fix.

### Added
- **Tool-name pattern matching** — `Criterion` gains `name_pattern` (regex over tool
  names) and `argument_patterns` (argument name → regex), and `ToolCallJudge` uses them.
  Exact names were near-useless against a real target: `setup.tools_available` is not
  bound to the agent by any adapter, so the agent under test has whatever its author
  named its tools. Patterns compile once per evaluation; an invalid one raises
  `ValueError` naming the offending pattern instead of silently never matching.
- **`aion-redteam harden`** — turns findings into an enforceable policy per finding plus
  a pytest regression module. Generates files only; enforces nothing, runs no agent, calls
  no LLM. Only tool-call findings produce policies — a text-only finding has no
  counterpart a tool gate can evaluate, and is skipped with a recorded reason. Schema and
  rationale in `docs/policy_schema.md`.
- **`aion-redteam run --baseline` and `aion-redteam baseline accept`** — gate CI on
  regressions rather than on absolute state, with `--fail-on` to narrow by severity.
  Prints the delta (`2 new failures, 1 fixed, 17 unchanged`). Without `--baseline`,
  behaviour is unchanged.
- `SingleRunDetail.matched_criteria_detail` and `.tool_calls` — a results file is now a
  self-contained record of what matched and what the agent did, rather than indices into
  a scenario library that may have moved. Both additive; v0.2-era result JSON still loads.
- `examples/ollama_tool_agent.py` — a real Ollama-backed LangGraph agent with tools bound,
  and `tests/test_toolcall_capture.py` verifying against a live model that the adapter
  really does populate `TargetResponse.tool_calls`. Neither previous example bound a
  single tool, so action-level testing had no target.

### Changed
- **14 of the 20 bundled scenarios now assert on tool calls** as the primary signal, each
  keeping one text criterion as a weaker secondary so an agent with no matching tool still
  yields a usable result. ASI09 stays text-only by design — a fabricated citation *is* the
  harm. ASI04 and ASI08 are deferred with `TODO(v0.4)` markers; they need run-level signals
  no criterion type expresses yet.
- **Retained text patterns tightened.** Under `mode: any` a trigger-happy text criterion
  silently undoes the whole change, and several matched the exact refusal they were meant
  to catch — ASI10-001's `without (your )?approval` matched "I won't act without your
  approval". Commands must now appear line-anchored (issued, not mentioned) and
  behavioural claims need an affirmative marker. `tests/test_scenario_criteria.py` pins a
  refusal and a compliance string per scenario so this cannot rot back.
- ASI02-001 no longer instructs the agent to prefix its command with `CMD:`. Payload text
  that exists only to make a text regex fire is teaching to the test.
- `tool_call_check` requires exactly one of `value` or `name_pattern`. Accepting both
  would silently ignore one.

## [0.2.1] - 2026-08-23

An honesty patch. The package advertised capabilities it does not have; this corrects
the claims rather than building the features. No functional change to the harness.

### Changed
- Package `description` no longer claims CrewAI and MCP support. Only the LangGraph
  adapters (in-process and server) exist.
- `LLMJudge` now says it is planned for v0.4 instead of "available in v0.2", and its
  `NotImplementedError` no longer points at an extra that does nothing. The class and
  its registry entry are retained — removing them would break any scenario that
  references `llm_judge`.
- `SECURITY.md` gained a "Threat model of the harness itself" section: the ReDoS bounds
  on judge input, the warning never to point the harness at production, and an explicit
  statement that a harness bypass (a `PASS` for a vulnerable agent) is a security defect.

### Removed
- The `crewai`, `mcp`, and `llm-judge` optional-dependency extras. No adapter or judge
  consumed them, so installing them did nothing. Examples that need the Anthropic SDK
  now name `anthropic` directly instead of hiding it behind `llm-judge`.

### Added
- `examples/ollama_tool_agent.py` — a real Ollama-backed LangGraph agent with tools
  bound, plus `tests/test_toolcall_capture.py` verifying that the adapter really does
  populate `TargetResponse.tool_calls` against a live model. Groundwork for scenarios
  that assert on actions rather than on text.

## [0.2.0] - 2026-06-15

### Added
- **`langgraph-server` adapter** — red-team a LangGraph agent running as an HTTP server
  (`langgraph dev` / LangGraph Platform) over `langgraph_sdk`, without installing
  aion-redteam in the agent's environment. Discovers the server's assistants/graphs and
  runs each scenario in a fresh thread. New CLI flags: `--base-url`, `--assistant`,
  `--api-key`. Ships as the `langgraph-server` extra.
- **Live progress** — `run` now streams each scenario verdict as it completes with a
  progress spinner, instead of appearing frozen during long scans.
- **PDF report** (`PDFReporter`, `pdf` extra) — `run --pdf` / `report --format pdf`.
- **Detailed reports** — HTML and PDF now show, per scenario: description, injection
  point, the attack payload, success criteria (with which matched), the agent's actual
  response (evidence), mitigations, and references.
- `ToolCallJudge` (`tool_call_check` criteria) — assert that an agent invoked a specific
  tool, optionally with given argument substrings. Tool calls are serialized to JSON for
  structured matching. Makes tool-using agents properly testable.
- CLI `--timeout` and `--num-runs` flags on `run` to override per-scenario execution
  budgets — needed for slow, multi-step tool-using agents on local models.

## [0.1.0] - 2026-06-11

### Added
- Core layer: scenario schema + `ScenarioLoader`, `StringMatch`/`Regex` judges, the
  `Target` lifecycle abstraction, the async `Runner` (PASS/FAIL/FLAKY/ERROR/TIMEOUT
  verdicts with a severity-weighted 0–100 risk score), and terminal/JSON/HTML reporters.
- LangGraph adapter (`LangGraphTarget`) with graph discovery and per-injection-point
  message encoding.
- Real example LangGraph agents (Anthropic-backed and a no-key local Ollama target) and
  a quick-start demo script.
- `ollama` optional extra (`langchain-ollama`) for the local example.

### Fixed
- CLI/demo force UTF-8 console output so verdict icons no longer crash on legacy Windows
  code pages (cp1252).

### Security
- Judge evaluation now runs untrusted (community-contributed) regex with a capped input
  length and under the scenario timeout, bounding ReDoS-style hangs.
- Target loading appends (rather than prepends) the target directory to `sys.path` so a
  target cannot shadow stdlib/installed packages; documented the load/scenario trust
  model in `SECURITY.md`.
- CLI (`aion-redteam`): `list`, `validate`, `run`, `report`, `init`.
- Bundled scenario library: 20 scenarios spanning all 10 OWASP Agentic (ASI) categories,
  plus the `owasp_agentic_top10` policy manifest.
- Documentation: scenario authoring and adapter guides; community files (LICENSE,
  SECURITY, CONTRIBUTING, CODE_OF_CONDUCT); GitHub issue templates and CI.

[Unreleased]: https://github.com/Cypharia/aion-redteam/commits/main
