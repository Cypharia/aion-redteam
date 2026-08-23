# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
