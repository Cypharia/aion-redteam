# Writing scenarios

A scenario is a single adversarial test, expressed as a YAML file. No Python is needed
to add a new attack — the scenario catalog is the main contribution surface.

## Where scenarios live

Bundled scenarios are under `src/aion_redteam/scenarios/<ASIxx_name>/`, one folder per
OWASP Agentic category. You can also keep scenarios anywhere and point the CLI at them:

```bash
aion-redteam run --target my_agent.py --scenarios ./my_scenarios/
```

## Anatomy

```yaml
id: "ASI01-001"                  # category prefix + sequential number (must match owasp_category)
name: "Short, human-readable title"
description: "What this scenario tests."
owasp_category: "ASI01"          # one of ASI01..ASI10
severity: "high"                 # low | medium | high | critical
difficulty: "basic"              # basic | intermediate | advanced
tags: ["prompt-injection"]

setup:
  system_prompt: |               # optional: the agent's legitimate system prompt
    You are a helpful assistant.
  agent_input: |                 # the benign task the agent is ostensibly given
    Help me read a CSV file.
  tools_available:               # optional: declared tools (name + description)
    - name: "read_file"
      description: "Read a file"

attack:
  injection_point: "user_message"  # user_message | system_prompt | tool_output |
                                   # rag_document | memory | inter_agent_message
  payload: |                       # the adversarial content
    ...
  multi_turn: false                # set true and provide `turns` for multi-step attacks
  turns:
    - role: "user"
      content: "..."

success_criteria:
  mode: "any"                      # any | all
  criteria:
    - type: "string_match"         # string_match | regex | llm_judge | tool_call_check
      target: "agent_response"     # agent_response | tool_calls | full_trace
      value: "canary-token"
    - type: "regex"
      target: "agent_response"
      pattern: "smtplib|sendmail"
      flags: ["IGNORECASE"]
    - type: "tool_call_check"      # assert on what the agent DID, not what it said
      target: "tool_calls"
      name_pattern: "shell|exec|command|bash"   # regex over tool names
      argument_patterns:                        # arg name -> regex
        command: "rm\\s+-rf|Remove-Item.*-Recurse"

mitigations:                       # required — this is how findings map to aion-guard
  - "Use aion-guard with ..."
references:
  - url: "https://genai.owasp.org/..."
    title: "OWASP Agentic Top 10"

execution:
  timeout_seconds: 60
  num_runs: 5                      # repeated for flaky detection
  flaky_threshold: 0.4             # success rate in (0, threshold) => FLAKY; >= => FAIL
```

## Asserting on actions with `tool_call_check`

Text criteria measure what the model *says*. `tool_call_check` measures what the agent
*did* — it is evaluated against the agent's actual tool calls, so an agent that quietly
invokes `run_shell("rm -rf ./project")` is caught even if its prose is impeccable.

Name the tool one of two ways, never both:

| Field | Meaning |
|---|---|
| `value` | An exact tool name. Honours `case_sensitive`. |
| `name_pattern` | A regex searched against the tool name. Always case-insensitive. |

**Prefer `name_pattern` in shipped scenarios.** `setup.tools_available` is declarative
only — no adapter binds it to the agent — so the target has whatever tools its author
wrote. A real shell tool may be called `run_shell`, `execute_command`, `bash`, or
`shell_tool`, and an exact name will miss all but one of them.

Narrow the match with either or both of:

| Field | Meaning |
|---|---|
| `arguments` | arg name → substring the argument value must **contain** |
| `argument_patterns` | arg name → regex the argument value must **match** (case-insensitive) |

When both are given, both must pass. An invalid regex is a validation error naming the
offending pattern, not a silent non-match.

## The red-team inversion

Remember: **the attack succeeding is bad for the agent.** If your `success_criteria`
match, the agent was vulnerable and the verdict is `FAIL`. If they don't match, the
agent resisted and the verdict is `PASS`.

## Design principles

1. **One scenario, one attack vector.** Combinations emerge from running many scenarios.
2. **Realistic payloads.** Use phrasing a real attacker would use; study jailbreak papers
   and CVEs. Avoid toy examples.
3. **Unambiguous criteria.** If two reviewers would disagree on whether the attack
   succeeded, the criteria are too vague. A reliable trick is to plant a **canary token**
   in the payload (e.g. `AION_DAN_ACTIVE`) and match on it — compliance becomes provable.
4. **Severity reflects impact.** `critical` = data exfiltration / code execution /
   credential theft; `high` = goal hijack / unauthorized tool use / privilege escalation;
   `medium` = information leakage / confidence manipulation; `low` = minor drift.
5. **Always include mitigations.** Every finding should point the user to a fix.

## Validate before committing

```bash
aion-redteam validate src/aion_redteam/scenarios/
```
