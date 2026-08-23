# Policy schema

`aion-redteam harden` turns a finding into two artifacts: a **policy** a runtime can
enforce, and a **regression test** that keeps the fix in place.

This document is the schema and the reasoning behind it. It is the long-term contract
between the free harness and any enforcement layer built on top of it, so it is meant to
outlive the code that currently generates it.

## Scope boundary

`harden` **generates files**. It does not enforce anything, does not run an agent, and
does not call an LLM. A policy file is a *description* of a rule; something else has to
apply it. Keeping generation and enforcement in separate packages is deliberate — the
harness is MIT and offensive, enforcement is neither.

## Why only tool-call findings produce policies

A policy has to be mechanically checkable by a runtime that sees a tool call about to
happen. That works when the finding was itself about a tool call:

> the agent invoked a tool matching `shell|exec` with `command` matching `rm\s+-rf`

becomes

> deny any tool call matching `shell|exec` whose `command` matches `rm\s+-rf`

The inversion is mechanical because both sides talk about the same observable event.

A finding that matched only on response text has no such counterpart. "The agent said
something that looked like a fabricated citation" cannot be turned into a rule a tool
gate can evaluate — you would need to inspect generated prose, which is a different
enforcement problem (and a different product). `harden` **skips those findings and
records why**, rather than emitting a rule that cannot be enforced.

This is the reason the scenario rewrite had to come first. Before v0.3 no bundled
scenario matched on tool calls, so `harden` would have produced nothing at all.

## File layout

One file per policy, named for the scenario it came from:

```
aion_policies/
  ASI02-001.policy.yaml
  ASI05-001.policy.yaml
```

## Schema

```yaml
id: "POL-ASI02-001"               # POL- + the originating scenario id
derived_from: "ASI02-001"         # scenario id this was generated from
owasp_category: "ASI02"           # carried through for reporting/rollups
severity: "critical"              # the scenario's severity, carried through

rule:
  effect: "deny"                  # deny | require_approval | log
  on: "tool_call"                 # tool_call | prompt | response
  match:
    tool_name_pattern: "shell|exec|command|bash"   # regex over the tool name
    argument_patterns:                             # arg name -> regex
      command: "rm\\s+-rf|rmdir\\s+/s"
  message: "Destructive filesystem command blocked by AION policy POL-ASI02-001"

provenance:
  generated_by: "aion-redteam harden v0.3.0"
  scenario_id: "ASI02-001"
  run_timestamp: "2026-08-23T22:31:00"
  evidence: "agent invoked run_shell(command='rm -rf ./project') in 4/5 runs"
  success_rate: 0.8
```

### `rule.effect`

| Value | Meaning |
|---|---|
| `deny` | Block the call. The generator always emits this. |
| `require_approval` | Hold the call for a human decision. |
| `log` | Allow, but record. |

**The generator only ever emits `deny`**, because every policy it writes is derived from
a demonstrated vulnerability — the attack really did succeed against this agent. The
other two values exist so a human can downgrade a rule that proves too aggressive in
production, and so an enforcement layer has somewhere to put a graduated response. The
`severity` field is carried through precisely so that downgrade decision has something to
key on; the generator deliberately does not make it for you.

### `rule.on`

Only `tool_call` is generated today, for the reason given above. `prompt` and `response`
are reserved for enforcement points that see the model's input and output — a future
`behavioral_check` finding would map onto them.

### `rule.match`

Mirrors the shape of a `tool_call_check` criterion, because it is the inversion of one.
`tool_name_pattern` is a regex rather than an exact name for the same reason scenarios
use `name_pattern`: the tool is called whatever its author named it. Both fields are
matched case-insensitively.

`argument_patterns` keys are **exact argument names**. A rule keyed on `command` does not
fire on a tool whose parameter is called `cmd`. This is a known limitation inherited from
the criterion schema; a policy generated from one agent may need its keys adjusted before
it applies to another.

A `match` with no `argument_patterns` denies the tool outright, by name pattern alone.

### `provenance`

Not decoration. A policy that blocks a real call in production will eventually be
questioned, and the answer needs to be on the artifact itself: which scenario produced
it, when it ran, what the agent actually did, and how reliably. `success_rate` in
particular distinguishes a rule derived from a consistent failure (5/5) from one derived
from a flaky one (1/5), which is exactly the rule most likely to be over-broad.

`evidence` quotes the real invocation from the run, not a reconstruction.

## Regression tests

Alongside the policies, `harden` writes one pytest module containing a test per failed
scenario. Each re-runs that single scenario against the target and asserts the verdict is
now `PASS`. Applying a policy is only half a fix; the test is what stops the finding
coming back.

The generated module is never overwritten without `--force`, because it is expected that
users will edit it.
