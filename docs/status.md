# Status — implemented, refused, and what each deferred lane still needs

Build: v1 offline debugger. Author: KENSEI. Date: 2026-10-14.
Pinned target host: `NousResearch/hermes-agent` @ `0e427d788d253630d38a3a51cd76849e73cd6925`.

## Implemented and tested

| Lane | Surface | Status |
|---|---|---|
| Offline import (Trace v1 + Claude JSONL) | CLI `import`, `/rundebug import`, `rundebug_import` | implemented |
| Timeline (partial order, gaps, ambiguity) | CLI `timeline`, `/rundebug timeline`, `rundebug_timeline` | implemented |
| Diagnosis (observed facts, ranked hypotheses with alternatives and falsifiers) | CLI `explain`, `/rundebug explain`, `rundebug_explain` | implemented |
| Inert replay (executes nothing) | CLI `replay`, `/rundebug replay`, `rundebug_replay` | implemented |
| Private report export | **operator CLI only** — no tool, no slash, no gateway route | implemented |
| Status / honesty report | CLI `status`, `/rundebug status`, `rundebug_status` | implemented |
| Local store (idempotent import, revisions, migrations, recovery, retention) | internal | implemented |
| Redaction (two stages, guarded) | internal | implemented |

## Not implemented — refused, never silently ignored

Each deferred lane has its own Phase 0 gate. Enabling one by setting its key
produces a **named refusal** from `import`, `export` and `status`; the plugin does
not pretend to provide it.

| Lane | Setting (default `false`) | Gate before it can ship |
|---|---|---|
| Native hook capture | `capture_enabled` | real host-emission tests at each advertised route; a non-policy observer hook set; proof that default capture never enters a fail-closed veto hook (`pre_tool_call`); overload/unload/reload behaviour; a route support matrix |
| Selected-session live read | `live_read_enabled` | a proven read-only path that leaves the source database, WAL and sidecars byte-unchanged under a live writer, with bounded retries and no repair path; no raw whole-database copy |
| Model narration | `llm_enabled` | an explicit egress/budget grant, a preview of exactly what would leave the machine, local schema validation, second-pass scrub, and audit provenance |
| Sandboxed experiments | `experiment_enabled` | a separately verified OS isolation backend, an owner-originated execution authority path, its own argv/input/env contract, and a one-time grant |

## Test lanes present

`tests/unit`, `tests/adversarial`, `tests/integration`, `tests/host`.
No `tests/platform` exists yet: cross-OS native evidence is part of the
release-gate plan for a build that advertises more than Linux. The host tests skip
(never fake) when `HERMES_HOST_SRC` is absent.

## Deliberate deviations from the planning document, with reasons

1. **`retention_mode` setting added** (`redacted-summary` default, `metadata-only`
   alternative). The plan requires "no raw prompt/tool/result retention" and
   "explicit, configurable" content retention. Prompt text and tool arguments are
   never retained; bounded, redacted tool-result *summaries* are, and the operator
   can turn even those off. This is the configurable default named in the plan, not
   a silent widening of it.
2. **Event schema gained `name` and `arguments_ref`.** A timeline that cannot say
   *which* tool failed is not useful, and the plan's own rule is that arguments are
   referenced, not stored. `name` is a bounded, control-character-free reported
   subject; `arguments_ref` is an opaque reference. Both are documented in
   `schemas/trace-v1.json`.
3. **`export` refuses on the slash route with a fixed message** (rather than
   parsing the arguments and failing later), so no partial parse can produce a
   write, and the refusal is byte-identical in tests.
4. **`provides_middleware` omitted from the manifest** — the target host reports it
   as an unknown field and this build registers no middleware.
5. **Identifier fields pass through redaction unchanged.** Rewriting a hex event id
   corrupted evidence linkage; identifiers are protected by field name and stated
   as a limitation of the filter.
