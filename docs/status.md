# Status — implemented, refused, and what each deferred lane still needs

Build: v1 offline debugger. Author: KENSEI. Date: 2026-10-14 (revised after the
independent KENSEI acceptance review of `e7abc33` — see "Corrections" at the end).
Pinned target host: `NousResearch/hermes-agent` @ `0e427d788d253630d38a3a51cd76849e73cd6925`.

## Implemented and tested

| Lane | Surface | Status |
|---|---|---|
| Offline import: Trace v1 | CLI `import`, `/rundebug import`, `rundebug_import` | implemented |
| Offline import: Claude JSONL transcripts | same | implemented |
| Timeline (partial order, gaps, ambiguity) | CLI `timeline`, `/rundebug timeline`, `rundebug_timeline` | implemented |
| Diagnosis (observed facts, ranked hypotheses with alternatives and falsifiers) | CLI `explain`, `/rundebug explain`, `rundebug_explain` | implemented |
| Inert replay (executes nothing) | CLI `replay`, `/rundebug replay`, `rundebug_replay` | implemented |
| Private report export | **operator CLI only** — no tool, no slash, no gateway route | implemented |
| Status / honesty report | CLI `status`, `/rundebug status`, `rundebug_status` | implemented |
| Local store (idempotent import, revisions, migrations, recovery, retention) | internal | implemented |
| Redaction (two stages, value-checked identifiers, full-payload guard) | internal | implemented |

**Not implemented: a native Hermes-log importer.** `SUPPORTED_FORMATS` is
`("v1", "claude")`, so a selected Hermes run must reach this build through an approved
export/conversion step first. A native plugin wrapper does not by itself make native
traces consumable, and no converter ships in this repository.

## Not implemented — refused, never silently ignored

Each deferred lane has its own Phase 0 gate. Enabling one by setting its key produces a
**named refusal** from `import`, `export` and `status`; the lane-name → config-key
mapping is explicit, so a lane cannot be switched on without its refusal firing.

| Lane | Setting (default `false`) | Gate before it can ship |
|---|---|---|
| Native hook capture | `capture_enabled` | real host-emission tests at each advertised route; a non-policy observer hook set; proof that default capture never enters a fail-closed veto hook (`pre_tool_call`); overload/unload/reload behaviour; a route support matrix |
| Selected-session live read | `live_read_enabled` | a proven read-only path that leaves the source database, WAL and sidecars byte-unchanged under a live writer, with bounded retries and no repair path; no raw whole-database copy |
| Model narration | `llm_enabled` | an explicit egress/budget grant, a preview of exactly what would leave the machine, local schema validation, second-pass scrub, and audit provenance |
| Sandboxed experiments | `experiment_enabled` | a separately verified OS isolation backend, an owner-originated execution authority path, its own argv/input/env contract, and a one-time grant |

## Test lanes present

| Lane | Contents | What it is |
|---|---|---|
| `tests/unit` | 6 files | schema, clock/cost, report, timeline, diagnosis, packaging guards |
| `tests/adversarial` | 4 files | privacy (incl. credential-shaped id/ref refusals), stream inputs, archives, provenance |
| `tests/integration` | 5 files | Claude adapter, store, replay, parallel/retry, end-to-end |
| `tests/platform` | 1 file | **Linux surface/claim-honesty only** — asserts which lanes are implemented, that enabling a deferred lane refuses by name, and that no non-Linux support is implied. It is **not** native Windows/macOS verification. |
| `tests/host` | 1 file | install-alone against the pinned target host: data-driven no-mixed-tree guard, a negative control for that guard, an interpreter-identity record, and a real tool round-trip through the host registry. Fails BLOCKED (never green, never silently skipped) when host prerequisites are missing. |

## Open items requiring the owner

1. **Retention-policy sign-off (review R4).** `retention_mode` defaults to
   `redacted-summary`: prompt text and tool arguments are never retained and tool-result
   text is bounded and redacted, but a redacted summary *is* retained. That is a
   documented deviation from "minimal metadata only" and it **awaits your explicit
   approval before real sensitive traces are imported**. `metadata-only` is one setting
   away if you prefer the stricter default.
2. **Host-lane prerequisites (review R3).** The host gate needs an interpreter carrying
   the target host's own dependencies. `scripts/host-test-env.sh` is the provisioning
   recipe, and it installs packages, so it needs your approval before it is run.
3. **DT19 value benchmark.** Unrun: it needs 3–5 owner-labelled real runs in a supported
   format, plus any baseline/spend/egress decision that implies.
4. INSTALL, DEPLOY/soak and PUBLISH remain your gates.

## Corrections after the independent review (superseded statements kept)

The review of `e7abc33` found, correctly:

1. **Privacy (blocking; fixed).** Identifier/reference/digest keys were exempt from
   redaction and only `reported_error` was scrubbed, so a credential-shaped value in
   `trace.source.ref` (or `event_id`, `attempt_id`, `run_id`, `evidence_ref`,
   `arguments_ref`, `private_digests`) reached `runs.trace_json` unredacted. The blanket
   exemption is gone. Identifier values are now value-checked: a sensitive-shaped one
   **refuses the source** (no raw value persisted, no id silently rewritten), the scrub
   guard runs over **every** payload before any write, and a refusal message names a
   field *position* rather than echoing the value. Two further gaps the new tests found:
   token patterns anchored on `\b` were defeated by an id prefix (`att_ghp_…`,
   `run_sk-…`), and the refusal message itself echoed the credential.
2. **Reporting (fixed).** A known `output_tokens` turned an unknown `input_tokens` into
   `0`. Knownness is tracked per metric; an unknown field stays `null`/`unknown`, a
   measured `0` stays `0`, partially known aggregates carry a coverage line
   (`input tokens reported for 1 of 3 events`), and the aggregate `cost_kind` reports
   `mixed` when actual and estimated spend coexist instead of claiming `actual`.
3. **Host verification (fixed).** `<host-deps-python>` was a placeholder, the host lane
   ran in the plugin venv (missing `ruamel` — a BLOCKED verification, not a plugin
   defect), and `checks.sh` swallowed failures with `|| true`. The gate now names the
   interpreter and target source, requires both explicitly, exits non-zero (BLOCKED)
   when they are missing, records the interpreter identity to `HOST_EVIDENCE_DIR`, and
   guards source purity with a name set **derived from the pinned tree** (plus a negative
   control proving the guard fires on an outside-pin module).
4. **Receipts (fixed).** This file previously claimed no `tests/platform` existed while
   `tests/platform/test_matrix.py` existed and passed, and the retention deviation had no
   owner sign-off. Both are corrected above; the superseded statements are kept in the
   history below rather than edited away.

Earlier form of the two corrected statements, retained verbatim:
`"tests/unit, tests/adversarial, tests/integration, tests/host. No tests/platform exists
yet"` and `"5. Identifier fields pass through redaction unchanged."`

## Deliberate deviations from the planning document

1. **`retention_mode` setting added** (`redacted-summary` default, `metadata-only`
   alternative) — prompt text and tool arguments are never retained; bounded, redacted
   tool-result summaries are, and the operator can switch even those off.
   Reason: the plan requires explicit, configurable content retention. **Approval
   pending** (see Open items 1).
2. **Event schema gained `name` and `arguments_ref`** — a timeline that cannot say
   *which* tool failed is not useful; arguments remain references, never payloads.
   Documented in `schemas/trace-v1.json`.
3. **`export` refuses on the slash route before parsing** — no partial parse can produce
   a write; the refusal is byte-identical in tests.
4. **`provides_middleware` omitted from the manifest** — the target host reports it as an
   unknown field and this build registers no middleware.
5. **Identifier fields are value-checked, not exempted** — supersedes the earlier
   blanket-exemption deviation (see correction 1).
