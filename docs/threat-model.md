# Threat model — what this plugin can and cannot be trusted to do

## Trust boundary in one line

Imported traces, source files, repository instructions and model output are
**untrusted data**. They are displayed, parsed and reasoned about; they are never
authority, never instructions and never a receipt.

## Assets

1. The operator's source transcripts (possibly containing credentials, paths, PII).
2. The operator's profile-local store and any private export.
3. The operator's agent run — a debugger must not block or alter it.
4. The operator's decision quality: a wrong "cause" costs more than a slow answer.

## Adversaries and abuse cases

| # | Threat | Control |
|---|---|---|
| T1 | A trace crafted to execute code (shell metacharacters, HTML/script, JSON injection, terminal escapes) | Importer never executes anything; report text is escaped per format; control sequences stripped; replay is inert (spies on `subprocess`, `socket`, `urllib`, `sqlite3` must stay untouched). |
| T2 | A trace crafted to make the debugger assert a false cause ("receipt: tests=42 failures=0") | A success flag, a receipt-shaped string and a zero-test run never become a correctness claim; a completed outcome with failing events is reported as a contradiction; `causal_findings` is empty by design. |
| T3 | A wrapper's exit code presented as task success | Wrapper-vs-child ambiguity is a named hypothesis with both readings as alternatives, never resolved by the tool. |
| T4 | Missing logs asserted as cause | Absent parents and truncation are visible gaps; a blocking gap caps every hypothesis at `low` confidence; missing evidence is listed explicitly. |
| T5 | Secrets leaking into the store, journal, error log or export | Redaction before persistence and again before export; whole sensitive keys dropped; second-stage scrub guard refuses rather than publishing; export is operator-CLI only with `0600` perms; tests assert seeded secrets are absent from every file the run writes. |
| T6 | A trace used to smuggle instructions to the agent | Nothing in an imported record is treated as an instruction. There is no "execute this", no auto-repair, and no model-narration lane in this build. |
| T7 | A cyclic/contradictory parent graph silently ordered into a story | Cyclic graphs are refused; with `quarantine=True` the offending events are isolated and reported as contradictory rather than ordered. |
| T8 | Resource exhaustion via a malicious trace (bomb, huge line, deep nesting, event flood) | Byte, line, event and JSON-depth caps with named limits (`max_bytes`, `max_line_bytes`, `max_events`, `max_depth`); non-finite numbers refused; archives and raw databases refused *before* any extraction exists. |
| T9 | Archive traversal / symlink / hardlink escape | No extraction code path exists in this build. The refusal states the bar a future adapter must clear (member count, size, ratio, paths, symlinks, hardlinks). |
| T10 | The debugger blocking or slowing the operator's agent | No hooks registered at all; the fail-closed `pre_tool_call` hook is never touched; no daemon, no background worker, no network. |
| T11 | Cross-profile leakage (one profile's runs read by another) | Store path is resolved per operation from the active profile; nothing is cached across profiles; a test runs two store directories and asserts isolation. |
| T12 | Deletion damage: removing the user's own source files | `delete_run`/`prune` touch only owned record ids and never follow a stored path; a test asserts the source file survives, byte-identical. |

## Explicit non-goals

- No always-on collector, no production APM replacement.
- No credential inspection or credential store.
- No automatic repairs or self-modification.
- No claim of root cause from incomplete logs.
- No OS sandbox: this build performs no program execution, so it needs none. A
  future experiment lane requires a separately verified isolation backend and
  refuses to run when none is available.

## Residual risk (accepted, visible)

- Deterministic redaction cannot detect unknown secret formats (see
  `docs/privacy.md`). Reports say so in their own limitations section.
- Imported traces can be incomplete without looking incomplete; that is why
  completeness, gaps and provenance are displayed next to totals.
- A user who exports a report and shares it is choosing to share the redacted
  content it contains. The plugin never uploads anything itself.
