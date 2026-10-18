# Agent Run Debugger

A local-first **evidence debugger** for failed, stalled or expensive agent runs.

Import one explicitly selected trace, get a deterministic timeline, observed
failure points, ranked hypotheses that name their own evidence, the evidence you
are missing, falsification checks you can run, and an inert replay of the
recorded timeline.

```
hermes run-debug import  --file ./selected-run.jsonl --format v1
hermes run-debug timeline --run <run-id>
hermes run-debug explain  --run <run-id>
hermes run-debug replay   --run <run-id>
hermes run-debug export   --run <run-id> --out ~/private/rundebug/report.md
hermes run-debug status
```

## What this is not

- Not a usage report, and not a model-written story: an LLM summary is a
  hypothesis, never causal proof.
- Not a command runner. `replay` re-reads the recorded timeline and executes
  nothing — no subprocess, no network, no live database.
- Not a guarantee of root cause. Missing logs stay visible as gaps, unknown
  billing stays `null`/UNKNOWN rather than `0`, and correlated anomalies are
  never asserted as cause.
- Not a telemetry collector. Default behaviour is offline import of a trace you
  selected. Capture, live session reads, model narration and real re-execution
  are separate opt-ins, each with its own gate.

## Harness support

The core is host-neutral: no module under `src/hermes_run_debugger/` imports the host, and
`adapters/hermes.py` is the only file that does. The plugin registers no hooks, no middleware,
no privileged capability and reads no environment variables, so it also runs with the host
absent — verified by driving the whole journey (import → timeline → explain → replay → export →
status) with no host package on `sys.path` and no `HERMES_HOME`.

Three import formats ship:

| Format | What it takes |
|---|---|
| `hermes` | `hermes sessions export --format jsonl` — the host's own session envelope, no conversion step |
| `v1` | the harness-neutral trace in `schemas/trace-v1.json` — any harness that can emit it is supported with no code change |
| `claude` | Claude Code JSONL session transcripts, via a tested adapter |

```sh
hermes sessions export --format jsonl --session-id <id> ./run.jsonl
hermes run-debug import --file ./run.jsonl --format hermes
```

Status comes only from an explicit signal in the source: a non-zero `exit_code` or a truthy
`error` means failed, a zero `exit_code` means ok, and a result carrying neither stays
`unknown` rather than being read as success. The host's `--format trace` export also imports
through the `claude` lane, but it drops the error flag on every tool result, so it cannot name a
failure — use `jsonl`.

Adding another harness means adding one adapter that maps its records onto `event-v1`; the
store, timeline, diagnosis, replay and report layers do not change. Reading a live session
database is a separate, separately gated lane (`live_read_enabled`), not part of import.

## Surfaces

| Surface | Route |
|---|---|
| CLI | `hermes run-debug import\|timeline\|explain\|replay\|export\|status` |
| Slash | `/rundebug <subcommand>` — the same read/import/analysis services |
| Agent tools | `rundebug_import`, `rundebug_timeline`, `rundebug_explain`, `rundebug_replay`, `rundebug_status` |

`export` is **operator-CLI-only**. There is no `rundebug_export` tool, no slash
export and no gateway export route: those routes refuse and write nothing,
because inert report viewing does not grant sharing permission.

## Privacy

- Minimal metadata by default; no raw prompt/result retention.
- Redaction runs **before** the store, the journal, error logs and again before
  export.
- Raw input digests stay local; exports carry redacted content digests and
  stable opaque refs.
- The store lives under `plugin-data/agent-run-debugger/` for the active
  profile. Deletion only ever targets owned record ids and never follows a
  source-path reference.

## Status

This is the v1 offline debugger: harness-neutral `event-v1` import, a tested
Claude JSONL adapter, a native Hermes session-export importer, deterministic
timeline/replay/diagnosis, safe local storage, CLI/slash/tool surfaces and a
private report. The native capture lane,
selected-session live reads, model narration and sandboxed experiments are
**not** in v1 — see `docs/status.md` for exactly what is implemented, what is
refused, and which Phase 0 gates each deferred lane still needs.

## Layout

```
plugin.yaml, __init__.py          # directory-plugin manifest + entry point
src/hermes_run_debugger/          # host-neutral domain core
  event_v1.py jsonio.py identity.py redact.py store.py migrations.py
  import_v1.py import_claude.py import_hermes.py timeline.py replay.py diagnose.py report.py
  settings.py cli.py
  adapters/hermes.py              # the only module that touches the host
schemas/                          # trace-v1 / diagnosis-v1 / report-v1
tests/{unit,adversarial,integration,platform,host}/
docs/                             # compatibility, privacy, threat model, provenance, status
```

## Development

```sh
uv sync --locked --extra dev
uv run python -m pytest tests/unit tests/adversarial --strict-markers -ra
uv run python -m pytest tests/integration --strict-markers -ra
uv run ruff check .
```

Nothing here installs into a live Hermes profile: the host test loads the
plugin from a checkout into a disposable `HERMES_HOME`.

Licensed under Apache-2.0. See `THIRD_PARTY_NOTICES.md` for the attribution
inventory.
