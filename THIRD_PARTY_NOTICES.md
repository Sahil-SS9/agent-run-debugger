# Third-party notices

This repository is licensed under Apache-2.0 (see `LICENSE`). This file records
every third-party component whose *behaviour or documentation* informed this build,
with its licence, so the adaptation is auditable.

## Adapted behavioural conformance: Claude transcript semantics

- **Source:** `anthropics/claude-plugins-official`, pinned at
  `8bd00f08f0b04705e610cf132fbe2cf5ec44cfe3`.
- **Component used:** `plugins/session-report` (skill + `analyze-sessions.mjs`).
- **Licence of that component:** Apache-2.0 (verified individually — the
  marketplace root README is a licence index, not a uniform grant).
- **What was taken:** the *documented, empirically discovered* structure of Claude
  session JSONL transcripts and the deduplication semantics, as behavioural
  conformance cases:
  - one API response is split across several `type:"assistant"` entries sharing a
    `requestId`/`message.id`, and only the last carries the final `output_tokens`
    → records are merged per request and the maximum is kept, so a run is not
    counted 3–10x;
  - resumed sessions re-serialise earlier entries into a new file → global `uuid`
    deduplication;
  - subagent transcripts live in `<project>/<sessionId>/subagents/*.jsonl` with an
    optional `*.meta.json` carrying `agentType`, otherwise a filename label;
  - a "human" turn is a plain-text `type:"user"` entry with falsy
    `isSidechain`/`isMeta`/`isCompactSummary`;
  - the cache/input token field names (`cache_read_input_tokens`,
    `cache_creation_input_tokens`).
- **What was NOT taken:** no source code, prompt, workflow, schema or documentation
  text was copied or translated. `src/hermes_run_debugger/import_claude.py` is an
  independent Python implementation of the Trace v1 contract, written against those
  documented semantics and covered by fixtures with an independently computed
  oracle (`tests/integration/test_import_claude.py`).
- **Explicitly excluded:** `plugins/claude-security` in the same repository is
  proprietary and forbids redistribution and non-Anthropic product use. **All** of
  its code, prompts, workflows, schemas and documentation are excluded from this
  work. Nothing here is derived from it.

## Behavioural influence, no code taken

- **`anthropics/claude-plugins-official` → `plugins/receipts`** (Apache-2.0): the
  evidence-honesty requirements (unknown values stay unknown; a context cost is not
  causally attributable to whichever tool happened to run). No personal-impact
  reporting and no git/history mining was adopted.

## Host platform

- **Hermes Agent** (`NousResearch/hermes-agent`, MIT) is the host this plugin
  targets. Its public plugin SDK, manifest format, storage helper and hook
  semantics are the integration contract documented in `docs/compatibility.md`.
  No host source file is modified, patched or vendored by this repository.

## Prior art considered (catalogue metadata only)

Catalogue entries for telemetry/debugging plugins were inspected as *pointers*, not
verified product behaviour, and none were used or depended on:
`hermes-telemetry`, `debug-desk`, `hermes-field-notes`. Differentiation claims are
deliberately not made from a shallow catalogue read.

## Runtime dependencies

None. The plugin and its tests use the Python standard library plus, for
development only, `pytest`, `ruff` and `build`. No bundled third-party assets, no
remote fonts, scripts or analytics in any generated report.
