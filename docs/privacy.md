# Privacy — what is read, what is kept, what never leaves

## Default data flow

```
selected file(s) → bounded JSON/JSONL parse → strict Trace v1 validation
   → redaction (stage 1: pre-store) → scrub guard → profile-local SQLite store
   → analysis in memory → redaction (stage 2: pre-egress) → private report file
```

Redaction runs **before** the store, the journal and error logs see a value, and
again before anything is written to a report. There is no path that keeps a raw
record "for later".

## What is never retained by default

| Data | Treatment |
|---|---|
| Prompt / user-turn text | Never stored. A human turn becomes a note event with an opaque reference only. |
| Tool arguments | Never stored. Reduced to `arguments_ref`, an opaque digest reference. |
| Tool result text | Bounded (500 chars) and redacted, then stored. `retention_mode: metadata-only` keeps status and references only. |
| Provider headers, approval bodies, raw request bodies, reasoning/stream deltas | Whole keys are dropped (replaced by `[redacted:key:<name>]`), not truncated. |
| Source paths | Only the file's basename is stored; exports contain neither path nor basename. |
| Raw input digests | Private. Kept in the store for deduplication; omitted from exports, which use redacted digests and stable opaque references. |

## What redaction removes

Private-key blocks; OpenAI/GitHub/AWS/Slack-style tokens; JWTs; `keyword: value`
credential assignments; `Bearer <token>`; e-mail addresses; phone and card-like
numbers; home-directory paths (`/home/<user>` → `/home/<user>` masked to `<user>`);
IPv4 addresses; ANSI escape sequences and control characters.

## What redaction cannot do (stated, not hidden)

- Unknown or invented credential formats, secrets split across fields, encoded or
  reversed payloads, and secrets inside binary blobs are **not** detected.
- **Identifier fields are value-checked, not exempted.** Event, attempt, span, run and
  reference ids are bounded tokens used to link evidence, so they are *not* rewritten
  silently — but being id-shaped is not a security property (a credential is printable).
  A sensitive-shaped value in an id, reference or digest field **refuses the whole
  source**: nothing is persisted, and no identifier is quietly altered. Refusal
  messages name a field *position* and never echo the value.
- Digest-shaped fields (`private_digests`, `sha256`) accept **digest grammar only**
  (bare hex, `sha256:…` or `redacted-sha256:…`). Anything else there — including a
  credential dressed as a digest — refuses the source, because it means the trace is
  not the shape it claims to be.
- A standalone long digit run in free text is treated as card-like. That is deliberate
  over-redaction, and it is why identifiers are protected by *field name plus value
  check* rather than by pattern alone.
- A clean report means "no known shape matched", never "nothing sensitive was
  captured". `RedactionPolicy.limitations()` returns exactly this list at runtime.

## Second-stage guard

`scrub_guard_payload()` walks the **entire** redacted trace, attempt, event, gap and
source payload — every string, at any depth — and refuses to persist or export if any
high-risk value survives. It runs before the database, the WAL, the journal and any log
write, and its pattern set is built from the **default** policy, so a policy that
disables a category cannot disable the guard with it. The snapshot identity written to
the journal and revision columns is value-checked too. A refused import leaves no run
row and no file containing the value.

## Exports and sharing

- `export` is **operator-CLI only**: no agent tool, no slash subcommand, no gateway
  route. Those routes refuse, write nothing and upload nothing.
- Exports are written with mode `0600` and require an explicit output path.
- Export payloads contain opaque references (`run/…`, `event/…`) derived from a
  per-install salt kept in the private store. They stay linkable within one install
  and are not reversible to the original ids.
- Nothing is uploaded anywhere by this plugin. Sharing is a separate decision the
  operator makes outside it.

## Storage and retention

- One SQLite store per profile: `<hermes home>/plugin-data/agent-run-debugger/rundebug.db`.
- `retention_days` (default 90) governs pruning. Deletion targets **only owned
  record ids** and never follows a source-path reference: `delete_run` cannot touch
  the file the operator imported.
- Migrations copy the previous store file to a `0600` backup before changing the
  schema; the schema is only ever created through the migration chain.

## Failure behaviour

If scrubbing fails, or a value cannot be resolved to a safe state, the import is
refused and only minimal, safe error metadata is retained — no raw failed record,
no egress. A refused import is never partially presented as a successful one.
