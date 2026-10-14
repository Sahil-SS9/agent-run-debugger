# Provenance — where every claim in this plugin comes from

## The four provenance values

| Value | Meaning | Example |
|---|---|---|
| `observed` | This plugin watched it happen, or computed it directly from bytes it read | the file digest of a selected source; a wall-clock gap computed from two recorded timestamps |
| `reported` | A source said so, and this plugin repeats it unchanged | an event's `reported_status`, a token count, a wrapper's exit code, an imported error string |
| `inferred` | This plugin derived it by comparing records | a completed-outcome-with-failures contradiction; a loop shape; a suspect gap |
| `unknown` | The source did not say, and this plugin will not guess | missing billing, a run outcome the transcript never states, an unsupported record kind |

Provenance is attached to records, not to the document, and nothing is ever
upgraded: no rule in this build turns a `reported` value into `observed`.

## Source-level provenance

- **`v1` imports** carry their own envelope; the importer validates it and records
  the file's content digest. If the envelope lacks a source digest, the importer
  computes one from the bytes it read and says so in an import note.
- **Claude JSONL imports** record the documented source structure and the
  adapter's own decisions in `trace.completeness.notes` and in the import summary:
  split assistant records merged per request (maximum reported `output_tokens`
  kept), global `uuid` deduplication, prompt text and tool arguments reduced to
  opaque references, and any usage key that the Trace v1 contract does not carry
  dropped with its name listed.
- **Unsupported record types** are counted and named in a note. They are never
  guessed into an event kind.

## What is deliberately not a provenance claim

- An `evidence_ref` is a pointer into the selected source. It is **not** a receipt:
  it is not checked, authenticated, signed or verified. Reports say so.
- A content digest binds bytes. It does not authenticate who produced them, and it
  does not authorise anything.
- Token counts are the source's reported figures. They are not money, and this
  build never converts them without a named price source.
- A timeline position is a display of the recorded causal order. Concurrent events
  are reported as ambiguous pairs because wall-clock order alone is not causation.

## Adaptations and attribution

`THIRD_PARTY_NOTICES.md` records the licence basis for the one foreign adapter.
Behavioural conformance cases (split-request merging, uuid deduplication, subagent
transcript labelling, human-turn detection) are attributed there; the
implementation is independent Python, not a port of the upstream JavaScript.
