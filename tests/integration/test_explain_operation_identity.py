"""Operation identity for R002 — a name match is not the same operation.

``_later_success`` decides whether a failed tool operation was recovered. It must not
infer that from anything short of genuine evidence that the *same* operation ran again.

Two ways a name-only match can go wrong:

* across attempts — a retry chain or subagent branch records its own tool calls
  (covered by ``test_explain_attempt_scope.py``);
* inside one attempt — two ``Read`` calls are different operations. Where the source
  gives an operation no span, the tool name carries no identity, so a later success of
  the same-named tool says nothing about the failed one.

Where the source *does* give an operation a span, the span is the identity and a later
success of that span is accepted. Where it does not, the later event must record a
causal link to the failed event before it counts as recovery.

Fixtures are synthetic and labelled as such; every case runs through
``Services.import_sources`` -> ``Services.explain_text``.
"""

from __future__ import annotations

import json

from hermes_run_debugger.cli import Services


def _header(run_id: str):
    return {
        "kind": "trace",
        "schema": "hermes-run-debugger/trace",
        "version": 1,
        "trace_id": f"trace-{run_id}",
        "run_id": run_id,
        "importer": "operation-identity-regression",
        "importer_version": "1.0.0",
        "source_format": "event-v1",
        "source_scope": "explicit-selection",
        "created_at": "2026-10-18T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "a" * 64, "name": f"{run_id}.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["tool_call"],
        "unsupported_kinds": [],
        "completeness": {
            "status": "complete",
            "missing_kinds": [],
            "notes": ["SYNTHETIC FIXTURE: not a benchmark case"],
        },
    }


def _attempt():
    return {
        "kind": "attempt",
        "attempt_id": "att-1",
        "run_id": "PLACEHOLDER",
        "parent_attempt_id": None,
        "model": "example-model",
        "provider": "example-provider",
        "role": "primary",
        "branch": "main",
        "sequence": 0,
        "started_at": "2026-10-18T10:00:00Z",
        "ended_at": "2026-10-18T10:05:00Z",
        "outcome": "completed",
        "unknowns": [],
    }


def _event(event_id, seq, status, *, span=None, name=None, parents=(), error=None):
    return {
        "kind": "event",
        "event_id": event_id,
        "run_id": "PLACEHOLDER",
        "attempt_id": "att-1",
        "span_id": span,
        "causal_parents": list(parents),
        "source_sequence": seq,
        "wall_time": f"2026-10-18T10:00:{seq:02d}Z",
        "monotonic_ms": seq * 1000,
        "clock": {"source": "monotonic", "quality": "high"},
        "event_kind": "tool_call",
        "reported_status": status,
        "reported_error": error,
        "usage": {},
        "evidence_ref": f"ref:{event_id}",
        "delivered_via": "import",
        "semantic_provenance": "reported",
        "gaps": [],
        "contradictions": [],
        "name": name,
    }


def _explain(tmp_path, run_id, events):
    records = [_header(run_id)]
    attempt = _attempt()
    attempt["run_id"] = run_id
    records.append(attempt)
    for event in events:
        event["run_id"] = run_id
        records.append(event)
    path = tmp_path / f"{run_id}.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    with Services(data_dir=tmp_path / "store") as services:
        imported = services.import_sources([path], fmt="v1")[0]
        return json.loads(services.explain_text(imported["run_id"], as_json=True))


def _r002(diagnosed):
    return next((h for h in diagnosed["hypotheses"] if h["rule_id"] == "R002"), None)


def test_same_named_tool_without_a_span_is_not_recovery(tmp_path):
    """Two span-less `Read` calls in one attempt are two different operations."""
    diagnosed = _explain(
        tmp_path,
        "name-only",
        events=[
            _event("e1", 0, "failed", name="Read", error="no such file"),
            _event("e2", 1, "ok", name="Read"),
        ],
    )
    hypothesis = _r002(diagnosed)
    assert hypothesis is not None, (
        "a later success of a same-named tool with no span was treated as recovery of "
        "the failed operation, so the failure is not reported at all"
    )
    assert list(hypothesis["evidence_refs"]) == ["e1"]


def test_recorded_causal_link_on_a_span_less_operation_is_recovery(tmp_path):
    """The same shape, but the retry records the failed event as its parent."""
    diagnosed = _explain(
        tmp_path,
        "causal-link",
        events=[
            _event("e1", 0, "failed", name="Read", error="transient"),
            _event("e2", 1, "ok", name="Read", parents=["e1"]),
        ],
    )
    hypothesis = _r002(diagnosed)
    assert hypothesis is None or "e1" not in list(hypothesis["evidence_refs"]), (
        "a retry that records its causal parent must count as recovery"
    )


def test_spanned_operation_still_recovers_on_a_later_success(tmp_path):
    """Control: when the source gives an operation a span, the span is the identity."""
    diagnosed = _explain(
        tmp_path,
        "spanned",
        events=[
            _event("e1", 0, "failed", span="toolu_1", error="transient"),
            _event("e2", 1, "ok", span="toolu_1"),
        ],
    )
    hypothesis = _r002(diagnosed)
    assert hypothesis is None or "e1" not in list(hypothesis["evidence_refs"])
