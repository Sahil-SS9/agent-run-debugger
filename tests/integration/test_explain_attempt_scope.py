"""Attempt scope for R002 — a failure belongs to an attempt, not to the run.

Regression file for the review of the R002 operation-versus-run correction. Two
properties are tested through the real explain path:

* the **reported outcome** quoted by R002 must come from the attempt that
  recorded the failing operation, not from any other attempt in the run. Retry
  chains and subagent branches are first-class in this schema (``attempt``
  records carry ``parent_attempt_id``, ``role`` and ``branch``), so quoting
  another attempt's outcome describes evidence the source does not have;
* a later success in a **different attempt** is not recovery of the failed
  operation. Only a later success of the same operation in the same attempt
  counts, which is what ``_later_success`` claims to test.

The two ATTEMPT-01/02 shapes below are the ones a retry chain or a subagent
session produces. Fixtures are synthetic and labelled as such; every case is
driven through ``Services.import_sources`` -> ``Services.explain_text``.
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
        "importer": "attempt-scope-regression",
        "importer_version": "1.0.0",
        "source_format": "event-v1",
        "source_scope": "explicit-selection",
        "created_at": "2026-10-18T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "a" * 64, "name": f"{run_id}.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["tool_call", "model_call", "note"],
        "unsupported_kinds": [],
        "completeness": {
            "status": "complete",
            "missing_kinds": [],
            "notes": ["SYNTHETIC FIXTURE: not a benchmark case"],
        },
    }


def _attempt(attempt_id, sequence, *, parent=None, outcome="unknown", role="primary"):
    return {
        "kind": "attempt",
        "attempt_id": attempt_id,
        "run_id": "PLACEHOLDER",
        "parent_attempt_id": parent,
        "model": "example-model",
        "provider": "example-provider",
        "role": role,
        "branch": "main",
        "sequence": sequence,
        "started_at": "2026-10-18T10:00:00Z",
        "ended_at": "2026-10-18T10:05:00Z",
        "outcome": outcome,
        "unknowns": [],
    }


def _event(event_id, seq, status, attempt_id, *, span=None, name=None, error=None):
    return {
        "kind": "event",
        "event_id": event_id,
        "run_id": "PLACEHOLDER",
        "attempt_id": attempt_id,
        "span_id": span,
        "causal_parents": [],
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


def _explain(tmp_path, run_id, *, attempts, events):
    records = [_header(run_id)]
    for attempt in attempts:
        attempt["run_id"] = run_id
        records.append(attempt)
    for event in events:
        event["run_id"] = run_id
        records.append(event)
    path = tmp_path / f"{run_id}.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    with Services(data_dir=tmp_path / "store") as services:
        imported = services.import_sources([path], fmt="v1")[0]
        diagnosed = json.loads(services.explain_text(imported["run_id"], as_json=True))
    return imported, diagnosed


def _r002(diagnosed):
    return next((h for h in diagnosed["hypotheses"] if h["rule_id"] == "R002"), None)


# --- ATTEMPT-01: the quoted outcome belongs to the attempt that failed --------


def test_reported_outcome_is_taken_from_the_attempt_that_recorded_the_failure(tmp_path):
    """A retry chain: attempt 1 completed, the failed operation lives in attempt 2.

    Attempt 2 reports no outcome of its own, so the only truthful value for
    "the attempt outcome" is unknown. Quoting attempt 1's "completed" describes
    an attempt that did not record this failure.
    """
    _, diagnosed = _explain(
        tmp_path,
        "retry-chain",
        attempts=[
            _attempt("att-1", 0, outcome="completed"),
            _attempt("att-2", 1, parent="att-1", outcome="unknown"),
        ],
        events=[
            _event("e1", 0, "ok", "att-1", name="Read"),
            _event("e2", 1, "failed", "att-2", span="toolu_2", error="denied"),
        ],
    )
    hypothesis = _r002(diagnosed)
    assert hypothesis is not None, "the failed operation must still be diagnosed"
    assert list(hypothesis["evidence_refs"]) == ["e2"]
    statement = hypothesis["statement"].lower()
    assert "reported completed" not in statement, (
        "the outcome of a different attempt was quoted as this attempt's outcome: "
        f"{hypothesis['statement']}"
    )
    assert "reported failed" not in statement, hypothesis["statement"]
    assert "unknown" in statement or "not recorded" in statement, hypothesis["statement"]


def test_quoted_outcome_still_works_when_the_failing_attempt_reports_it(tmp_path):
    """Control: a single attempt that reports failed is still described as failed."""
    _, diagnosed = _explain(
        tmp_path,
        "single-attempt",
        attempts=[_attempt("att-1", 0, outcome="failed")],
        events=[_event("e1", 0, "failed", "att-1", name="Bash", error="exit 2")],
    )
    hypothesis = _r002(diagnosed)
    assert hypothesis is not None
    statement = hypothesis["statement"].lower()
    assert "reported" in statement and "failed" in statement, hypothesis["statement"]
    assert hypothesis["confidence"] != "high"


# --- ATTEMPT-02: a different attempt is not a retry of the same operation ----


def test_later_success_in_a_different_attempt_is_not_recovery(tmp_path):
    """A subagent attempt succeeded at a same-named tool; that is not a retry.

    Both events carry no span, so a name-only match would read as recovery and
    the failure would disappear from the diagnosis entirely.
    """
    _, diagnosed = _explain(
        tmp_path,
        "cross-attempt",
        attempts=[
            _attempt("att-1", 0, outcome="failed"),
            _attempt("att-2", 1, parent="att-1", outcome="unknown", role="subagent"),
        ],
        events=[
            _event("e1", 0, "failed", "att-1", name="Bash", error="exit 1"),
            _event("e2", 1, "ok", "att-2", name="Bash"),
        ],
    )
    hypothesis = _r002(diagnosed)
    assert hypothesis is not None, (
        "a same-named success in another attempt was treated as recovery of the "
        "failed operation, so the failure is not reported at all"
    )
    assert list(hypothesis["evidence_refs"]) == ["e1"]


def test_later_success_in_the_same_attempt_is_still_recovery(tmp_path):
    """Control: the same operation succeeding later in the same attempt recovers."""
    _, diagnosed = _explain(
        tmp_path,
        "same-attempt",
        attempts=[_attempt("att-1", 0, outcome="completed")],
        events=[
            _event("e1", 0, "failed", "att-1", span="span-1", name="Bash", error="transient"),
            _event("e2", 1, "ok", "att-1", span="span-1", name="Bash"),
        ],
    )
    hypothesis = _r002(diagnosed)
    assert hypothesis is None or "e1" not in list(hypothesis["evidence_refs"]), (
        "a recorded same-attempt recovery must not be reported as unrecovered"
    )
