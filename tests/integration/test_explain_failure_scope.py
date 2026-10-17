"""Follow-up correction — a failed operation is NOT a terminal failure of the run.

Regression file for the paired-retention follow-up. The property under test is the
*scope* of the failure statement, not merely its confidence label:

* the source-reported failed operations and their evidence references survive;
* an unrecovered operation is distinguished from later run activity, from a
  reported task outcome, and from an unknown terminal outcome;
* a later success of a *different* operation does not prove recovery of the failed
  one, but continued activity must still stop the diagnosis from implying that the
  whole run stopped at that step;
* missing terminal evidence cannot carry a high-confidence run-finality claim.

Every case below is driven through the real explain path
(``Services.import_sources`` -> ``Services.explain_text``), not by calling
``diagnose()`` directly, so the imported record shape and the public surface are
both exercised. Fixtures are synthetic and labelled as such.
"""

from __future__ import annotations

import json

from hermes_run_debugger.cli import Services

#: Phrases that assert the run stopped at the failed step. The correction removes them.
FINALITY_PHRASES = ("terminal tool failure", "terminal run failure", "the run stopped")


def _header(run_id: str, *, completeness="complete", missing_kinds=(), notes=()):
    return {
        "kind": "trace",
        "schema": "hermes-run-debugger/trace",
        "version": 1,
        "trace_id": f"trace-{run_id}",
        "run_id": run_id,
        "importer": "follow-up-regression",
        "importer_version": "1.0.0",
        "source_format": "event-v1",
        "source_scope": "explicit-selection",
        "created_at": "2026-10-16T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "a" * 64, "name": f"{run_id}.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["tool_call", "model_call", "note"],
        "unsupported_kinds": [],
        "completeness": {
            "status": completeness,
            "missing_kinds": list(missing_kinds),
            "notes": [*list(notes), "SYNTHETIC FIXTURE: not a benchmark case"],
        },
    }


def _attempt(run_id: str, outcome: str):
    return {
        "kind": "attempt",
        "attempt_id": "att-1",
        "run_id": run_id,
        "parent_attempt_id": None,
        "model": "example-model",
        "provider": "example-provider",
        "role": "primary",
        "branch": "main",
        "sequence": 0,
        "started_at": "2026-10-16T10:00:00Z",
        "ended_at": "2026-10-16T10:05:00Z",
        "outcome": outcome,
        "unknowns": [],
    }


def _event(event_id, seq, kind, status, *, span=None, parent=None, error=None, name=None):
    return {
        "kind": "event",
        "event_id": event_id,
        "run_id": "PLACEHOLDER",
        "attempt_id": "att-1",
        "span_id": span,
        "causal_parents": [parent] if parent else [],
        "source_sequence": seq,
        "wall_time": f"2026-10-16T10:00:{seq:02d}Z",
        "monotonic_ms": seq * 1000,
        "clock": {"source": "monotonic", "quality": "high"},
        "event_kind": kind,
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


def _explain(tmp_path, run_id, *, outcome, events, completeness="complete",
             missing_kinds=(), notes=(), store_name="store"):
    records = [_header(run_id, completeness=completeness, missing_kinds=missing_kinds, notes=notes),
               _attempt(run_id, outcome)]
    for event in events:
        event["run_id"] = run_id
        records.append(event)
    path = tmp_path / f"{run_id}.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    with Services(data_dir=tmp_path / store_name) as services:
        imported = services.import_sources([path], fmt="v1")[0]
        diagnosed = json.loads(services.explain_text(imported["run_id"], as_json=True))
        return imported, diagnosed


def _r002(diagnosed):
    return next((h for h in diagnosed["hypotheses"] if h["rule_id"] == "R002"), None)


def _observed_failures(diagnosed):
    return [item for item in diagnosed["observed"] if item["kind"].startswith("failure:")]


def test_failed_operation_followed_by_continuation_is_not_a_run_finality_claim(tmp_path):
    """CASE-01's shape: a failed operation, then the run carries on and completes."""
    imported, diagnosed = _explain(
        tmp_path, "cont", outcome="completed",
        events=[
            _event("e0", 0, "model_call", "ok", name="example-model"),
            _event("e1", 1, "tool_call", "failed", parent="e0", name="Bash",
                   error="This command requires approval"),
            _event("e2", 2, "model_call", "ok", parent="e0", name="example-model"),
            _event("e3", 3, "tool_call", "ok", parent="e2", name="Read"),
        ],
    )
    assert imported["events"] == 4
    assert [item["event_ref"] for item in _observed_failures(diagnosed)] == ["e1"]

    hypothesis = _r002(diagnosed)
    assert hypothesis is not None, "the failed operation must still be diagnosed"
    assert list(hypothesis["evidence_refs"]) == ["e1"]
    statement = hypothesis["statement"].lower()
    assert "consistent with" in statement
    assert not any(phrase in statement for phrase in FINALITY_PHRASES), hypothesis["statement"]
    assert "continued" in statement, hypothesis["statement"]
    assert hypothesis["confidence"] != "high", hypothesis["confidence"]


def test_later_unrelated_success_does_not_prove_recovery_of_the_failed_operation(tmp_path):
    """A different tool succeeding later is neither recovery nor finality."""
    _, diagnosed = _explain(
        tmp_path, "unrelated", outcome="completed",
        events=[
            _event("e0", 0, "tool_call", "failed", name="Bash", error="blocked by policy"),
            _event("e1", 1, "tool_call", "ok", name="Read"),
        ],
    )
    hypothesis = _r002(diagnosed)
    assert hypothesis is not None
    assert list(hypothesis["evidence_refs"]) == ["e0"], "the failed operation stays unrecovered"
    statement = hypothesis["statement"].lower()
    assert "continued" in statement
    assert not any(phrase in statement for phrase in FINALITY_PHRASES)


def test_recorded_linked_recovery_is_not_counted_as_unrecovered(tmp_path):
    """Same operation, same span, later success: the operation recovered."""
    _, diagnosed = _explain(
        tmp_path, "recovered", outcome="completed",
        events=[
            _event("e0", 0, "tool_call", "failed", span="span-1", name="Bash", error="transient"),
            _event("e1", 1, "tool_call", "ok", span="span-1", parent="e0", name="Bash"),
        ],
    )
    assert [item["event_ref"] for item in _observed_failures(diagnosed)] == ["e0"], \
        "the failed operation is still observed"
    hypothesis = _r002(diagnosed)
    assert hypothesis is None or "e0" not in list(hypothesis["evidence_refs"]), \
        "a recorded linked recovery must not be reported as unrecovered"


def test_failure_without_a_terminal_record_reports_an_unknown_terminal_outcome(tmp_path):
    _, diagnosed = _explain(
        tmp_path, "noterminal", outcome="unknown",
        events=[_event("e0", 0, "tool_call", "failed", name="Bash", error="stopped")],
    )
    hypothesis = _r002(diagnosed)
    assert hypothesis is not None
    statement = hypothesis["statement"].lower()
    assert not any(phrase in statement for phrase in FINALITY_PHRASES), hypothesis["statement"]
    assert "unknown" in statement or "not recorded" in statement, hypothesis["statement"]
    assert hypothesis["confidence"] != "high"


def test_supported_reported_terminal_failure_is_reported_as_the_sources_own_report(tmp_path):
    _, diagnosed = _explain(
        tmp_path, "reported-terminal", outcome="failed",
        events=[_event("e0", 0, "tool_call", "failed", name="Bash", error="exit 2")],
    )
    hypothesis = _r002(diagnosed)
    assert hypothesis is not None
    statement = hypothesis["statement"].lower()
    assert "reported" in statement and "failed" in statement, hypothesis["statement"]
    assert hypothesis["confidence"] != "high", \
        "a reported outcome without terminal event evidence is at most medium"


def test_blocking_gap_lowers_confidence_below_medium(tmp_path):
    """A missing causal parent is a blocking gap: the step-scoped claim weakens to low."""
    _, diagnosed = _explain(
        tmp_path, "gapped", outcome="failed",
        events=[
            _event("e0", 0, "model_call", "ok", parent="e-absent", name="example-model"),
            _event("e1", 1, "tool_call", "failed", parent="e0", name="Bash", error="exit 2"),
        ],
    )
    hypothesis = _r002(diagnosed)
    assert hypothesis is not None
    assert hypothesis["confidence"] == "low", hypothesis["confidence"]


def test_clean_control_keeps_no_failure_claim(tmp_path):
    imported, diagnosed = _explain(
        tmp_path, "clean", outcome="completed",
        events=[
            _event("e0", 0, "model_call", "ok", name="example-model"),
            _event("e1", 1, "tool_call", "ok", parent="e0", name="Bash"),
        ],
    )
    assert imported["events"] == 2
    assert _r002(diagnosed) is None
    assert _observed_failures(diagnosed) == []
    assert diagnosed["causal_findings"] == []
