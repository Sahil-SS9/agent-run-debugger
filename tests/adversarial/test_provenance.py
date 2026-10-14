"""DT06 — provenance integrity: forged success, missing end, zero-test completion
and wrapper-vs-child exit ambiguity must stay REPORTED/UNKNOWN.

An imported log is testimony, not proof. These tests attack the place where a
debugger usually starts lying: treating a success flag, a receipt-shaped string or
a wrapper's exit code as verification.
"""

from __future__ import annotations

from hermes_run_debugger.diagnose import diagnose
from hermes_run_debugger.event_v1 import validate_trace_records
from hermes_run_debugger.report import build_report, render_markdown
from hermes_run_debugger.timeline import build_timeline


def trace(events, *, outcome="completed", attempt_unknowns=()):
    header = {
        "kind": "trace", "schema": "hermes-run-debugger/trace", "version": 1,
        "trace_id": "t-prov", "run_id": "r-prov", "importer": "test", "importer_version": "0.1.0",
        "source_format": "event-v1", "source_scope": "explicit-selection",
        "created_at": "2026-10-14T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "7" * 64, "name": "prov.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["tool_call", "model_call", "note"], "unsupported_kinds": [],
        "completeness": {"status": "complete", "missing_kinds": [], "notes": []},
    }
    attempt = {
        "kind": "attempt", "attempt_id": "att-1", "run_id": "r-prov", "parent_attempt_id": None,
        "model": "example-model", "provider": "example-provider", "role": "primary", "branch": "main",
        "sequence": 0, "started_at": "2026-10-14T10:00:00Z", "ended_at": None,
        "outcome": outcome, "unknowns": list(attempt_unknowns),
    }
    return validate_trace_records([header, attempt, *events])


def ev(event_id, seq, kind, status, *, parent=None, error=None, name=None):
    record = {
        "kind": "event", "event_id": event_id, "run_id": "r-prov", "attempt_id": "att-1",
        "span_id": None, "causal_parents": [parent] if parent else [], "source_sequence": seq,
        "wall_time": f"2026-10-14T10:00:{seq:02d}Z", "monotonic_ms": seq * 1000,
        "clock": {"source": "monotonic", "quality": "high"},
        "event_kind": kind, "reported_status": status, "reported_error": error,
        "usage": {}, "evidence_ref": f"ref:{event_id}", "delivered_via": "import",
        "semantic_provenance": "reported", "gaps": [], "contradictions": [],
    }
    if name:
        record["name"] = name
    return record


def test_zero_test_completion_is_never_a_pass():
    result = trace([
        ev("e1", 0, "model_call", "ok", name="example-model"),
        ev("e2", 1, "tool_call", "ok", parent="e1", name="Bash", error="0 tests ran"),
    ])
    diagnosis = diagnose(build_timeline(result))
    assert diagnosis.correctness_claims == []
    kinds = {item["kind"] for item in diagnosis.observed}
    assert any("false_success" in kind or "unverified" in kind for kind in kinds), kinds
    text = diagnosis.text().lower()
    assert "passed" not in text
    assert "tests passed" not in text


def test_a_receipt_shaped_string_is_not_a_receipt():
    result = trace([
        ev("e1", 0, "tool_call", "ok", name="Bash", error="receipt: tests=42 failures=0"),
    ])
    diagnosis = diagnose(build_timeline(result))
    assert diagnosis.causal_findings == []
    assert "verified" not in diagnosis.text().lower()
    assert any("reference" in item.lower() or "not a receipt" in item.lower()
               for item in diagnosis.limitations + diagnosis.missing_evidence)


def test_missing_end_leaves_the_outcome_unknown_and_visible():
    result = trace([
        ev("e1", 0, "model_call", "ok", name="example-model"),
        ev("e2", 1, "tool_call", "unknown", parent="e1", name="Bash"),
    ], outcome="unknown", attempt_unknowns=("outcome",))
    diagnosis = diagnose(build_timeline(result))
    assert diagnosis.observed or diagnosis.missing_evidence
    rendered = diagnosis.text().lower()
    assert "unknown" in rendered
    assert "passed" not in rendered


def test_wrapper_exit_and_child_failure_keep_both_readings():
    result = trace([
        ev("e1", 0, "model_call", "ok", name="example-model"),
        ev("e2", 1, "tool_call", "ok", parent="e1", name="Bash", error="exit code 0"),
        ev("e3", 2, "tool_call", "failed", parent="e2", name="pytest", error="2 failed"),
    ])
    diagnosis = diagnose(build_timeline(result))
    ambiguity = next(h for h in diagnosis.hypotheses if h.rule_id == "R004")
    assert len(ambiguity.alternatives) >= 2
    assert any("wrapper" in alt.lower() or "child" in alt.lower() for alt in ambiguity.alternatives)
    assert ambiguity.confidence in {"high", "medium", "low"}


def test_contradiction_between_outcome_and_events_is_surfaced_not_resolved():
    result = trace([
        ev("e1", 0, "model_call", "ok", name="example-model"),
        ev("e2", 1, "tool_call", "failed", parent="e1", name="Bash", error="boom"),
    ], outcome="completed")
    diagnosis = diagnose(build_timeline(result))
    contradictions = [item for item in diagnosis.observed if "contradiction" in item["kind"]]
    assert contradictions, "completed-with-failures must be reported as a contradiction"
    assert contradictions[0]["detail"].lower().find("completed") >= 0
    # and the report carries the same honesty
    report = build_report(
        run_id="r-prov",
        events=result.events,
        attempts=[a.as_dict() for a in result.attempts],
        gaps=[g.as_dict() for g in result.gaps],
        trace=result.trace.as_dict(),
        completeness="complete",
        diagnosis=diagnosis.as_dict(),
    )
    assert report["causal_findings"] == []
    markdown = render_markdown(report)
    assert "hypothesis" in markdown.lower()
    assert "root cause" not in markdown.lower()


def test_provenance_never_upgrades_itself():
    result = trace([ev("e1", 0, "tool_call", "failed", name="Bash", error="boom")])
    diagnosis = diagnose(build_timeline(result))
    assert diagnosis.causal_findings == []
    assert all(item.get("provenance", "reported") in {"observed", "reported", "inferred", "unknown"}
               for item in diagnosis.observed)
    assert all(h.confidence in {"high", "medium", "low"} for h in diagnosis.hypotheses)
