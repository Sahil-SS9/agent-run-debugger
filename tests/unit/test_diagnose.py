"""D5 — diagnosis: observed failures, ranked hypotheses, falsifiers, unknowns.

The property under test is the boundary itself: a hypothesis must carry its
evidence, name alternatives and state how it could be falsified; correlation and
missing logs must never be promoted into a cause.
"""

from __future__ import annotations

from hermes_run_debugger.diagnose import (
    CONFIDENCE_CATEGORIES,
    diagnose,
)
from hermes_run_debugger.event_v1 import Gap, validate_trace_records
from hermes_run_debugger.timeline import build_timeline


def trace(events, *, outcome="failed", completeness="complete", missing_kinds=(), notes=()):
    header = {
        "kind": "trace", "schema": "hermes-run-debugger/trace", "version": 1,
        "trace_id": "t-dx", "run_id": "r-dx", "importer": "test", "importer_version": "0.1.0",
        "source_format": "event-v1", "source_scope": "explicit-selection",
        "created_at": "2026-10-14T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "9" * 64, "name": "dx.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["tool_call", "model_call", "provider_error", "note", "interrupt"],
        "unsupported_kinds": [],
        "completeness": {"status": completeness, "missing_kinds": list(missing_kinds), "notes": list(notes)},
    }
    attempt = {
        "kind": "attempt", "attempt_id": "att-1", "run_id": "r-dx", "parent_attempt_id": None,
        "model": "example-model", "provider": "example-provider", "role": "primary", "branch": "main",
        "sequence": 0, "started_at": "2026-10-14T10:00:00Z", "ended_at": "2026-10-14T10:05:00Z",
        "outcome": outcome, "unknowns": [],
    }
    return validate_trace_records([header, attempt, *events])


def ev(event_id, seq, kind, status, *, parent=None, error=None, name=None, mono=None,
       quality="high", usage=None, provenance="reported"):
    record = {
        "kind": "event", "event_id": event_id, "run_id": "r-dx", "attempt_id": "att-1",
        "span_id": None, "causal_parents": [parent] if parent else [], "source_sequence": seq,
        "wall_time": f"2026-10-14T10:00:{seq:02d}Z",
        "monotonic_ms": mono if mono is not None else seq * 1000,
        "clock": {"source": "monotonic" if mono is not None else "wall", "quality": quality},
        "event_kind": kind, "reported_status": status, "reported_error": error,
        "usage": usage or {}, "evidence_ref": f"ref:{event_id}", "delivered_via": "import",
        "semantic_provenance": provenance, "gaps": [], "contradictions": [],
    }
    if name:
        record["name"] = name
    return record


def run(events, **kw):
    result = trace(events, **kw)
    return diagnose(build_timeline(result))


def test_clean_run_produces_no_failure_claims_and_no_causal_finding():
    diagnosis = run([
        ev("e1", 0, "model_call", "ok", name="example-model"),
        ev("e2", 1, "tool_call", "ok", parent="e1", name="Bash"),
    ], outcome="completed")
    assert diagnosis.observed == []
    assert diagnosis.hypotheses == []
    assert diagnosis.causal_findings == []
    text = diagnosis.text().lower()
    assert "causal finding" in text
    assert "root cause" not in text
    assert all("caused by" not in h.statement.lower() for h in diagnosis.hypotheses)


def test_tool_failure_is_observed_with_a_falsifiable_hypothesis():
    diagnosis = run([
        ev("e1", 0, "model_call", "ok", name="example-model"),
        ev("e2", 1, "tool_call", "failed", parent="e1", name="Bash", error="command timed out"),
        ev("e3", 2, "tool_call", "failed", parent="e2", name="Bash", error="command timed out"),
        ev("e4", 3, "tool_call", "failed", parent="e3", name="Bash", error="command timed out"),
    ])
    assert [item["event_ref"] for item in diagnosis.observed] == ["e2", "e3", "e4"]
    hypothesis = next(h for h in diagnosis.hypotheses if h.rule_id == "R002")
    assert set(hypothesis.evidence_refs) <= {"e2", "e3", "e4"}
    assert hypothesis.evidence_refs
    assert hypothesis.alternatives, "an alternative explanation is mandatory"
    assert hypothesis.falsifiers, "a falsification check is mandatory"
    assert hypothesis.confidence in CONFIDENCE_CATEGORIES
    assert "consistent with" in hypothesis.statement.lower()


def test_repeated_identical_failures_are_flagged_as_a_loop_not_a_cause():
    diagnosis = run([
        ev(f"e{i}", i, "tool_call", "failed", name="Bash", error="boom") for i in range(5)
    ])
    loop = next(h for h in diagnosis.hypotheses if h.rule_id == "R003")
    assert loop.confidence in CONFIDENCE_CATEGORIES
    assert any("loop" in falsifier.lower() or "manual" in falsifier.lower() for falsifier in loop.falsifiers)


def test_provider_error_stop_point_and_retry_exhaustion():
    diagnosis = run([
        ev("e1", 0, "provider_error", "failed", error="529 overloaded"),
        ev("e2", 1, "provider_error", "failed", error="529 overloaded"),
        ev("e3", 2, "provider_error", "failed", error="529 overloaded"),
        ev("e4", 3, "provider_error", "failed", error="529 overloaded"),
    ])
    assertion = next(h for h in diagnosis.hypotheses if h.rule_id == "R001")
    assert assertion.confidence == "high", "four agreeing provider errors is strong evidence"
    assert len(assertion.evidence_refs) == 4
    assert assertion.alternatives


def test_missing_evidence_caps_confidence_and_is_listed():
    result = trace([
        ev("e1", 0, "model_call", "ok", name="example-model"),
        ev("e2", 1, "tool_call", "failed", parent="e1", name="Bash", error="timed out"),
    ])
    # a parent that is not in the trace becomes a visible gap
    result.gaps.append(Gap("missing_parent", "parent absent", "e2", "gone"))
    diagnosis = diagnose(build_timeline(result))
    assert any("gap" in item.lower() or "missing" in item.lower() for item in diagnosis.missing_evidence)
    for hypothesis in diagnosis.hypotheses:
        assert hypothesis.confidence == "low", "a blocking gap caps confidence"
        assert hypothesis.confidence == "low"


def test_correlation_is_not_asserted_as_cause():
    diagnosis = run([
        ev("e1", 0, "model_call", "ok", name="example-model"),
        ev("e2", 1, "tool_call", "failed", parent="e1", name="Bash", error="exit code 1"),
    ])
    blocked = ("caused by", "root cause", "because of", "proves that")
    rendered = diagnosis.text().lower()
    for phrase in blocked:
        assert phrase not in rendered, f"{phrase!r} asserts causation the evidence cannot support"
    assert all(
        phrase not in h.statement.lower() for h in diagnosis.hypotheses for phrase in blocked
    )


def test_cost_anomalies_are_observations_never_dollars():
    diagnosis = run([
        ev("e1", 0, "model_call", "ok", name="example-model",
           usage={"input_tokens": 900000, "output_tokens": 1}),
        ev("e2", 1, "tool_call", "failed", parent="e1", name="Bash", error="nope"),
    ])
    assert any("usage" in item["kind"] for item in diagnosis.observed)
    rendered = diagnosis.text()
    assert "$" not in rendered
    assert diagnosis.cost["reported_total"] is None
    assert diagnosis.cost["cost_kind"] == "unknown"


def test_diagnosis_is_deterministic():
    events = [
        ev("e1", 0, "model_call", "ok", name="example-model"),
        ev("e2", 1, "tool_call", "failed", parent="e1", name="Bash", error="boom"),
    ]
    first = run(events)
    second = run(events)
    assert first.as_dict() == second.as_dict()
    assert first.text() == second.text()


def test_every_hypothesis_is_fully_specified():
    diagnosis = run([
        ev("e1", 0, "provider_error", "failed", error="429 rate limit"),
        ev("e2", 1, "provider_error", "failed", error="429 rate limit"),
        ev("e3", 2, "provider_error", "failed", error="429 rate limit"),
    ])
    assert diagnosis.hypotheses
    for hypothesis in diagnosis.hypotheses:
        assert hypothesis.rule_id and hypothesis.statement
        assert hypothesis.evidence_refs
        assert hypothesis.alternatives
        assert hypothesis.falsifiers
        assert hypothesis.confidence in CONFIDENCE_CATEGORIES
    assert diagnosis.next_diagnostics, "read-only next steps are part of the output"
    assert all("read-only" in step.lower() or "no execution" in step.lower()
               for step in diagnosis.next_diagnostics)
