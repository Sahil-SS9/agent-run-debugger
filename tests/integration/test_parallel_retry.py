"""DT07 — retry, fork/join, interrupt and provider faults keep ids and parents.

Parallel work is the case where a debugger most easily invents a sequence. These
tests require retry chains and forks to survive import with their identities
intact and without a fabricated order.
"""

from __future__ import annotations

from hermes_run_debugger.diagnose import diagnose
from hermes_run_debugger.event_v1 import validate_trace_records
from hermes_run_debugger.timeline import build_timeline


def build(events, attempts):
    header = {
        "kind": "trace", "schema": "hermes-run-debugger/trace", "version": 1,
        "trace_id": "t-par", "run_id": "r-par", "importer": "test", "importer_version": "0.1.0",
        "source_format": "event-v1", "source_scope": "explicit-selection",
        "created_at": "2026-10-14T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "3" * 64, "name": "par.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["tool_call", "model_call", "retry", "interrupt", "provider_error"],
        "unsupported_kinds": [],
        "completeness": {"status": "complete", "missing_kinds": [], "notes": []},
    }
    return validate_trace_records([header, *attempts, *events])


def attempt(attempt_id, sequence, *, parent=None, outcome="failed", branch="main", role="primary"):
    return {
        "kind": "attempt", "attempt_id": attempt_id, "run_id": "r-par", "parent_attempt_id": parent,
        "model": "example-model", "provider": "example-provider", "role": role, "branch": branch,
        "sequence": sequence, "started_at": "2026-10-14T10:00:00Z", "ended_at": None,
        "outcome": outcome, "unknowns": [],
    }


def ev(event_id, seq, kind, status, *, attempt_id="att-1", parent=None, error=None, name=None):
    record = {
        "kind": "event", "event_id": event_id, "run_id": "r-par", "attempt_id": attempt_id,
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


def test_retry_attempt_chain_is_preserved():
    attempts = [
        attempt("att-1", 0),
        attempt("att-2", 1, parent="att-1"),
        attempt("att-3", 2, parent="att-2"),
    ]
    events = [
        ev("e1", 0, "provider_error", "failed", attempt_id="att-1", error="503"),
        ev("e2", 1, "retry", "ok", attempt_id="att-2", parent="e1"),
        ev("e3", 2, "provider_error", "failed", attempt_id="att-2", parent="e2", error="503"),
        ev("e4", 3, "retry", "ok", attempt_id="att-3", parent="e3"),
    ]
    result = build(events, attempts)
    timeline = build_timeline(result)
    assert [a.parent_attempt_id for a in result.attempts] == [None, "att-1", "att-2"]
    ordered = [entry.event_id for entry in timeline.entries]
    assert ordered == ["e1", "e2", "e3", "e4"], "the recorded chain is respected"
    assert [entry.depth for entry in timeline.entries] == [0, 1, 2, 3]
    assert timeline.ambiguous_pairs == [], "a recorded chain has no ambiguous pairs"


def test_fork_and_join_keep_both_children_visible_and_ambiguous():
    attempts = [
        attempt("att-1", 0),
        attempt("att-2", 1, parent="att-1", branch="child-a", role="subagent"),
        attempt("att-3", 2, parent="att-1", branch="child-b", role="subagent"),
    ]
    events = [
        ev("root", 0, "model_call", "ok", name="example-model"),
        ev("child-a", 1, "tool_call", "ok", attempt_id="att-2", parent="root", name="Bash"),
        ev("child-b", 2, "tool_call", "failed", attempt_id="att-3", parent="root", name="Read",
           error="no such file"),
        ev("join", 3, "model_call", "ok", parent="child-a", name="example-model"),
        ev("join2", 4, "model_call", "ok", parent="child-b", name="example-model"),
    ]
    timeline = build_timeline(build(events, attempts))
    pairs = {tuple(sorted(pair)) for pair in timeline.ambiguous_pairs}
    assert ("child-a", "child-b") in pairs
    by_id = {entry.event_id: entry for entry in timeline.entries}
    assert by_id["root"].depth == 0
    assert by_id["child-a"].depth == 1 and by_id["child-b"].depth == 1
    assert by_id["join"].depth == 2 and by_id["join2"].depth == 2
    # both children are represented: no child silently merged into the other
    assert {entry.event_id for entry in timeline.entries} == {"root", "child-a", "child-b", "join", "join2"}


def test_interrupt_and_provider_fault_are_distinguished():
    events = [
        ev("e1", 0, "model_call", "ok", name="example-model"),
        ev("e2", 1, "interrupt", "interrupted", parent="e1", error="operator stop"),
        ev("e3", 2, "provider_error", "failed", parent="e2", error="connection reset"),
    ]
    diagnosis = diagnose(build_timeline(build(events, [attempt("att-1", 0, outcome="interrupted")])))
    kinds = {item["kind"] for item in diagnosis.observed}
    assert any("interrupt" in kind for kind in kinds)
    assert any("provider" in kind for kind in kinds)
    interrupt_hypothesis = next((h for h in diagnosis.hypotheses if h.rule_id == "R009"), None)
    assert interrupt_hypothesis is not None
    assert interrupt_hypothesis.alternatives


def test_no_invented_ordering_when_timestamps_are_identical():
    events = [
        ev("a", 0, "tool_call", "ok", name="Bash"),
        ev("b", 0, "tool_call", "ok", name="Read"),
    ]
    timeline = build_timeline(build(events, [attempt("att-1", 0)]))
    assert [entry.event_id for entry in timeline.entries] == ["a", "b"]
    assert {tuple(sorted(pair)) for pair in timeline.ambiguous_pairs} == {("a", "b")}
