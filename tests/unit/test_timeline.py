"""D4 — timeline: partial-order display, stable tie-breaks, honest ambiguity.

Wall-clock order is not causation. These tests pin the properties that keep that
promise: identical output for identical evidence regardless of input order,
fork/join structure preserved, missing parents visible as gaps, and concurrent
events explicitly marked ambiguous instead of being sorted into a story.
"""

from __future__ import annotations

import random

import pytest

from hermes_run_debugger.event_v1 import validate_trace_records
from hermes_run_debugger.timeline import (
    TimelineContradiction,
    build_timeline,
)


def records(events, *, attempts=None, gaps_note=""):
    header = {
        "kind": "trace", "schema": "hermes-run-debugger/trace", "version": 1,
        "trace_id": "t-tl", "run_id": "r-tl", "importer": "test", "importer_version": "0.1.0",
        "source_format": "event-v1", "source_scope": "explicit-selection",
        "created_at": "2026-10-14T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "f" * 64, "name": "tl.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["tool_call", "model_call", "note"], "unsupported_kinds": [],
        "completeness": {"status": "complete", "missing_kinds": [], "notes": [gaps_note]},
    }
    attempt = {
        "kind": "attempt", "attempt_id": "att-1", "run_id": "r-tl", "parent_attempt_id": None,
        "model": "example-model", "provider": "example-provider", "role": "primary", "branch": "main",
        "sequence": 0, "started_at": "2026-10-14T10:00:00Z", "ended_at": "2026-10-14T10:05:00Z",
        "outcome": "failed", "unknowns": [],
    }
    if attempts:
        attempt.update(attempts)
    return [header, attempt, *events]


def ev(event_id, seq, *, parents=(), kind="tool_call", wall=None, mono=None,
       quality="low", status="ok", name=None, attempt="att-1"):
    record = {
        "kind": "event", "event_id": event_id, "run_id": "r-tl", "attempt_id": attempt,
        "span_id": None, "causal_parents": list(parents), "source_sequence": seq,
        "wall_time": wall, "monotonic_ms": mono,
        "clock": {"source": "monotonic" if mono is not None else "wall", "quality": quality},
        "event_kind": kind, "reported_status": status, "reported_error": None, "usage": {},
        "evidence_ref": f"ref:{event_id}", "delivered_via": "import",
        "semantic_provenance": "reported", "gaps": [], "contradictions": [],
    }
    if name:
        record["name"] = name
    return record


def build(events, **kw):
    return build_timeline(validate_trace_records(records(events, **kw)))


def test_chain_orders_parents_before_children_and_computes_depth():
    timeline = build([
        ev("a", 0),
        ev("b", 1, parents=("a",)),
        ev("c", 2, parents=("b",)),
    ])
    assert [entry.event_id for entry in timeline.entries] == ["a", "b", "c"]
    assert [entry.depth for entry in timeline.entries] == [0, 1, 2]
    assert timeline.entries[1].causal_parents == ("a",)
    assert timeline.ambiguous_pairs == []


def test_input_order_does_not_change_the_display():
    events = [
        ev("root", 0),
        ev("left", 1, parents=("root",)),
        ev("right", 2, parents=("root",)),
        ev("join", 3, parents=("left", "right")),
    ]
    first = build(events)
    shuffled = list(events)
    random.Random(7).shuffle(shuffled)
    second = build(shuffled)
    assert [e.event_id for e in first.entries] == [e.event_id for e in second.entries]
    assert first.text() == second.text()


def test_fork_children_are_explicitly_ambiguous_not_silently_sorted():
    timeline = build([
        ev("root", 0),
        ev("left", 1, parents=("root",), wall="2026-10-14T10:00:01Z"),
        ev("right", 2, parents=("root",), wall="2026-10-14T10:00:02Z"),
    ])
    assert [e.event_id for e in timeline.entries] == ["root", "left", "right"]
    pairs = {tuple(sorted(pair)) for pair in timeline.ambiguous_pairs}
    assert ("left", "right") in pairs
    text = timeline.text()
    assert "ambiguous" in text.lower()
    assert "wall-clock order is not causation" in text.lower()


def test_equal_sequence_ties_break_on_event_id_deterministically():
    timeline = build([
        ev("root", 0),
        ev("z-child", 5, parents=("root",)),
        ev("a-child", 5, parents=("root",)),
    ])
    assert [e.event_id for e in timeline.entries] == ["root", "a-child", "z-child"]


def test_missing_parent_is_a_gap_and_the_event_becomes_a_root():
    validated = validate_trace_records(records([ev("orphan", 3, parents=("gone",))]))
    timeline = build_timeline(validated)
    assert [e.event_id for e in timeline.entries] == ["orphan"]
    assert timeline.entries[0].depth == 0
    assert any(gap.kind == "missing_parent" for gap in timeline.gaps)
    assert "missing parent" in timeline.text().lower()


def test_cycle_is_refused_by_default_and_quarantinable_on_request():
    validated = validate_trace_records(
        records([ev("x", 0, parents=("y",)), ev("y", 1, parents=("x",))]),
        refuse="collect",
    )
    assert not validated.ok
    with pytest.raises(TimelineContradiction):
        build_timeline(_force_cycle_edges(validated))

    timeline = build_timeline(_force_cycle_edges(validated), quarantine=True)
    assert timeline.quarantined, "the offending portion must be visible, not ordered"
    assert timeline.entries == []
    assert "quarantin" in timeline.text().lower()


def _force_cycle_edges(validated):
    """Validation refuses cycles; simulate corrupt *stored* data reaching the builder."""
    from hermes_run_debugger.event_v1 import ValidationResult

    forced = ValidationResult(
        trace=validated.trace,
        attempts=list(validated.attempts),
        events=list(validated.events),
        gaps=list(validated.gaps),
        parent_edges=[("x", "y"), ("y", "x")],
        refused=[],
    )
    return forced


def test_suspect_wall_clock_windows_are_hypotheses_not_facts():
    timeline = build([
        ev("start", 0, wall="2026-10-14T10:00:00Z", quality="low"),
        ev("after-gap", 1, parents=("start",), wall="2026-10-14T11:30:00Z", quality="low"),
    ])
    windows = timeline.suspect_windows
    assert windows and windows[0]["wall_delta_s"] == pytest.approx(5400)
    assert windows[0]["status"] == "hypothesis"
    assert "no monotonic clock" in windows[0]["why"].lower()
    assert "stall" in timeline.text().lower()
    assert "hypothesis" in timeline.text().lower()


def test_monotonic_evidence_upgrades_the_window_to_observation():
    timeline = build([
        ev("start", 0, wall="2026-10-14T10:00:00Z", mono=1000, quality="high"),
        ev("after", 1, parents=("start",), wall="2026-10-14T11:30:00Z", mono=5_401_000, quality="high"),
    ])
    window = timeline.suspect_windows[0]
    assert window["status"] == "observed"
    assert window["monotonic_delta_ms"] == 5_400_000


def test_timeline_surfaces_gaps_and_never_invents_an_order_it_cannot_justify():
    timeline = build([
        ev("a", 0, wall="2026-10-14T10:00:10Z"),
        ev("b", 1, wall="2026-10-14T10:00:00Z"),
    ])
    # source order wins: wall-clock disagreement is recorded, not obeyed
    assert [e.event_id for e in timeline.entries] == ["a", "b"]
    assert timeline.clock_notes, "a wall-clock disagreement must be visible"
    assert "source order" in " ".join(timeline.clock_notes).lower()
