"""DT08 — clock and cost honesty.

Two claims that a debugger usually gets wrong: that a wall-clock gap is a stall,
and that token totals are money. Neither can be established from what these
fixtures contain, and the tests require the code to say so.
"""

from __future__ import annotations

import json

import pytest

from hermes_run_debugger.diagnose import diagnose
from hermes_run_debugger.event_v1 import validate_trace_records
from hermes_run_debugger.import_claude import import_claude_trace
from hermes_run_debugger.jsonio import StreamLimits
from hermes_run_debugger.report import summarise_cost
from hermes_run_debugger.timeline import build_timeline


def trace(events):
    header = {
        "kind": "trace", "schema": "hermes-run-debugger/trace", "version": 1,
        "trace_id": "t-cc", "run_id": "r-cc", "importer": "test", "importer_version": "0.1.0",
        "source_format": "event-v1", "source_scope": "explicit-selection",
        "created_at": "2026-10-14T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "5" * 64, "name": "cc.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["model_call", "tool_call"], "unsupported_kinds": [],
        "completeness": {"status": "complete", "missing_kinds": [], "notes": []},
    }
    attempt = {
        "kind": "attempt", "attempt_id": "att-1", "run_id": "r-cc", "parent_attempt_id": None,
        "model": "example-model", "provider": "example-provider", "role": "primary", "branch": "main",
        "sequence": 0, "started_at": "2026-10-14T10:00:00Z", "ended_at": "2026-10-14T12:00:00Z",
        "outcome": "failed", "unknowns": [],
    }
    return validate_trace_records([header, attempt, *events])


def ev(event_id, seq, *, mono=None, quality="low", wall="2026-10-14T10:00:00Z", usage=None,
       status="ok", error=None):
    return {
        "kind": "event", "event_id": event_id, "run_id": "r-cc", "attempt_id": "att-1",
        "span_id": None, "causal_parents": [], "source_sequence": seq,
        "wall_time": wall, "monotonic_ms": mono,
        "clock": {"source": "monotonic" if mono is not None else "wall", "quality": quality},
        "event_kind": "model_call", "reported_status": status, "reported_error": error,
        "usage": usage or {}, "evidence_ref": f"ref:{event_id}", "delivered_via": "import",
        "semantic_provenance": "reported", "gaps": [], "contradictions": [],
    }


def test_wall_clock_gap_without_monotonic_evidence_is_a_hypothesis_not_a_stall():
    result = trace([
        ev("e1", 0, wall="2026-10-14T10:00:00Z", quality="low"),
        ev("e2", 1, wall="2026-10-14T13:20:00Z", quality="low"),
    ])
    timeline = build_timeline(result)
    window = timeline.suspect_windows[0]
    assert window["status"] == "hypothesis"
    assert window["monotonic_delta_ms"] is None
    diagnosis = diagnose(timeline)
    stall = next(h for h in diagnosis.hypotheses if h.rule_id == "R006")
    assert stall.confidence == "low"
    assert "suspend" in " ".join(stall.alternatives).lower() or "drift" in " ".join(stall.alternatives).lower()


def test_monotonic_evidence_supports_the_observation():
    result = trace([
        ev("e1", 0, mono=0, quality="high", wall="2026-10-14T10:00:00Z"),
        ev("e2", 1, mono=12_000_000, quality="high", wall="2026-10-14T13:20:00Z"),
    ])
    timeline = build_timeline(result)
    window = timeline.suspect_windows[0]
    assert window["status"] == "observed"
    assert window["monotonic_delta_ms"] == 12_000_000


def test_actual_estimated_and_unknown_costs_stay_separate():
    events = trace([
        ev("e1", 0, usage={"input_tokens": 100, "output_tokens": 50, "cost": 1.5, "cost_kind": "actual"}),
        ev("e2", 1, usage={"input_tokens": 200, "output_tokens": 60, "cost": 2.0,
                           "cost_kind": "estimated", "price_source": "operator-price-table-v3"}),
        ev("e3", 2, usage={"input_tokens": 10}),
    ]).events
    cost = summarise_cost(events)
    assert cost["reported_total"] == pytest.approx(1.5)
    assert cost["estimated_total"] == pytest.approx(2.0)
    assert cost["events_with_unknown_cost"] == 1
    assert cost["events_with_unknown_tokens"] == 0
    # Both kinds present: the aggregate label must say so rather than saying "actual".
    assert cost["cost_kind"] == "mixed"
    assert cost["price_source"] == "operator-price-table-v3"
    assert "money" in cost["note"] or "price source" in cost["note"]
    assert cost["coverage"]["events_with_reported_cost"] == 2
    assert cost["coverage"]["events"] == 3


def test_partially_known_token_counts_stay_partial():
    """Known output tokens must not turn unknown input tokens into zero."""
    events = trace([ev("e1", 0, usage={"output_tokens": 7})]).events
    cost = summarise_cost(events)
    assert cost["reported_input_tokens"] is None
    assert cost["reported_output_tokens"] == 7
    assert cost["coverage"]["events_with_input_tokens"] == 0
    assert cost["coverage"]["events_with_output_tokens"] == 1
    assert "1 of 1" in cost["coverage"]["note"]


def test_both_unknown_tokens_stay_null():
    events = trace([ev("e1", 0, usage={})]).events
    cost = summarise_cost(events)
    assert cost["reported_input_tokens"] is None
    assert cost["reported_output_tokens"] is None
    assert cost["events_with_unknown_tokens"] == 1


def test_measured_zero_is_preserved_as_a_measurement():
    events = trace([ev("e1", 0, usage={"input_tokens": 0, "output_tokens": 0})]).events
    cost = summarise_cost(events)
    assert cost["reported_input_tokens"] == 0
    assert cost["reported_output_tokens"] == 0
    assert cost["coverage"]["events_with_input_tokens"] == 1
    assert cost["events_with_unknown_tokens"] == 0


def test_mixed_known_and_unknown_reports_a_labelled_subtotal():
    events = trace([
        ev("e1", 0, usage={"input_tokens": 100, "output_tokens": 10}),
        ev("e2", 1, usage={"output_tokens": 5}),
        ev("e3", 2, usage={}),
    ]).events
    cost = summarise_cost(events)
    assert cost["reported_input_tokens"] == 100
    assert cost["reported_output_tokens"] == 15
    assert cost["coverage"]["events"] == 3
    assert cost["coverage"]["events_with_input_tokens"] == 1
    assert cost["coverage"]["events_with_output_tokens"] == 2
    assert "1 of 3" in cost["coverage"]["note"] and "2 of 3" in cost["coverage"]["note"]
    assert cost["events_with_unknown_tokens"] == 1


def test_unknown_billing_is_never_zero():
    events = trace([
        ev("e1", 0, usage={"input_tokens": 100, "output_tokens": 50}),
    ]).events
    cost = summarise_cost(events)
    assert cost["reported_total"] is None
    assert cost["estimated_total"] is None
    assert cost["cost_kind"] == "unknown"
    assert cost["reported_total"] != 0


def test_report_marks_unknown_metrics_as_unknown_not_zero():
    from hermes_run_debugger.report import build_report, render_markdown

    events = trace([ev("e1", 0, usage={"output_tokens": 7})]).events
    report = build_report(run_id="r-cc", events=events, trace={"trace_id": "t-cc"})
    markdown = render_markdown(report)
    assert "reported total: unknown" in markdown
    assert "output tokens reported for 1 of 1 events" in markdown
    assert "input tokens reported for 0 of 1 events" in markdown
    assert "0 tokens" not in markdown.replace("0 of 1", "")


def test_claude_token_totals_reconcile_with_an_independent_oracle(tmp_path):
    entries = [
        {"type": "assistant", "uuid": "a1", "requestId": "r1", "sessionId": "s1",
         "timestamp": "2026-10-14T10:00:01.000Z",
         "message": {"id": "m1", "role": "assistant", "model": "claude-x",
                     "content": [{"type": "text", "text": "one"}],
                     "usage": {"input_tokens": 10, "output_tokens": 3,
                               "cache_read_input_tokens": 4, "cache_creation_input_tokens": 6}}},
        {"type": "assistant", "uuid": "a2", "requestId": "r1", "sessionId": "s1",
         "timestamp": "2026-10-14T10:00:02.000Z",
         "message": {"id": "m1", "role": "assistant", "model": "claude-x",
                     "content": [{"type": "text", "text": "two"}],
                     "usage": {"input_tokens": 10, "output_tokens": 9,
                               "cache_read_input_tokens": 4, "cache_creation_input_tokens": 6}}},
        {"type": "assistant", "uuid": "a3", "requestId": "r2", "sessionId": "s1",
         "timestamp": "2026-10-14T10:00:03.000Z",
         "message": {"id": "m2", "role": "assistant", "model": "claude-x",
                     "content": [{"type": "text", "text": "three"}],
                     "usage": {"input_tokens": 20, "output_tokens": 5}}},
    ]
    path = tmp_path / "session.jsonl"
    path.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")
    imported = import_claude_trace([path], limits=StreamLimits())

    # oracle: per request, the max output_tokens; input counted once per request
    oracle_output = 9 + 5
    oracle_input = 10 + 20
    cost = summarise_cost(imported.result.events)
    assert cost["reported_output_tokens"] == oracle_output
    assert cost["reported_input_tokens"] == oracle_input
    assert cost["reported_total"] is None, "resumed/split logs do not imply money"
