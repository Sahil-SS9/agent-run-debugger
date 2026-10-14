"""DT01 — Trace v1 strict validation (normalisation contract, evidence semantics).

Covers: strict schema/version/id/type checks, unknown-field policy, parent
references (missing parent is a visible GAP, not an inferred edge), cycle
refusal, duplicate ids, non-finite numbers, and the separation between a run's
outcome and any correctness claim.
"""

from __future__ import annotations

import math

import pytest

from hermes_run_debugger.event_v1 import (
    EVENT_KINDS,
    OUTCOMES,
    PROVENANCE,
    SCHEMA_ID,
    SCHEMA_VERSION,
    TraceValidationError,
    validate_trace_records,
)


def trace_record(**over):
    rec = {
        "kind": "trace",
        "schema": SCHEMA_ID,
        "version": SCHEMA_VERSION,
        "trace_id": "t-1",
        "run_id": "r-1",
        "importer": "import_v1",
        "importer_version": "0.1.0",
        "source_format": "event-v1",
        "source_scope": "explicit-selection",
        "created_at": "2026-10-14T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "a" * 64, "name": "selected.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["model_call", "tool_call"],
        "unsupported_kinds": [],
        "completeness": {"status": "complete", "missing_kinds": [], "notes": []},
    }
    rec.update(over)
    return rec


def attempt_record(**over):
    rec = {
        "kind": "attempt",
        "attempt_id": "att-1",
        "run_id": "r-1",
        "parent_attempt_id": None,
        "model": "example-model",
        "provider": "example-provider",
        "role": "primary",
        "branch": "main",
        "sequence": 0,
        "started_at": "2026-10-14T10:00:00Z",
        "ended_at": "2026-10-14T10:05:00Z",
        "outcome": "failed",
        "unknowns": [],
    }
    rec.update(over)
    return rec


def event_record(**over):
    rec = {
        "kind": "event",
        "event_id": "e-1",
        "run_id": "r-1",
        "attempt_id": "att-1",
        "span_id": None,
        "causal_parents": [],
        "source_sequence": 1,
        "wall_time": "2026-10-14T10:00:01Z",
        "monotonic_ms": 1000,
        "clock": {"source": "wall", "quality": "low"},
        "event_kind": "tool_call",
        "reported_status": "failed",
        "reported_error": "command timed out",
        "usage": {"input_tokens": 10, "output_tokens": 20, "cache_read_tokens": None},
        "evidence_ref": "ref:0001",
        "delivered_via": "import",
        "semantic_provenance": "reported",
        "gaps": [],
        "contradictions": [],
    }
    rec.update(over)
    return rec


def test_valid_trace_accepts_and_preserves_semantics():
    result = validate_trace_records(
        [trace_record(), attempt_record(), event_record(), event_record(event_id="e-2", source_sequence=2)]
    )
    assert result.refused == []
    assert result.ok
    assert result.trace.run_id == "r-1"
    assert [e.event_id for e in result.events] == ["e-1", "e-2"]
    assert result.events[0].semantic_provenance == "reported"
    assert result.events[0].semantic_provenance in PROVENANCE
    assert result.attempts[0].outcome in OUTCOMES


def test_unknown_schema_and_version_are_refused():
    with pytest.raises(TraceValidationError) as exc:
        validate_trace_records([trace_record(schema="something-else")])
    assert "schema" in str(exc.value)

    with pytest.raises(TraceValidationError) as exc:
        validate_trace_records([trace_record(version=SCHEMA_VERSION + 1)])
    assert "version" in str(exc.value).lower()


def test_first_record_must_be_the_trace_envelope():
    with pytest.raises(TraceValidationError):
        validate_trace_records([event_record()])


def test_unknown_field_is_refused_under_strict_policy():
    with pytest.raises(TraceValidationError) as exc:
        validate_trace_records([trace_record(), attempt_record(), event_record(surprise_field=1)])
    assert "unknown field" in str(exc.value).lower()

    lenient = validate_trace_records(
        [trace_record(), attempt_record(), event_record(surprise_field=1)],
        unknown_field_policy="ignore",
    )
    assert lenient.ok
    assert any("surprise_field" in note for note in lenient.warnings)


def test_unknown_event_kind_and_provenance_are_refused_not_guessed():
    assert "tool_call" in EVENT_KINDS
    with pytest.raises(TraceValidationError):
        validate_trace_records([trace_record(), attempt_record(), event_record(event_kind="mystery")])
    with pytest.raises(TraceValidationError):
        validate_trace_records(
            [trace_record(), attempt_record(), event_record(semantic_provenance="certain")]
        )


def test_missing_parent_is_a_gap_not_an_inferred_edge():
    out = validate_trace_records(
        [
            trace_record(),
            attempt_record(),
            event_record(event_id="e-1", causal_parents=["e-missing"], source_sequence=1),
        ]
    )
    assert out.ok, "a legitimately missing parent must not refuse the import"
    assert out.events[0].causal_parents == ("e-missing",)
    gaps = [g for g in out.gaps if g.event_id == "e-1"]
    assert gaps and gaps[0].kind == "missing_parent"
    assert gaps[0].parent_id == "e-missing"
    # No edge was invented from the missing parent.
    assert ("e-missing", "e-1") not in out.parent_edges


def test_cycle_is_refused():
    with pytest.raises(TraceValidationError) as exc:
        validate_trace_records(
            [
                trace_record(),
                attempt_record(),
                event_record(event_id="e-1", causal_parents=["e-2"], source_sequence=1),
                event_record(event_id="e-2", causal_parents=["e-1"], source_sequence=2),
            ]
        )
    assert "cycl" in str(exc.value).lower()


def test_duplicate_event_id_is_refused():
    with pytest.raises(TraceValidationError) as exc:
        validate_trace_records(
            [trace_record(), attempt_record(), event_record(), event_record()]
        )
    assert "duplicate" in str(exc.value).lower()


def test_event_referencing_unknown_attempt_is_refused():
    with pytest.raises(TraceValidationError):
        validate_trace_records([trace_record(), attempt_record(), event_record(attempt_id="att-missing")])


def test_non_finite_numbers_and_bad_ids_are_refused():
    with pytest.raises(TraceValidationError):
        validate_trace_records([trace_record(), attempt_record(), event_record(monotonic_ms=math.nan)])
    with pytest.raises(TraceValidationError):
        validate_trace_records([trace_record(), attempt_record(), event_record(event_id="bad\nid")])
    with pytest.raises(TraceValidationError):
        validate_trace_records([trace_record(), attempt_record(), event_record(event_id="")])


def test_outcome_is_separate_from_a_correctness_claim():
    """'Agent completed' never means 'task passed'."""
    out = validate_trace_records(
        [
            trace_record(),
            attempt_record(outcome="completed"),
            event_record(event_id="e-1", reported_status="failed", source_sequence=1),
        ]
    )
    assert out.attempts[0].outcome == "completed"
    assert out.events[0].reported_status == "failed"
    assert out.correctness_claims == []


def test_cost_is_never_silently_zero_for_unknown_values():
    event = validate_trace_records(
        [trace_record(), attempt_record(), event_record(usage={"input_tokens": None, "output_tokens": None})]
    ).events[0]
    assert event.usage.input_tokens is None and event.usage.input_tokens != 0
    assert event.usage.as_reported()["input_tokens"] is None


def test_completeness_never_invents_a_skipped_callback_count():
    with pytest.raises(TraceValidationError):
        validate_trace_records(
            [
                trace_record(
                    completeness={
                        "status": "complete",
                        "missing_kinds": [],
                        "notes": [],
                        "skipped_callback_count": 3,
                    }
                )
            ]
        )
