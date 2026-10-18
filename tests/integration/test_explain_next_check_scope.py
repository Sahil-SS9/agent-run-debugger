"""Next-check scope — a check that names "the failing events" needs a failure to name.

Found by reading the delivered output for a clean run during the usability walkthrough:
the clean case still listed

    read-only: inspect the referenced source lines for the failing events and confirm the
    reported status against the raw text

on a run that recorded no failing event at all. Every line in this section is meant to be a
concrete read-only next step, so a step pointing at events that do not exist is worse than
noise: it implies a failure the evidence does not contain.

Same gate as the retention note (`diagnose.py`, ``_collect_missing_evidence``): the
failure-dependent line is emitted only when the evidence reports a failure or an
interruption. The failure-independent checks stay on every run.

Both directions are asserted through the real explain path.
"""

from __future__ import annotations

import json

from hermes_run_debugger.cli import Services

FAILURE_STEP_FRAGMENT = "for the failing events"


def _header(run_id: str):
    return {
        "kind": "trace",
        "schema": "hermes-run-debugger/trace",
        "version": 1,
        "trace_id": f"trace-{run_id}",
        "run_id": run_id,
        "importer": "next-check-scope-regression",
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


def _event(event_id, seq, status, *, name="Bash", error=None):
    return {
        "kind": "event",
        "event_id": event_id,
        "run_id": "PLACEHOLDER",
        "attempt_id": "att-1",
        "span_id": None,
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


def test_clean_run_has_no_check_that_names_failing_events(tmp_path):
    diagnosed = _explain(
        tmp_path,
        "clean",
        events=[
            _event("e1", 0, "ok", name="Read"),
            _event("e2", 1, "ok", name="Bash"),
        ],
    )
    assert diagnosed["observed"] == [], "fixture must record no failure"
    steps = diagnosed["next_diagnostics"]
    assert steps, "the failure-independent next checks must still be offered"
    offending = [step for step in steps if FAILURE_STEP_FRAGMENT in step]
    assert offending == [], (
        f"a clean run was given a next check that points at failing events: {offending}"
    )


def test_failing_run_still_gets_the_failure_check(tmp_path):
    diagnosed = _explain(
        tmp_path,
        "failing",
        events=[
            _event("e1", 0, "failed", name="Bash", error="exit 2"),
            _event("e2", 1, "ok", name="Read"),
        ],
    )
    assert diagnosed["observed"], "fixture must record a failure"
    steps = diagnosed["next_diagnostics"]
    assert any(FAILURE_STEP_FRAGMENT in step for step in steps), (
        "a failing run must keep the check that inspects the failing evidence"
    )


def test_interrupted_run_gets_the_failure_check(tmp_path):
    """An interruption is an observed failure-or-interruption for this gate."""
    diagnosed = _explain(
        tmp_path,
        "interrupted",
        events=[
            _event("e1", 0, "failed", name="Bash", error="interrupted by user"),
        ],
    )
    steps = diagnosed["next_diagnostics"]
    assert any(FAILURE_STEP_FRAGMENT in step for step in steps)
