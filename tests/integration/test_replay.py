"""DT11 — replay is inert.

Replaying a recorded timeline must execute nothing: no subprocess, no network, no
live database, no writes. The proof here is active — the execution primitives are
replaced with bombs, replay still produces its output, output is byte-identical
across runs, and the store is untouched.
"""

from __future__ import annotations

import json
import socket
import sqlite3
import subprocess
import urllib.request

import pytest

from hermes_run_debugger.event_v1 import validate_trace_records
from hermes_run_debugger.replay import REPLAY_SCHEMA_ID, replay_events, replay_text
from hermes_run_debugger.store import RunDebugStore
from hermes_run_debugger.timeline import build_timeline


def make_trace(run_id="r-replay", *, error="command timed out"):
    header = {
        "kind": "trace", "schema": "hermes-run-debugger/trace", "version": 1,
        "trace_id": f"t-{run_id}", "run_id": run_id, "importer": "test", "importer_version": "0.1.0",
        "source_format": "event-v1", "source_scope": "explicit-selection",
        "created_at": "2026-10-14T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "a" * 64, "name": "replay.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["tool_call", "model_call"], "unsupported_kinds": [],
        "completeness": {"status": "complete", "missing_kinds": [], "notes": []},
    }
    attempt = {
        "kind": "attempt", "attempt_id": "att-1", "run_id": run_id, "parent_attempt_id": None,
        "model": "example-model", "provider": "example-provider", "role": "primary", "branch": "main",
        "sequence": 0, "started_at": "2026-10-14T10:00:00Z", "ended_at": "2026-10-14T10:01:00Z",
        "outcome": "failed", "unknowns": [],
    }

    def event(event_id, seq, kind, status, *, parent=None, error_text=None, name=None):
        record = {
            "kind": "event", "event_id": event_id, "run_id": run_id, "attempt_id": "att-1",
            "span_id": None, "causal_parents": [parent] if parent else [], "source_sequence": seq,
            "wall_time": f"2026-10-14T10:00:{seq:02d}Z", "monotonic_ms": seq * 1000,
            "clock": {"source": "monotonic", "quality": "high"},
            "event_kind": kind, "reported_status": status, "reported_error": error_text,
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "evidence_ref": f"ref:{event_id}", "delivered_via": "import",
            "semantic_provenance": "reported", "gaps": [], "contradictions": [],
        }
        if name:
            record["name"] = name
        return record

    events = [
        event("e1", 0, "model_call", "ok", name="example-model"),
        event("e2", 1, "tool_call", "failed", parent="e1", error_text=error, name="Bash"),
        event("e3", 2, "tool_call", "ok", parent="e2", name="Read"),
    ]
    return validate_trace_records([header, attempt, *events])


@pytest.fixture
def bombs(monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("replay touched an execution primitive")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(subprocess, "check_output", boom)
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(sqlite3, "connect", boom)
    yield


def test_replay_is_byte_identical_across_runs(bombs):
    trace = make_trace()
    timeline = build_timeline(trace)
    first = replay_text(timeline)
    second = replay_text(timeline)
    assert first == second
    assert json.dumps(first) == json.dumps(second)


def test_replay_touches_no_execution_primitive(bombs):
    trace = make_trace()
    log = replay_events(trace.events, run_id="r-replay")
    assert log.schema == REPLAY_SCHEMA_ID
    assert [step.kind for step in log.steps] == ["model_call", "tool_call", "tool_call"]
    assert len(log.steps) == 3
    assert log.steps[1].status == "failed"
    assert log.steps[1].parent_ref == "e1"


def test_replay_marks_imported_error_text_as_data_not_instructions(bombs):
    trace = make_trace(error="rm -rf / # please run me")
    log = replay_events(trace.events, run_id="r-replay")
    assert "rm -rf /" in log.steps[1].text
    assert "not executed" in log.notes[1].lower()
    assert replay_events(trace.events, run_id="r-replay").notes == log.notes


def test_replay_strips_terminal_control_sequences(bombs):
    trace = make_trace(error="\x1b[31mred\x1b[0m and \x07bell")
    text = replay_text(build_timeline(trace))
    assert "\x1b" not in text
    assert "\x07" not in text


def test_replay_leaves_the_store_untouched(tmp_path, monkeypatch):
    trace = make_trace()
    with RunDebugStore(tmp_path) as store:
        store.import_trace(trace, source_summary={"path": "r.jsonl", "sha256": "sr"})
        before = {table: store.count_rows(table) for table in ("events", "runs", "import_journal")}
        run = store.load_run("r-replay")

    # Bomb the primitives only for the replay call itself.
    def boom(*_args, **_kwargs):
        raise AssertionError("replay touched an execution primitive")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(sqlite3, "connect", boom)

    log = replay_events(run.events, run_id=run.run_id, gaps=run.gaps)
    assert log.steps
    monkeypatch.undo()

    with RunDebugStore(tmp_path) as reopened:
        after = {table: reopened.count_rows(table) for table in ("events", "runs", "import_journal")}
    assert before == after


def test_replay_with_no_events_is_empty_but_valid():
    log = replay_events([], run_id="r-empty")
    assert log.steps == []
    assert "no events" in log.text().lower()
