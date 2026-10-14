"""DT10 — report rendering: exact totals, escaped output, no remote assets.

A report is a *display* of untrusted data. It must not be able to execute an
imported log, fetch anything, or lose the provenance/gap information a reader
needs in order to judge it.
"""

from __future__ import annotations

import json
import socket
import stat
import urllib.request

import pytest

from hermes_run_debugger.event_v1 import validate_trace_records
from hermes_run_debugger.report import (
    LIMITATIONS,
    build_report,
    render,
    render_html,
    render_json,
    render_markdown,
    write_report,
)


def fixtures():
    header = {
        "kind": "trace", "schema": "hermes-run-debugger/trace", "version": 1,
        "trace_id": "t-rep", "run_id": "r-rep", "importer": "test", "importer_version": "0.1.0",
        "source_format": "event-v1", "source_scope": "explicit-selection",
        "created_at": "2026-10-14T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "8" * 64, "name": "rep.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 3},
        "covered_kinds": ["tool_call", "model_call"], "unsupported_kinds": [],
        "completeness": {"status": "complete", "missing_kinds": [], "notes": []},
    }
    attempt = {
        "kind": "attempt", "attempt_id": "att-1", "run_id": "r-rep", "parent_attempt_id": None,
        "model": "example-model", "provider": "example-provider", "role": "primary", "branch": "main",
        "sequence": 0, "started_at": "2026-10-14T10:00:00Z", "ended_at": None,
        "outcome": "failed", "unknowns": [],
    }
    events = [
        {
            "kind": "event", "event_id": "e1", "run_id": "r-rep", "attempt_id": "att-1",
            "span_id": None, "causal_parents": [], "source_sequence": 0,
            "wall_time": "2026-10-14T10:00:01Z", "monotonic_ms": 1000,
            "clock": {"source": "monotonic", "quality": "high"}, "event_kind": "model_call",
            "reported_status": "ok", "reported_error": None,
            "usage": {"input_tokens": 100, "output_tokens": 20},
            "evidence_ref": "ref:e1", "delivered_via": "import",
            "semantic_provenance": "reported", "gaps": [], "contradictions": [],
            "name": "example-model",
        },
        {
            "kind": "event", "event_id": "e2", "run_id": "r-rep", "attempt_id": "att-1",
            "span_id": None, "causal_parents": ["e1"], "source_sequence": 1,
            "wall_time": "2026-10-14T10:00:02Z", "monotonic_ms": 2000,
            "clock": {"source": "monotonic", "quality": "high"}, "event_kind": "tool_call",
            "reported_status": "failed",
            "reported_error": "<script>alert('x')</script> | pipe \x1b[31mred\x1b[0m",
            "usage": {}, "evidence_ref": "ref:e2", "delivered_via": "import",
            "semantic_provenance": "reported", "gaps": [], "contradictions": [],
            "name": "<script>Bash</script>",
        },
        {
            "kind": "event", "event_id": "e3", "run_id": "r-rep", "attempt_id": "att-1",
            "span_id": None, "causal_parents": ["e2"], "source_sequence": 2,
            "wall_time": "2026-10-14T10:00:03Z", "monotonic_ms": 3000,
            "clock": {"source": "monotonic", "quality": "high"}, "event_kind": "tool_call",
            "reported_status": "failed", "reported_error": "again",
            "usage": {}, "evidence_ref": "ref:e3", "delivered_via": "import",
            "semantic_provenance": "reported", "gaps": [], "contradictions": [],
            "name": "Read",
        },
    ]
    result = validate_trace_records([header, attempt, *events])
    report = build_report(
        run_id="r-rep",
        events=result.events,
        attempts=[attempt],
        gaps=[{"kind": "missing_parent", "detail": "parent absent", "event_id": "e3", "parent_id": "gone"}],
        trace=result.trace.as_dict(),
        completeness="complete",
        may_claim_complete=False,
        revisions=1,
        diagnosis={
            "observed": [{"kind": "failure:tool_call", "event_ref": "e2"}],
            "hypotheses": [{
                "rule_id": "R002", "statement": "consistent with a terminal tool failure",
                "confidence": "medium", "evidence_refs": ["e2", "e3"], "alternatives": ["tolerated"],
                "falsifiers": ["re-run manually"],
            }],
            "missing_evidence": ["gap (missing parent)"],
            "causal_findings": [],
        },
    )
    return result, report


def test_totals_provenance_and_gaps_are_exact():
    _result, report = fixtures()
    assert report["counts"] == {"events": 3, "attempts": 1, "gaps": 1, "failures": 2, "interruptions": 0}
    assert report["provenance"] == {"observed": 0, "reported": 3, "inferred": 0, "unknown": 0}
    assert report["run"]["revisions"] == 1
    assert report["run"]["may_claim_complete"] is False
    assert report["gaps"][0]["kind"] == "missing_parent"
    assert report["causal_findings"] == []
    assert report["cost"]["reported_total"] is None
    assert report["cost"]["cost_kind"] == "unknown"
    assert report["limitations"] == list(LIMITATIONS)


def test_markdown_names_the_subject_and_escapes_table_cells():
    _result, report = fixtures()
    markdown = render_markdown(report)
    assert "Bash" in markdown, "a timeline that hides which tool failed is not useful"
    assert "pipe" in markdown and "\\|" in markdown, "table-breaking pipes must be escaped"
    assert "\x1b" not in markdown, "terminal escapes must not reach a terminal-rendered report"
    assert "missing parent" in markdown
    assert "hypothesis" in markdown.lower()


def test_html_is_escaped_and_fetches_nothing(monkeypatch):
    _result, report = fixtures()

    def boom(*_args, **_kwargs):
        raise AssertionError("report rendering touched the network")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)

    html = render_html(report)
    assert "<script>alert" not in html, "an imported payload must never appear as a live tag"
    assert "&lt;script&gt;" in html
    assert "Bash" in html
    lowered = html.lower()
    assert "http://" not in lowered and "https://" not in lowered, "no remote assets"
    assert "src=" not in lowered and "onload=" not in lowered
    assert "content-security-policy" in lowered
    assert "hypothesis" in lowered


def test_json_round_trips_and_carries_no_private_digests():
    _result, report = fixtures()
    payload = render_json(report)
    parsed = json.loads(payload)
    assert parsed["schema"] == "hermes-run-debugger/report"
    assert parsed["counts"]["events"] == 3
    assert "sha256:" not in payload, "raw input digests stay in the private store"
    assert "private_digests" not in payload


def test_unknown_format_is_refused():
    _result, report = fixtures()
    with pytest.raises(ValueError):
        render(report, "csv")


def test_write_report_is_private(tmp_path):
    _result, report = fixtures()
    path = write_report(render_markdown(report), tmp_path / "nested" / "report.md")
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0


def test_rendering_is_deterministic():
    _result, report = fixtures()
    first = render_markdown(report)
    second = render_markdown(report)
    assert first == second
