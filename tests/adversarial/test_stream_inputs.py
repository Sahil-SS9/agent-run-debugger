"""DT03 — adversarial stream inputs: truncation, corruption, caps, non-finite values.

Truthfulness is the property under test, not leniency. Every one of these inputs
must either import with an honest, visible gap/completeness statement, or be
refused with a message that names the reason. Silent loss and invented
completeness both fail.
"""

from __future__ import annotations

import json

import pytest

from hermes_run_debugger.import_v1 import ImportRefused, import_trace
from hermes_run_debugger.jsonio import (
    InputLimitExceeded,
    MalformedRecord,
    ScanState,
    StreamLimits,
    scan_jsonl,
)

HEADER = {
    "kind": "trace",
    "schema": "hermes-run-debugger/trace",
    "version": 1,
    "trace_id": "t-stream",
    "run_id": "r-stream",
    "importer": "import_v1",
    "importer_version": "0.1.0",
    "source_format": "event-v1",
    "source_scope": "explicit-selection",
    "created_at": "2026-10-14T10:00:00Z",
    "source": {"kind": "file", "ref": "sha256:" + "d" * 64, "name": "stream.jsonl"},
    "redaction": {"policy": "minimal-metadata", "applied_count": 0},
    "covered_kinds": ["tool_call"],
    "unsupported_kinds": [],
    "completeness": {"status": "complete", "missing_kinds": [], "notes": []},
}
ATTEMPT = {
    "kind": "attempt", "attempt_id": "att-1", "run_id": "r-stream", "parent_attempt_id": None,
    "model": "example-model", "provider": "example-provider", "role": "primary", "branch": "main",
    "sequence": 0, "started_at": "2026-10-14T10:00:00Z", "ended_at": "2026-10-14T10:01:00Z",
    "outcome": "failed", "unknowns": [],
}


def event(idx: int) -> dict:
    return {
        "kind": "event", "event_id": f"e-{idx}", "run_id": "r-stream", "attempt_id": "att-1",
        "span_id": None, "causal_parents": [], "source_sequence": idx,
        "wall_time": f"2026-10-14T10:00:{idx:02d}Z", "monotonic_ms": idx * 1000,
        "clock": {"source": "wall", "quality": "low"}, "event_kind": "tool_call",
        "reported_status": "ok", "reported_error": None, "usage": {},
        "evidence_ref": f"ref:{idx}", "delivered_via": "import",
        "semantic_provenance": "reported", "gaps": [], "contradictions": [],
    }


def write_lines(path, lines: list[str]):
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    return path


def good_lines(events: int = 2) -> list[str]:
    return [json.dumps(HEADER), json.dumps(ATTEMPT)] + [json.dumps(event(i)) for i in range(events)]


def test_corrupt_middle_line_refuses_and_names_the_line(tmp_path):
    lines = good_lines(3)
    lines[3] = '{"kind": "event", "event_id": "e-2"'  # truncated object mid-file
    path = write_lines(tmp_path / "stream.jsonl", lines)
    with pytest.raises(ImportRefused) as exc:
        import_trace(path, fmt="v1")
    assert "stream.jsonl:4" in str(exc.value)

    # allow_partial must NOT rescue a corrupt middle line
    with pytest.raises(ImportRefused):
        import_trace(path, fmt="v1", allow_partial=True)


def test_truncated_final_line_is_refused_by_default_and_marked_partial_on_request(tmp_path):
    lines = good_lines(3)
    raw = "\n".join(lines) + '\n{"kind": "event", "event_id": "e-3", "run_'
    path = tmp_path / "stream.jsonl"
    path.write_text(raw, encoding="utf-8")

    with pytest.raises(ImportRefused) as exc:
        import_trace(path, fmt="v1")
    assert "truncated" in str(exc.value).lower()
    assert "allow_partial" in str(exc.value)

    partial = import_trace(path, fmt="v1", allow_partial=True)
    assert partial.partial is True
    assert partial.snapshot["partial"] is True
    assert len(partial.result.events) == 3, "the valid prefix is kept, nothing is invented"
    assert any(gap.kind == "truncation" for gap in partial.result.gaps)
    assert partial.may_claim_complete is False


def test_bounds_are_enforced_with_named_limits(tmp_path):
    path = write_lines(tmp_path / "stream.jsonl", good_lines(5))

    with pytest.raises(InputLimitExceeded) as exc:
        scan_jsonl(path, limits=StreamLimits(max_line_bytes=40), state=ScanState(path=str(path)))
    assert "max_line_bytes" in str(exc.value)

    with pytest.raises(InputLimitExceeded) as exc:
        scan_jsonl(path, limits=StreamLimits(max_bytes=80), state=ScanState(path=str(path)))
    assert "max_bytes" in str(exc.value)

    with pytest.raises(InputLimitExceeded) as exc:
        scan_jsonl(path, limits=StreamLimits(max_events=2), state=ScanState(path=str(path)))
    assert "max_events" in str(exc.value)


def test_deep_nesting_and_non_finite_values_are_refused(tmp_path):
    deep = json.dumps(HEADER)
    for _ in range(40):
        deep = deep.replace('"kind": "trace"', '"kind": "trace"', 1)
    nested = {"kind": "event", "event_id": "e-9", "run_id": "r-stream", "attempt_id": "att-1",
              "source_sequence": 0, "event_kind": "tool_call", "semantic_provenance": "reported",
              "evidence": {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}}
    path = write_lines(tmp_path / "deep.jsonl", [deep, json.dumps(nested)])
    with pytest.raises(InputLimitExceeded) as exc:
        scan_jsonl(path, limits=StreamLimits(max_depth=4), state=ScanState(path=str(path)))
    assert "max_depth" in str(exc.value)

    nan_path = write_lines(tmp_path / "nan.jsonl", ['{"kind": "event", "monotonic_ms": NaN}'])
    with pytest.raises(MalformedRecord) as exc:
        scan_jsonl(nan_path, limits=StreamLimits(), state=ScanState(path=str(nan_path)))
    assert "non-finite" in str(exc.value)


def test_blank_lines_are_counted_and_not_turned_into_records(tmp_path):
    lines = good_lines(2)
    path = tmp_path / "stream.jsonl"
    path.write_text("\n".join([lines[0], "", lines[1], "   ", lines[2]]) + "\n", encoding="utf-8")
    state = ScanState(path=str(path))
    records, state = scan_jsonl(path, limits=StreamLimits(), state=state)
    assert len(records) == 3
    assert state.skipped_blank == 2
    assert state.records == 3
    assert state.lines == 5


def test_unknown_record_kind_is_refused_not_skipped(tmp_path):
    lines = good_lines(1)
    lines.append(json.dumps({"kind": "mystery", "run_id": "r-stream"}))
    path = write_lines(tmp_path / "stream.jsonl", lines)
    with pytest.raises(ImportRefused) as exc:
        import_trace(path, fmt="v1")
    assert "mystery" in str(exc.value)


def test_unsupported_schema_version_is_refused(tmp_path):
    header = dict(HEADER, version=99)
    path = write_lines(tmp_path / "stream.jsonl", [json.dumps(header), json.dumps(ATTEMPT)])
    with pytest.raises(ImportRefused) as exc:
        import_trace(path, fmt="v1")
    assert "version" in str(exc.value).lower()


def test_snapshot_identity_changes_when_the_source_grows(tmp_path):
    path = write_lines(tmp_path / "stream.jsonl", good_lines(2))
    first = import_trace(path, fmt="v1")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event(2)) + "\n")
    second = import_trace(path, fmt="v1")

    assert first.snapshot["sha256"] != second.snapshot["sha256"]
    assert first.snapshot["records"] == 4
    assert second.snapshot["records"] == 5
    assert first.result.trace.private_digests["content"] == first.snapshot["sha256"]


def test_source_digest_is_computed_when_the_file_does_not_carry_one(tmp_path):
    header = dict(HEADER)
    header.pop("source")
    header["source"] = {"kind": "file", "name": "stream.jsonl"}
    path = write_lines(tmp_path / "stream.jsonl", [json.dumps(header), json.dumps(ATTEMPT)])
    imported = import_trace(path, fmt="v1")
    assert imported.result.trace.source["ref"].startswith("sha256:")
    assert any("computed" in note for note in imported.notes)
