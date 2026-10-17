"""Retention wording scope — the policy note must not appear on a run with no failure.

Follow-up cleanup recorded in `ERRATUM.md` §"Recorded limitation": under
``metadata-only`` the diagnosis emitted

    "error and tool-result text was not retained under the active retention policy
     (metadata-only), so the mechanism behind a failure cannot be named ..."

even for a run that recorded **no failure at all**. The wording is conditioned on "a
failure", so it is not a false claim, but on a clean run it reads as though a failure
existed and its mechanism is being withheld — a scope slip a matched reader of the same
evidence does not make.

The note is useful where it belongs: when a failure was actually observed and the text
that would name its mechanism was dropped by policy. Both directions are asserted here,
through the real explain path (``Services.import_sources`` → ``Services.explain_text``),
using the Claude lane so the fixture matches the real cases this was found on.

A separate file on purpose: `tests/integration/test_explain_failure_scope.py` is an
accepted, hash-pinned artifact of the paired-retention trial and must not change.
"""

from __future__ import annotations

import json

from hermes_run_debugger.cli import Services
from hermes_run_debugger.settings import Settings

POLICY_NOTE_MARKER = "was not retained under the active retention policy"

METADATA_ONLY = Settings.from_mapping({
    "retention_mode": "metadata-only",
    "capture_enabled": False,
    "live_read_enabled": False,
    "llm_enabled": False,
    "experiment_enabled": False,
    "allow_partial": False,
})


def _claude_records(*, failing_tool_result: bool):
    records = [
        {"type": "user", "uuid": "u1", "sessionId": "s1",
         "timestamp": "2026-10-17T10:00:00.000Z",
         "message": {"role": "user", "content": "check the render"}},
        {"type": "assistant", "uuid": "a1", "parentUuid": "u1", "requestId": "r1", "sessionId": "s1",
         "timestamp": "2026-10-17T10:00:01.000Z",
         "message": {"id": "m1", "role": "assistant", "model": "claude-example",
                     "content": [{"type": "tool_use", "id": "tu1", "name": "Bash",
                                  "input": {"command": "check --all"}}],
                     "usage": {"input_tokens": 10, "output_tokens": 5}}},
    ]
    if failing_tool_result:
        records.append(
            {"type": "user", "uuid": "u2", "parentUuid": "a1", "sessionId": "s1",
             "timestamp": "2026-10-17T10:00:02.000Z",
             "message": {"role": "user", "content": [
                 {"type": "tool_result", "tool_use_id": "tu1", "is_error": True,
                  "content": [{"type": "text", "text": "This command requires approval"}]}]}})
    else:
        records.append(
            {"type": "user", "uuid": "u2", "parentUuid": "a1", "sessionId": "s1",
             "timestamp": "2026-10-17T10:00:02.000Z",
             "message": {"role": "user", "content": [
                 {"type": "tool_result", "tool_use_id": "tu1", "is_error": False,
                  "content": [{"type": "text", "text": "all 30 pieces read"}]}]}})
    return records


def _explain(tmp_path, name, *, failing_tool_result):
    path = tmp_path / f"{name}.jsonl"
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in _claude_records(
            failing_tool_result=failing_tool_result)),
        encoding="utf-8",
    )
    with Services(data_dir=tmp_path / f"{name}-store", settings=METADATA_ONLY) as services:
        imported = services.import_sources([path], fmt="claude")[0]
        diagnosed = json.loads(services.explain_text(imported["run_id"], as_json=True))
    return imported, diagnosed


def _policy_notes(diagnosed):
    return [item for item in diagnosed["missing_evidence"] if POLICY_NOTE_MARKER in item]


def test_policy_note_is_omitted_when_nothing_failed(tmp_path):
    imported, diagnosed = _explain(tmp_path, "clean", failing_tool_result=False)

    assert imported["events"] > 0, "the fixture must actually import"
    assert diagnosed["observed"] == [], "this run records no failure"
    assert diagnosed["hypotheses"] == []
    assert _policy_notes(diagnosed) == [], (
        "a clean run must not carry a note about an unnameable failure mechanism; got "
        f"{[item[:90] for item in _policy_notes(diagnosed)]}"
    )


def test_policy_note_is_present_when_a_failure_could_not_be_explained(tmp_path):
    imported, diagnosed = _explain(tmp_path, "failed", failing_tool_result=True)

    assert imported["events"] > 0
    assert [item["kind"] for item in diagnosed["observed"]] == ["failure:tool_call"]
    notes = _policy_notes(diagnosed)
    assert len(notes) == 1, f"expected exactly one policy note, got {len(notes)}"
    assert "metadata-only" in notes[0]
