"""Hermes session-export adapter (``hermes sessions export --format jsonl``).

The fixtures here reproduce the shapes a real export produces, including the one that is
easy to get wrong: ``tool_calls`` is serialised with ``str()``, so it is a single-quoted
Python literal rather than JSON. A fixture written with ``json.dumps`` would hide that.

Covered:

* the happy path end to end through ``Services`` (import → timeline → explain → replay);
* failure detection from an explicit signal (non-zero ``exit_code``, truthy ``error``),
  and the honest ``unknown`` when a payload carries neither;
* retention: mechanism text present under ``redacted-summary``, absent under
  ``metadata-only``;
* privacy: prompt text and tool arguments never reach the store, the explanation or the
  export;
* format detection and multi-session files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hermes_run_debugger.cli import Services
from hermes_run_debugger.import_v1 import ImportRefused, detect_format
from hermes_run_debugger.settings import Settings

SEED = "ghp_ab12cd34ef56gh78ij90kl12mn34op56qr78"


def _session(session_id="20260101_000000_abcdef", *, messages, model="example-model",
             parent=None, source="cli"):
    """One session record shaped like ``hermes sessions export --format jsonl``."""
    return {
        "id": session_id,
        "source": source,
        "user_id": None,
        "model": model,
        "parent_session_id": parent,
        "started_at": 1780000000.0,
        "ended_at": 1780000100.0,
        "end_reason": "user_exit",
        "message_count": len(messages),
        "tool_call_count": sum(1 for m in messages if m.get("role") == "tool"),
        "messages": messages,
    }


def _msg(role, content, *, mid, ts=1780000000.0, tool_calls=None, tool_call_id=None,
         tool_name=None):
    return {
        "id": mid,
        "session_id": "PLACEHOLDER",
        "role": role,
        "content": content,
        "tool_call_id": tool_call_id,
        "tool_calls": tool_calls,
        "tool_name": tool_name,
        "timestamp": ts,
        "token_count": 10,
        "finish_reason": None,
    }


def _tool_call_payload(*, code, output="", error=None, status=None, extra=None):
    payload = {"output": output, "exit_code": code, "error": error}
    if status is not None:
        payload["status"] = status
    if extra:
        payload.update(extra)
    return json.dumps(payload)


def _write(tmp_path, sessions, name="export.jsonl"):
    path = tmp_path / name
    path.write_text("".join(json.dumps(s) + "\n" for s in sessions), encoding="utf-8")
    return path


def _import(tmp_path, path, *, mode="redacted-summary"):
    with Services(data_dir=tmp_path / "store", settings=Settings(retention_mode=mode)) as services:
        imported = services.import_sources([path], fmt="hermes")[0]
        explained = json.loads(services.explain_text(imported["run_id"], as_json=True))
        return imported, explained


# --- detection ---------------------------------------------------------------


def test_detects_a_hermes_session_export(tmp_path):
    path = _write(tmp_path, [_session(messages=[_msg("user", "hi", mid="m1")])])
    assert detect_format(path) == "hermes"


def test_a_claude_transcript_is_not_mistaken_for_a_hermes_export(tmp_path):
    path = tmp_path / "claude.jsonl"
    path.write_text(
        json.dumps({"type": "assistant", "uuid": "u1", "sessionId": "s1",
                    "message": {"role": "assistant", "content": "hello"}}) + "\n",
        encoding="utf-8",
    )
    assert detect_format(path) == "claude"


def test_a_non_session_jsonl_is_refused_with_a_reason(tmp_path):
    path = tmp_path / "other.jsonl"
    path.write_text(json.dumps({"hello": "world"}) + "\n", encoding="utf-8")
    # Explicit detection defers to the caller's choice; the refusal happens at import,
    # where the file is actually read for session records.
    with pytest.raises(ImportRefused) as excinfo, Services(
        data_dir=tmp_path / "store"
    ) as services:
        services.import_sources([path], fmt="hermes")
    assert "messages" in str(excinfo.value)


# --- the happy path ----------------------------------------------------------


def test_imports_a_session_end_to_end(tmp_path):
    path = _write(tmp_path, [_session(messages=[
        _msg("user", "run the checks", mid="m1"),
        _msg("assistant", "on it", mid="m2", ts=1780000001.0,
             tool_calls=str([{"id": "call_1", "type": "function",
                              "function": {"name": "terminal", "arguments": '{"cmd": "ls"}'}}])),
        _msg("tool", _tool_call_payload(code=0, output="file.txt"), mid="m3",
             ts=1780000002.0, tool_call_id="call_1", tool_name="terminal"),
        _msg("assistant", "done", mid="m4", ts=1780000003.0),
    ])])
    with Services(data_dir=tmp_path / "store") as services:
        imported = services.import_sources([path], fmt="hermes")[0]
        assert imported["format"] == "hermes"
        # note (user) + model_call & tool_call (assistant) + tool result + model_call
        assert imported["events"] == 5
        assert imported["attempts"] == 1
        assert services.timeline_text(imported["run_id"])
        assert services.replay_text(imported["run_id"])


def test_python_repr_tool_calls_are_parsed(tmp_path):
    """The real export uses ``str()``, not JSON: single quotes, Python literals."""
    path = _write(tmp_path, [_session(messages=[
        _msg("assistant", "calling", mid="m2",
             tool_calls="[{'id': 'call_q04n6fno', 'call_id': 'call_q04n6fno', "
                        "'type': 'function', 'function': {'name': 'terminal', "
                        "'arguments': '{\"command\": \"uptime\"}'}}]"),
    ])])
    with Services(data_dir=tmp_path / "store") as services:
        imported = services.import_sources([path], fmt="hermes")[0]
        assert imported["stats"]["tool_calls_started"] == 1
        assert imported["stats"]["unparsed_tool_calls"] == 0


# --- failure detection -------------------------------------------------------


def test_non_zero_exit_code_is_a_reported_failure(tmp_path):
    path = _write(tmp_path, [_session(messages=[
        _msg("assistant", "check", mid="m1",
             tool_calls=str([{"id": "call_1", "function": {"name": "terminal", "arguments": "{}"}}])),
        _msg("tool", _tool_call_payload(code=1, output="Permission denied"), mid="m2",
             tool_call_id="call_1", tool_name="terminal"),
        _msg("assistant", "continued", mid="m3", ts=1780000005.0),
    ])])
    _, explained = _import(tmp_path, path)
    failures = [o for o in explained["observed"] if o["kind"].startswith("failure:")]
    assert len(failures) == 1
    assert "Permission denied" in failures[0]["detail"]
    assert any(h["rule_id"] == "R002" for h in explained["hypotheses"])


def test_blocked_command_error_is_a_reported_failure(tmp_path):
    """``exit_code: -1`` with a ``BLOCKED:`` error is how a refused command is recorded."""
    path = _write(tmp_path, [_session(messages=[
        _msg("assistant", "try", mid="m1",
             tool_calls=str([{"id": "call_9", "function": {"name": "terminal", "arguments": "{}"}}])),
        _msg("tool", _tool_call_payload(code=-1, error="BLOCKED: dangerous command"), mid="m2",
             tool_call_id="call_9", tool_name="terminal"),
    ])])
    _, explained = _import(tmp_path, path)
    failures = [o for o in explained["observed"] if o["kind"].startswith("failure:")]
    assert len(failures) == 1
    assert "BLOCKED" in failures[0]["detail"]


def test_payload_without_a_status_signal_stays_unknown(tmp_path):
    """A result with no exit code and no error is not evidence of success."""
    path = _write(tmp_path, [_session(messages=[
        _msg("assistant", "write", mid="m1",
             tool_calls=str([{"id": "call_w", "function": {"name": "write_file",
                                                           "arguments": "{}"}}])),
        _msg("tool", json.dumps({"bytes_written": 12, "resolved_path": "/tmp/x"}), mid="m2",
             tool_call_id="call_w", tool_name="write_file"),
    ])])
    _, explained = _import(tmp_path, path)
    assert explained["observed"] == [], "a status-less payload must not be read as a failure"
    statuses = {
        event["reported_status"]
        for event in json.loads(json.dumps(explained))["observed"]
    }
    assert statuses <= {"unknown"}


# --- retention ---------------------------------------------------------------


def test_metadata_only_drops_the_mechanism_text(tmp_path):
    path = _write(tmp_path, [_session(messages=[
        _msg("assistant", "check", mid="m1",
             tool_calls=str([{"id": "call_1", "function": {"name": "terminal", "arguments": "{}"}}])),
        _msg("tool", _tool_call_payload(code=1, output="SPECIFIC-MECHANISM-TEXT"), mid="m2",
             tool_call_id="call_1", tool_name="terminal"),
    ])])
    _, explained = _import(tmp_path, path, mode="metadata-only")
    failures = [o for o in explained["observed"] if o["kind"].startswith("failure:")]
    assert len(failures) == 1, "the failure is still observed"
    assert "SPECIFIC-MECHANISM-TEXT" not in json.dumps(explained)


def test_redacted_summary_keeps_the_mechanism_text(tmp_path):
    path = _write(tmp_path, [_session(messages=[
        _msg("assistant", "check", mid="m1",
             tool_calls=str([{"id": "call_1", "function": {"name": "terminal", "arguments": "{}"}}])),
        _msg("tool", _tool_call_payload(code=1, output="SPECIFIC-MECHANISM-TEXT"), mid="m2",
             tool_call_id="call_1", tool_name="terminal"),
    ])])
    _, explained = _import(tmp_path, path)
    assert "SPECIFIC-MECHANISM-TEXT" in json.dumps(explained)


# --- privacy -----------------------------------------------------------------


def test_prompts_and_tool_arguments_are_never_persisted(tmp_path):
    path = _write(tmp_path, [_session(messages=[
        _msg("user", f"my token is {SEED}", mid="m1"),
        _msg("assistant", "noted", mid="m2",
             tool_calls=str([{"id": "call_1", "function": {
                 "name": "terminal", "arguments": json.dumps({"cmd": f"echo {SEED}"})}}])),
        _msg("tool", _tool_call_payload(code=0, output="ok"), mid="m3",
             tool_call_id="call_1", tool_name="terminal"),
    ])])
    with Services(data_dir=tmp_path / "store") as services:
        imported = services.import_sources([path], fmt="hermes")[0]
        explained = services.explain_text(imported["run_id"], as_json=True)
        report = services.export_report(imported["run_id"], tmp_path / "report.md")
        timeline = services.timeline_text(imported["run_id"])

    assert SEED not in explained
    assert SEED not in timeline
    assert SEED not in Path(report).read_text(encoding="utf-8")
    for db in (tmp_path / "store").rglob("*.db"):
        assert SEED.encode() not in db.read_bytes(), f"seed reached the store at {db}"


# --- multi-session files -----------------------------------------------------


def test_two_sessions_in_one_export_become_two_attempts(tmp_path):
    path = _write(tmp_path, [
        _session("sess-a", messages=[_msg("user", "one", mid="a1")]),
        _session("sess-b", messages=[_msg("user", "two", mid="b1")], parent="sess-a",
                 source="subagent"),
    ])
    with Services(data_dir=tmp_path / "store") as services:
        imported = services.import_sources([path], fmt="hermes")[0]
        timeline = services.load_timeline(imported["run_id"])
    assert len(timeline.attempts) == 2
    roles = sorted(attempt["role"] for attempt in timeline.attempts)
    assert roles == ["primary", "subagent"]
    child = next(a for a in timeline.attempts if a["role"] == "subagent")
    parent = next(a for a in timeline.attempts if a["role"] == "primary")
    assert child["parent_attempt_id"] == parent["attempt_id"]
