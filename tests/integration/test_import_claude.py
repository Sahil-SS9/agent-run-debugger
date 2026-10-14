"""DT02 — Claude JSONL adapter conformance against an independently counted oracle.

The oracle in this file re-derives expectations straight from the fixtures with
its own loop; it never calls the adapter's internals. Semantics under test are the
ones the pinned analyzer documents empirically (attributed in
``THIRD_PARTY_NOTICES.md``):

* one API response is split into several ``type:"assistant"`` entries sharing a
  ``requestId``/``message.id``, and only the last carries the final
  ``output_tokens`` → dedupe by requestId, keep the max, so tokens are not
  counted 3-10x;
* resumed sessions re-serialise earlier entries into a new file → dedupe globally
  by entry ``uuid``;
* subagent transcripts are separate files with a meta sibling or a filename label;
* a "human" message is one where ``isSidechain``/``isMeta``/``isCompactSummary``
  are falsy and the content is plain text rather than a tool result.
"""

from __future__ import annotations

import json
from pathlib import Path

from hermes_run_debugger.import_claude import import_claude_trace
from hermes_run_debugger.jsonio import StreamLimits

ROOT_ENTRIES = [
    {
        "type": "user", "uuid": "u1", "parentUuid": None, "sessionId": "s1",
        "timestamp": "2026-10-14T10:00:00.000Z", "cwd": "/home/kensei/proj",
        "isSidechain": False,
        "message": {"role": "user", "content": "fix the failing test"},
    },
    # request r1 is split across three entries; only the last has the final output tokens
    {
        "type": "assistant", "uuid": "a1", "parentUuid": "u1", "requestId": "r1",
        "sessionId": "s1", "timestamp": "2026-10-14T10:00:01.000Z",
        "message": {"id": "msg_1", "role": "assistant", "model": "claude-example",
                    "content": [{"type": "text", "text": "Looking at the test."}],
                    "usage": {"input_tokens": 100, "output_tokens": 5,
                              "cache_read_input_tokens": 10, "cache_creation_input_tokens": 20}},
    },
    {
        "type": "assistant", "uuid": "a2", "parentUuid": "a1", "requestId": "r1",
        "sessionId": "s1", "timestamp": "2026-10-14T10:00:02.000Z",
        "message": {"id": "msg_1", "role": "assistant", "model": "claude-example",
                    "content": [{"type": "tool_use", "id": "tu1", "name": "Bash",
                                 "input": {"command": "pytest -q"}}],
                    "usage": {"input_tokens": 100, "output_tokens": 9,
                              "cache_read_input_tokens": 10, "cache_creation_input_tokens": 20}},
    },
    {
        "type": "assistant", "uuid": "a3", "parentUuid": "a2", "requestId": "r1",
        "sessionId": "s1", "timestamp": "2026-10-14T10:00:03.000Z",
        "message": {"id": "msg_1", "role": "assistant", "model": "claude-example",
                    "content": [{"type": "tool_use", "id": "tu1", "name": "Bash",
                                 "input": {"command": "pytest -q"}}],
                    "usage": {"input_tokens": 100, "output_tokens": 12,
                              "cache_read_input_tokens": 10, "cache_creation_input_tokens": 20}},
    },
    {
        "type": "user", "uuid": "u2", "parentUuid": "a3", "sessionId": "s1",
        "timestamp": "2026-10-14T10:00:04.000Z",
        "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "tu1", "is_error": True,
             "content": [{"type": "text", "text": "2 failed, 1 passed"}]}]},
    },
    {
        "type": "assistant", "uuid": "a4", "parentUuid": "u2", "requestId": "r2",
        "sessionId": "s1", "timestamp": "2026-10-14T10:00:05.000Z",
        "message": {"id": "msg_2", "role": "assistant", "model": "claude-example",
                    "content": [{"type": "text", "text": "Fixing it now."}],
                    "usage": {"input_tokens": 120, "output_tokens": 7}},
    },
    # meta/compaction noise must never masquerade as a human turn
    {
        "type": "user", "uuid": "u3", "parentUuid": "a4", "sessionId": "s1",
        "timestamp": "2026-10-14T10:00:06.000Z", "isMeta": True,
        "message": {"role": "user", "content": "injected context"},
    },
    {
        "type": "user", "uuid": "u4", "parentUuid": "a4", "sessionId": "s1",
        "timestamp": "2026-10-14T10:00:07.000Z", "isCompactSummary": True,
        "message": {"role": "user", "content": "summary of earlier work"},
    },
]

RESUME_ENTRIES = [
    # replayed history: same uuids as the root file
    ROOT_ENTRIES[1],
    ROOT_ENTRIES[2],
    {
        "type": "assistant", "uuid": "a5", "parentUuid": "a3", "requestId": "r3",
        "sessionId": "s1", "timestamp": "2026-10-14T10:05:00.000Z",
        "message": {"id": "msg_3", "role": "assistant", "model": "claude-example",
                    "content": [{"type": "text", "text": "Still working."}],
                    "usage": {"input_tokens": 130, "output_tokens": 3}},
    },
]

SUBAGENT_ENTRIES = [
    {
        "type": "assistant", "uuid": "sa1", "parentUuid": None, "requestId": "rs1",
        "sessionId": "s1", "timestamp": "2026-10-14T10:00:03.500Z", "isSidechain": True,
        "agentId": "a-security-reviewer-1a2b3c4d5e6f7a8b",
        "message": {"id": "msg_s1", "role": "assistant", "model": "claude-example",
                    "content": [{"type": "tool_use", "id": "tu9", "name": "Grep",
                                 "input": {"pattern": "token"}}],
                    "usage": {"input_tokens": 50, "output_tokens": 4}},
    },
]

ORACLE_MAX_OUTPUT = {"r1": 12, "r2": 7, "r3": 3, "rs1": 4}


def write_jsonl(path: Path, entries: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")
    return path


def oracle_requests(entries: list[dict]) -> dict[str, dict]:
    """Independent oracle: dedupe by requestId, keep the max output_tokens."""
    seen_uuid: set[str] = set()
    requests: dict[str, dict] = {}
    for entry in entries:
        if entry.get("uuid") in seen_uuid:
            continue
        seen_uuid.add(entry["uuid"])
        if entry.get("type") != "assistant":
            continue
        rid = entry.get("requestId") or entry["message"].get("id")
        usage = entry["message"].get("usage") or {}
        best = requests.get(rid)
        if best is None or usage.get("output_tokens", 0) > best["output_tokens"]:
            requests[rid] = {
                "output_tokens": usage.get("output_tokens", 0),
                "input_tokens": usage.get("input_tokens", 0),
            }
    return requests


def test_split_requests_are_merged_and_never_double_counted(tmp_path):
    root = write_jsonl(tmp_path / "session.jsonl", ROOT_ENTRIES)
    imported = import_claude_trace([root], limits=StreamLimits())
    oracle = oracle_requests(ROOT_ENTRIES)

    model_calls = [e for e in imported.result.events if e.event_kind == "model_call"]
    assert len(model_calls) == len(oracle) == 2
    by_usage = sorted(e.usage.output_tokens for e in model_calls)
    assert by_usage == sorted(spec["output_tokens"] for spec in oracle.values())

    total_output = sum(e.usage.output_tokens or 0 for e in model_calls)
    assert total_output == sum(spec["output_tokens"] for spec in oracle.values()) == 19
    assert imported.stats["assistant_records"] == 4
    assert imported.stats["requests"] == 2
    assert imported.stats["records_merged_into_requests"] == 2  # a1+a2+a3 -> r1
    assert imported.stats["duplicate_records_dropped"] == 0


def test_tool_calls_and_results_are_linked_by_tool_use_id(tmp_path):
    root = write_jsonl(tmp_path / "session.jsonl", ROOT_ENTRIES)
    imported = import_claude_trace([root], limits=StreamLimits())
    events = imported.result.events

    starts = [e for e in events if e.event_kind == "tool_call" and e.span_id is None]
    results = [e for e in events if e.event_kind == "tool_call" and e.span_id is not None]
    assert len(starts) == 1, "a tool_use id repeated across split entries is one start"
    assert starts[0].name == "Bash"
    assert len(results) == 1
    assert results[0].reported_status == "failed"
    assert results[0].causal_parents == (starts[0].event_id,)

    model_call_ids = {e.event_id for e in events if e.event_kind == "model_call"}
    assert set(starts[0].causal_parents) <= model_call_ids


def test_human_turns_are_notes_and_noise_is_not(tmp_path):
    root = write_jsonl(tmp_path / "session.jsonl", ROOT_ENTRIES)
    imported = import_claude_trace([root], limits=StreamLimits())
    notes = [e for e in imported.result.events if e.event_kind == "note"]
    assert len(notes) == 1, "only the plain human message becomes a note"
    assert imported.stats["human_messages"] == 1
    # meta and compact-summary entries are counted as skipped, never as human turns
    assert imported.stats["meta_records_skipped"] == 2
    rendered = json.dumps([e.as_dict() for e in imported.result.events])
    assert "injected context" not in rendered
    assert "summary of earlier work" not in rendered


def test_resumed_session_replay_is_deduped_globally_by_uuid(tmp_path):
    root = write_jsonl(tmp_path / "session.jsonl", ROOT_ENTRIES)
    resumed = write_jsonl(tmp_path / "session-resumed.jsonl", RESUME_ENTRIES)
    imported = import_claude_trace([root, resumed], limits=StreamLimits())

    oracle = oracle_requests(ROOT_ENTRIES + RESUME_ENTRIES)
    model_calls = [e for e in imported.result.events if e.event_kind == "model_call"]
    assert len(model_calls) == len(oracle) == 3, "replayed history must not add events"
    assert imported.stats["duplicate_records_dropped"] == 2
    by_request_outputs = sorted(e.usage.output_tokens for e in model_calls)
    assert by_request_outputs == sorted(spec["output_tokens"] for spec in oracle.values())


def test_subagent_transcript_becomes_a_child_attempt(tmp_path):
    root = write_jsonl(tmp_path / "session.jsonl", ROOT_ENTRIES)
    subagent = write_jsonl(
        tmp_path / "session" / "subagents" / "agent-security-reviewer-1a2b3c4d.jsonl",
        SUBAGENT_ENTRIES,
    )
    imported = import_claude_trace([root, subagent], limits=StreamLimits())

    attempts = imported.result.attempts
    assert len(attempts) == 2
    root_attempt = next(a for a in attempts if a.role == "primary")
    child = next(a for a in attempts if a.role != "primary")
    assert child.parent_attempt_id == root_attempt.attempt_id
    assert child.branch == "security-reviewer"
    assert child.model == "claude-example"
    subagent_events = [e for e in imported.result.events if e.attempt_id == child.attempt_id]
    assert [e.event_kind for e in subagent_events] == ["model_call", "tool_call"]
    assert imported.stats["subagent_files"] == 1


def test_cache_and_input_token_fields_carry_verbatim(tmp_path):
    root = write_jsonl(tmp_path / "session.jsonl", ROOT_ENTRIES)
    imported = import_claude_trace([root], limits=StreamLimits())
    r1 = next(
        e for e in imported.result.events
        if e.event_kind == "model_call" and e.usage.output_tokens == 12
    )
    assert r1.usage.input_tokens == 100
    assert r1.usage.cache_read_tokens == 10
    assert r1.usage.cache_write_tokens == 20
    assert r1.usage.cost is None, "no price is invented from tokens"
    assert r1.usage.cost_kind == "unknown"


def test_unknown_record_types_are_counted_not_guessed(tmp_path):
    entries = [*ROOT_ENTRIES[:1], {"type": "brand_new_record", "uuid": "x1", "payload": {"a": 1}}]
    root = write_jsonl(tmp_path / "session.jsonl", entries)
    imported = import_claude_trace([root], limits=StreamLimits())
    assert imported.stats["unsupported_records"] == 1
    assert any("brand_new_record" in note for note in imported.notes)
    assert all(e.event_kind != "note" or e.event_id for e in imported.result.events)
