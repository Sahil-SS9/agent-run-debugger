"""Claude JSONL transcript adapter (one tested foreign adapter for v1).

Independently implemented in Python from the pinned public source's *documented,
empirically discovered* structure (see ``THIRD_PARTY_NOTICES.md`` for attribution
and the licence basis). It is an adapter, not a port: the pinned source is a
JavaScript usage analyser, this is a Python importer into the Trace v1 contract.

Documented source semantics this adapter implements:

* One API response is split into several ``type:"assistant"`` entries that share a
  ``requestId`` / ``message.id``; only the last carries the final
  ``output_tokens``. Records are merged per request and the **maximum**
  ``output_tokens`` is kept, so a run is not counted or billed 3-10x.
* ``type:"user"`` entries mix tool results with meta-injected text, interrupt
  markers and compact summaries. Only a plain-text entry with falsy
  ``isSidechain`` / ``isMeta`` / ``isCompactSummary`` is a human turn.
* Resumed sessions can re-serialise earlier entries into a new file: dedupe
  globally by ``uuid`` so replayed history is not counted twice.
* Subagent transcripts live in ``…/<sessionId>/subagents/*.jsonl`` with an
  optional sibling ``*.meta.json`` carrying ``agentType``; otherwise the label is
  taken from the filename (``agent-<label>-<hash>.jsonl``).

What is deliberately NOT retained: prompt text and tool arguments (references
only), and tool-result text under ``retention_mode="metadata-only"``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .event_v1 import EVENT_KINDS, Gap, validate_trace_records
from .identity import content_ref, redacted_content_ref, sha256_hex, stable_id
from .import_v1 import ImportRefused, TraceImport, guard_source
from .jsonio import InputLimitExceeded, MalformedRecord, ScanState, StreamLimits, scan_jsonl
from .redact import sanitise_message

__all__ = ["MAX_RESULT_SUMMARY", "RETENTION_MODES", "import_claude_trace"]

#: Bound on retained tool-result summary text (redacted later, before persistence).
MAX_RESULT_SUMMARY = 500

RETENTION_MODES = ("redacted-summary", "metadata-only")

_SKIPPED_TYPES = {"system", "summary", "queue-operation", "file-history-snapshot"}
_HEX_RE = re.compile(r"^[0-9a-f]{8,}$")
#: Claude usage keys mapped onto the Trace v1 usage contract. Unmapped keys are
#: dropped deliberately; the count is reported in a note.
_USAGE_MAP = {
    "input_tokens": "input_tokens",
    "output_tokens": "output_tokens",
    "cache_read_input_tokens": "cache_read_tokens",
    "cache_creation_input_tokens": "cache_write_tokens",
}


@dataclass
class _Source:
    path: Path
    kind: str  # "main" | "subagent"
    label: str = ""
    entries: list[dict[str, Any]] = field(default_factory=list)
    state: ScanState | None = None
    partial: bool = False


def _subagent_label(path: Path) -> str:
    meta = path.parent / f"{path.stem}.meta.json"
    if meta.exists():
        try:
            payload = json.loads(meta.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
        agent_type = payload.get("agentType") if isinstance(payload, Mapping) else None
        if isinstance(agent_type, str) and agent_type.strip():
            return agent_type.strip()
    stem = path.stem
    if stem.startswith("agent-"):
        stem = stem[len("agent-"):]
    if "-" in stem:
        head, _, tail = stem.rpartition("-")
        if head and _HEX_RE.match(tail):
            return head
    return "subagent" if _HEX_RE.match(stem) else stem


def _classify(path: Path) -> _Source:
    is_subagent = "subagents" in path.parts or path.stem.startswith("agent-")
    return _Source(
        path=path,
        kind="subagent" if is_subagent else "main",
        label=_subagent_label(path) if is_subagent else "main",
    )


def _normalise_usage(raw: Any) -> tuple[dict[str, Any], list[str]]:
    """Map reported Claude usage onto Trace v1 usage. Returns (usage, unmapped_keys)."""
    if not isinstance(raw, Mapping):
        return {}, []
    usage: dict[str, Any] = {}
    unmapped: list[str] = []
    for key, value in raw.items():
        target = _USAGE_MAP.get(key)
        if target is None:
            unmapped.append(str(key))
            continue
        usage[target] = value if isinstance(value, int) and not isinstance(value, bool) else None
    return usage, sorted(unmapped)


def _text_of(content: Any) -> str:
    """Best-effort plain text of a content value. Caller bounds the length."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, Mapping) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(parts)
    return ""


def _content_blocks(entry: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    message = entry.get("message")
    content = message.get("content") if isinstance(message, Mapping) else None
    if isinstance(content, list):
        for block in content:
            if isinstance(block, Mapping):
                yield block


def _is_tool_result(content: Any) -> bool:
    if isinstance(content, list) and content and isinstance(content[0], Mapping):
        return content[0].get("type") == "tool_result"
    return False


def _request_key(entry: Mapping[str, Any]) -> str:
    request_id = entry.get("requestId")
    if isinstance(request_id, str) and request_id:
        return request_id
    message = entry.get("message")
    if isinstance(message, Mapping) and isinstance(message.get("id"), str):
        return str(message["id"])
    return str(entry.get("uuid") or "")


def import_claude_trace(
    paths: str | Path | Sequence[str | Path],
    *,
    limits: StreamLimits | None = None,
    allow_partial: bool = False,
    retention_mode: str = "redacted-summary",
    run_id: str | None = None,
) -> TraceImport:
    """Import one or more explicitly selected Claude JSONL transcripts."""
    if retention_mode not in RETENTION_MODES:
        raise ValueError(f"retention_mode must be one of {RETENTION_MODES}")
    limits = limits or StreamLimits()
    if isinstance(paths, (str, Path)):
        paths = [paths]
    if not paths:
        raise ImportRefused("empty-selection", ["no source files were selected"])

    sources: list[_Source] = []
    for raw_path in paths:
        path = Path(raw_path)
        guard_source(path)
        source = _classify(path)
        state = ScanState(path=str(path))
        try:
            entries, state = scan_jsonl(path, limits=limits, allow_partial=allow_partial, state=state)
        except InputLimitExceeded as exc:
            raise ImportRefused("limits", [str(exc)]) from exc
        except MalformedRecord as exc:
            raise ImportRefused("malformed", [str(exc)]) from exc
        source.entries = [entry for entry in entries if isinstance(entry, dict)]
        source.state = state
        source.partial = state.partial
        sources.append(source)

    return _build_trace(sources, limits=limits, retention_mode=retention_mode, run_id=run_id)


def _build_trace(
    sources: Sequence[_Source], *, limits: StreamLimits, retention_mode: str, run_id: str | None
) -> TraceImport:
    stats: dict[str, Any] = {
        "assistant_records": 0,
        "requests": 0,
        "records_merged_into_requests": 0,
        "duplicate_records_dropped": 0,
        "meta_records_skipped": 0,
        "unsupported_records": 0,
        "human_messages": 0,
        "tool_calls_started": 0,
        "tool_results": 0,
        "subagent_files": sum(1 for source in sources if source.kind == "subagent"),
        "entries_read": sum(len(source.entries) for source in sources),
    }
    notes: list[str] = []
    warnings: list[str] = []
    unsupported_types: list[str] = []
    unmapped_usage_keys: set[str] = set()
    partial = any(source.partial for source in sources)

    session_ids: list[str] = []
    for source in sources:
        for entry in source.entries:
            session_id = entry.get("sessionId")
            if isinstance(session_id, str) and session_id and session_id not in session_ids:
                session_ids.append(session_id)

    digest_input = "|".join(
        f"{source.path.name}:{source.state.digest if source.state else ''}" for source in sources
    )
    if run_id is None:
        run_id = f"run_claude_{sha256_hex(digest_input + '|' + ','.join(session_ids))[:12]}"
    trace_id = stable_id("trace", run_id)
    root_attempt_id = stable_id("att", run_id, "primary")

    attempts: list[dict[str, Any]] = [{
        "kind": "attempt",
        "attempt_id": root_attempt_id,
        "run_id": run_id,
        "parent_attempt_id": None,
        "model": None,
        "provider": "anthropic",
        "role": "primary",
        "branch": "main",
        "sequence": 0,
        "started_at": None,
        "ended_at": None,
        # The transcript does not report a run outcome: "unknown" is the honest value.
        "outcome": "unknown",
        "unknowns": ["outcome"],
    }]
    attempt_ids: dict[int, str] = {}
    sub_index = 0
    for index, source in enumerate(sources):
        if source.kind == "subagent":
            sub_index += 1
            attempt_id = stable_id("att", run_id, source.path.name)
            attempts.append({
                "kind": "attempt",
                "attempt_id": attempt_id,
                "run_id": run_id,
                "parent_attempt_id": root_attempt_id,
                "model": None,
                "provider": "anthropic",
                "role": "subagent",
                "branch": source.label,
                "sequence": sub_index,
                "started_at": None,
                "ended_at": None,
                "outcome": "unknown",
                "unknowns": ["outcome"],
            })
        else:
            attempt_id = root_attempt_id
        attempt_ids[index] = attempt_id

    events: list[dict[str, Any]] = []
    seen_uuids: set[str] = set()
    sequence = 0

    def emit(payload: dict[str, Any]) -> str:
        nonlocal sequence
        payload["source_sequence"] = sequence
        sequence += 1
        events.append(payload)
        return str(payload["event_id"])

    for index, source in enumerate(sources):
        attempt_id = attempt_ids[index]
        uuid_to_event: dict[str, str] = {}
        tool_start: dict[str, str] = {}
        pending: dict[str, dict[str, Any]] = {}
        state_holder = {"last": None, "current": None}

        def flush(
            request_id: str | None,
            *,
            pending: dict[str, dict[str, Any]],
            uuid_to_event: dict[str, str],
            tool_start: dict[str, str],
            state_holder: dict[str, Any],
            attempt_id: str,
        ) -> None:
            """Emit the merged model_call + tool starts for the open request."""
            if request_id is None:
                return
            merged = pending.pop(request_id, None)
            state_holder["current"] = None
            if merged is None:
                return
            parent_uuid = merged.get("parentUuid")
            parent = uuid_to_event.get(parent_uuid) or state_holder["last"]
            event_id = stable_id("evt", run_id, attempt_id, "model_call", request_id)
            error_text = _text_of(merged.get("content"))[:MAX_RESULT_SUMMARY] \
                if merged.get("isApiErrorMessage") else None
            emit({
                "kind": "event",
                "event_id": event_id,
                "run_id": run_id,
                "attempt_id": attempt_id,
                "span_id": None,
                "causal_parents": [parent] if parent else [],
                "wall_time": merged.get("timestamp"),
                "monotonic_ms": None,
                "clock": {"source": "wall", "quality": "medium"},
                "event_kind": "model_call",
                "reported_status": "failed" if merged.get("isApiErrorMessage") else "ok",
                "reported_error": error_text,
                "usage": merged.get("usage") or {},
                "evidence_ref": f"claude:request:{request_id}",
                "delivered_via": "import",
                "semantic_provenance": "reported",
                "name": merged.get("model"),
                "gaps": [],
                "contradictions": [],
            })
            for uuid in merged.get("block_uuids", []):
                uuid_to_event[uuid] = event_id
            state_holder["last"] = event_id

            for tool in merged.get("tools", []):
                tool_event_id = stable_id("evt", run_id, attempt_id, "tool_call", tool["id"])
                emit({
                    "kind": "event",
                    "event_id": tool_event_id,
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                    "span_id": None,
                    "causal_parents": [event_id],
                    "wall_time": merged.get("timestamp"),
                    "monotonic_ms": None,
                    "clock": {"source": "wall", "quality": "medium"},
                    "event_kind": "tool_call",
                    "reported_status": "unknown",
                    "reported_error": None,
                    "usage": {},
                    "evidence_ref": f"claude:tool_use:{tool['id']}",
                    "delivered_via": "import",
                    "semantic_provenance": "reported",
                    "name": tool["name"],
                    "arguments_ref": redacted_content_ref(tool.get("input")),
                    "gaps": [],
                    "contradictions": [],
                })
                tool_start[tool["id"]] = tool_event_id
                state_holder["last"] = tool_event_id
                stats["tool_calls_started"] += 1

        for entry in source.entries:
            entry_type = entry.get("type")
            entry_uuid = entry.get("uuid")
            if isinstance(entry_uuid, str) and entry_uuid:
                if entry_uuid in seen_uuids:
                    stats["duplicate_records_dropped"] += 1
                    continue
                seen_uuids.add(entry_uuid)

            if entry_type == "assistant":
                stats["assistant_records"] += 1
                request_id = _request_key(entry)
                if state_holder["current"] is None:
                    state_holder["current"] = request_id
                elif request_id != state_holder["current"]:
                    flush(
                        state_holder["current"], pending=pending, uuid_to_event=uuid_to_event,
                        tool_start=tool_start, state_holder=state_holder, attempt_id=attempt_id,
                    )
                    state_holder["current"] = request_id

                message = entry.get("message") if isinstance(entry.get("message"), Mapping) else {}
                usage, unmapped = _normalise_usage(message.get("usage"))
                unmapped_usage_keys.update(unmapped)
                merged = pending.get(request_id)
                if merged is None:
                    stats["requests"] += 1
                    merged = {
                        "usage": usage,
                        "output_tokens": int(usage.get("output_tokens") or 0),
                        "timestamp": entry.get("timestamp"),
                        "parentUuid": entry.get("parentUuid"),
                        "model": message.get("model"),
                        "isApiErrorMessage": bool(entry.get("isApiErrorMessage")),
                        "content": [],
                        "tools": [],
                        "block_uuids": [],
                        "seen_tool_ids": set(),
                    }
                    pending[request_id] = merged
                else:
                    stats["records_merged_into_requests"] += 1
                    candidate = int(usage.get("output_tokens") or 0)
                    if candidate > merged["output_tokens"]:
                        merged["output_tokens"] = candidate
                        merged["usage"] = usage
                if isinstance(entry_uuid, str) and entry_uuid:
                    merged["block_uuids"].append(entry_uuid)
                for block in _content_blocks(entry):
                    if block.get("type") == "tool_use" and isinstance(block.get("id"), str):
                        if block["id"] in merged["seen_tool_ids"]:
                            continue
                        merged["seen_tool_ids"].add(block["id"])
                        merged["tools"].append({
                            "id": block["id"],
                            "name": block.get("name") or "unknown",
                            "input": block.get("input"),
                        })
                    elif block.get("type") == "text":
                        merged["content"].append(block.get("text"))
                continue

            if entry_type == "user":
                # A user entry closes the open request so the timeline stays in
                # source order: the tool result that follows belongs after it.
                flush(
                    state_holder["current"], pending=pending, uuid_to_event=uuid_to_event,
                    tool_start=tool_start, state_holder=state_holder, attempt_id=attempt_id,
                )
                message = entry.get("message") if isinstance(entry.get("message"), Mapping) else {}
                content = message.get("content")
                if entry.get("isMeta") or entry.get("isCompactSummary") or entry.get("isSidechain"):
                    stats["meta_records_skipped"] += 1
                    continue
                if _is_tool_result(content):
                    stats["tool_results"] += 1
                    for block in content if isinstance(content, list) else []:
                        if not isinstance(block, Mapping) or block.get("type") != "tool_result":
                            continue
                        tool_use_id = str(block.get("tool_use_id") or "")
                        parent = tool_start.get(tool_use_id) or state_holder["last"]
                        summary = ""
                        if retention_mode == "redacted-summary":
                            summary = _text_of(block.get("content"))[:MAX_RESULT_SUMMARY]
                        event_id = stable_id("evt", run_id, attempt_id, "tool_result", tool_use_id)
                        emit({
                            "kind": "event",
                            "event_id": event_id,
                            "run_id": run_id,
                            "attempt_id": attempt_id,
                            # span_id carries the source's tool_use id: an opaque link
                            # between a result and its start, not a reconstructed span.
                            "span_id": tool_use_id or None,
                            "causal_parents": [parent] if parent else [],
                            "wall_time": entry.get("timestamp"),
                            "monotonic_ms": None,
                            "clock": {"source": "wall", "quality": "medium"},
                            "event_kind": "tool_call",
                            "reported_status": "failed" if block.get("is_error") else "ok",
                            "reported_error": summary or None,
                            "usage": {},
                            "evidence_ref": f"claude:tool_result:{tool_use_id}",
                            "delivered_via": "import",
                            "semantic_provenance": "reported",
                            "name": None,
                            "gaps": [],
                            "contradictions": [],
                        })
                        if isinstance(entry_uuid, str) and entry_uuid:
                            uuid_to_event[entry_uuid] = event_id
                        state_holder["last"] = event_id
                    continue
                # a plain human turn: a reference, never the prompt text
                stats["human_messages"] += 1
                parent = uuid_to_event.get(entry.get("parentUuid")) or state_holder["last"]
                event_id = stable_id("evt", run_id, attempt_id, "note", str(entry_uuid or ""))
                emit({
                    "kind": "event",
                    "event_id": event_id,
                    "run_id": run_id,
                    "attempt_id": attempt_id,
                    "span_id": None,
                    "causal_parents": [parent] if parent else [],
                    "wall_time": entry.get("timestamp"),
                    "monotonic_ms": None,
                    "clock": {"source": "wall", "quality": "medium"},
                    "event_kind": "note",
                    "reported_status": "ok",
                    "reported_error": None,
                    "usage": {},
                    "evidence_ref": f"claude:prompt:{entry_uuid}",
                    "delivered_via": "import",
                    "semantic_provenance": "reported",
                    "name": "human",
                    "gaps": [],
                    "contradictions": [],
                })
                if isinstance(entry_uuid, str) and entry_uuid:
                    uuid_to_event[entry_uuid] = event_id
                state_holder["last"] = event_id
                continue

            if entry_type in _SKIPPED_TYPES:
                stats["meta_records_skipped"] += 1
                continue

            stats["unsupported_records"] += 1
            if isinstance(entry_type, str) and entry_type not in unsupported_types:
                unsupported_types.append(entry_type)

        flush(
            state_holder["current"], pending=pending, uuid_to_event=uuid_to_event,
            tool_start=tool_start, state_holder=state_holder, attempt_id=attempt_id,
        )

    if unmapped_usage_keys:
        notes.append(
            "usage keys not part of the Trace v1 contract were dropped (reported by the source, "
            "not mapped): " + ", ".join(sorted(unmapped_usage_keys)[:6])
        )
    if stats["unsupported_records"]:
        notes.append(
            "unsupported record types skipped (not guessed): "
            + sanitise_message(", ".join(unsupported_types[:5]))
        )
    if stats["duplicate_records_dropped"]:
        notes.append(f"{stats['duplicate_records_dropped']} replayed record(s) deduplicated by uuid")
    if stats["records_merged_into_requests"]:
        notes.append(
            f"{stats['records_merged_into_requests']} split assistant record(s) merged per request; "
            "the maximum reported output_tokens per request is kept"
        )
    notes.append(
        "adapter semantics: prompt text and tool arguments are never retained (opaque references "
        "only); request-level usage is the source's own reported value"
    )

    covered = sorted({str(event["event_kind"]) for event in events} & EVENT_KINDS)
    envelope = {
        "kind": "trace",
        "schema": "hermes-run-debugger/trace",
        "version": 1,
        "trace_id": trace_id,
        "run_id": run_id,
        "importer": "import_claude",
        "importer_version": "0.1.0",
        "source_format": "claude-jsonl",
        "source_scope": "explicit-selection",
        "created_at": _first_timestamp(sources) or "1970-01-01T00:00:00Z",
        "source": {
            "kind": "file",
            "ref": content_ref(digest_input),
            "name": sources[0].path.name if sources else "",
        },
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": covered or ["note"],
        "unsupported_kinds": [],
        "completeness": {
            "status": "partial" if (partial or stats["unsupported_records"]) else "complete",
            "missing_kinds": [],
            "notes": notes,
            "source_limits": {
                "max_bytes": limits.max_bytes,
                "max_events": limits.max_events,
            },
        },
        "private_digests": {
            "content": sha256_hex(digest_input),
            "files": [
                {"name": source.path.name, "sha256": source.state.digest if source.state else ""}
                for source in sources
            ],
        },
    }
    _fill_attempt_models(attempts, events)

    records: list[dict[str, Any]] = [envelope, *attempts, *events]
    result = validate_trace_records(records)
    if partial:
        result.gaps.append(
            Gap("truncation", "at least one selected transcript ended mid-record; PARTIAL import")
        )
        warnings.append("import is PARTIAL: at least one source ended mid-record")

    snapshot = {
        "path": str(sources[0].path) if sources else "",
        "sha256": sha256_hex(digest_input),
        "records": stats["entries_read"],
        "partial": partial,
        "files": [
            {
                "path": str(source.path),
                "kind": source.kind,
                "records": len(source.entries),
                "sha256": source.state.digest if source.state else "",
            }
            for source in sources
        ],
    }
    return TraceImport(
        format="claude",
        result=result,
        snapshot=snapshot,
        partial=partial,
        warnings=warnings + list(result.warnings),
        notes=notes,
        stats=stats,
        paths=[str(source.path) for source in sources],
    )


def _first_timestamp(sources: Sequence[_Source]) -> str | None:
    for source in sources:
        for entry in source.entries:
            timestamp = entry.get("timestamp")
            if isinstance(timestamp, str) and timestamp:
                return timestamp
    return None


def _fill_attempt_models(attempts: list[dict[str, Any]], events: Sequence[Mapping[str, Any]]) -> None:
    """Attribute a reported model to an attempt only when the source said so."""
    by_attempt: dict[str, str] = {}
    for event in events:
        name = event.get("name")
        if event.get("event_kind") == "model_call" and isinstance(name, str) and name:
            by_attempt.setdefault(str(event.get("attempt_id")), name)
    for attempt in attempts:
        model = by_attempt.get(str(attempt["attempt_id"]))
        if model:
            attempt["model"] = model
            attempt["unknowns"] = [item for item in attempt["unknowns"] if item != "model"]
