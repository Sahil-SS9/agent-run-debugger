"""Inert replay: re-read the recorded timeline, execute nothing.

This module imports no execution primitive — no ``subprocess``, no ``socket``, no
network client, no database driver. It is a pure function over already-loaded
evidence, which is what makes "replay" safe to offer to someone debugging a
failure they do not fully understand yet.

Imported command and error text is *displayed as data*. It is never executed, and
it is never accepted as an instruction.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .event_v1 import Event
from .redact import safe_text
from .timeline import Timeline

__all__ = ["REPLAY_SCHEMA_ID", "ReplayLog", "ReplayStep", "replay_events", "replay_text"]

REPLAY_SCHEMA_ID = "hermes-run-debugger/replay"

_NOTES = (
    "replay is inert: it re-reads the recorded timeline and executes nothing "
    "(no subprocess, no network, no live database, no writes)",
    "imported command/error text is displayed as data and is not executed",
    "ordering follows the recorded causal parents, not wall-clock order",
)


@dataclass(frozen=True)
class ReplayStep:
    index: int
    kind: str
    status: str
    provenance: str
    at: str | None
    name: str | None
    parent_ref: str | None
    text: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "kind": self.kind,
            "status": self.status,
            "provenance": self.provenance,
            "at": self.at,
            "name": self.name,
            "parent_ref": self.parent_ref,
            "text": self.text,
        }


@dataclass
class ReplayLog:
    run_id: str
    steps: list[ReplayStep] = field(default_factory=list)
    gaps: list[dict[str, Any]] = field(default_factory=list)
    ambiguous_pairs: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    schema: str = REPLAY_SCHEMA_ID

    def text(self) -> str:
        lines = [f"inert replay of run {safe_text(self.run_id)} (nothing is executed)"]
        for note in self.notes:
            lines.append(f"note: {safe_text(note)}")
        if not self.steps:
            lines.append("(no events to replay)")
        for step in self.steps:
            parent = f" parent={step.parent_ref}" if step.parent_ref else ""
            name = f" {step.name}" if step.name else ""
            lines.append(
                f"{step.index:04d} {step.kind}{name} status={step.status} "
                f"at={step.at or 'unknown'} [{step.provenance}]{parent} :: {safe_text(step.text)}"
            )
        for pair in self.ambiguous_pairs:
            lines.append(f"ambiguous order: {pair[0]} <-> {pair[1]} (recorded as concurrent)")
        for gap in self.gaps:
            lines.append(
                f"gap: {str(gap.get('kind', '')).replace('_', ' ')} — {safe_text(gap.get('detail', ''))}"
            )
        return "\n".join(lines) + "\n"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "run_id": self.run_id,
            "steps": [step.as_dict() for step in self.steps],
            "gaps": self.gaps,
            "ambiguous_pairs": [list(pair) for pair in self.ambiguous_pairs],
            "notes": list(self.notes),
        }


def replay_events(
    events: Iterable[Event],
    *,
    run_id: str,
    gaps: Sequence[Mapping[str, Any]] | None = None,
    ambiguous_pairs: Sequence[tuple[str, str]] | None = None,
) -> ReplayLog:
    """Walk recorded events in their stored order. Pure; no side effects."""
    log = ReplayLog(run_id=run_id, notes=list(_NOTES))
    for index, event in enumerate(events):
        text = event.reported_error or ""
        parent = event.causal_parents[0] if event.causal_parents else None
        log.steps.append(
            ReplayStep(
                index=index,
                kind=event.event_kind,
                status=event.reported_status,
                provenance=event.semantic_provenance,
                at=event.wall_time,
                name=event.name,
                parent_ref=parent,
                # Text is data. It is escaped for display and never interpreted.
                text=text,
            )
        )
    log.gaps = [dict(gap) for gap in (gaps or [])]
    log.ambiguous_pairs = list(ambiguous_pairs or [])
    return log


def replay_text(events: Iterable[Event] | Timeline, **kwargs: Any) -> str:
    """Convenience: replay either a Timeline or an event iterable and return text."""
    if isinstance(events, Timeline):
        log = replay_events(
            (entry.event for entry in events.entries),
            run_id=events.run_id,
            gaps=[gap.as_dict() for gap in events.gaps],
            ambiguous_pairs=events.ambiguous_pairs,
        )
        return log.text()
    return replay_events(events, **kwargs).text()
