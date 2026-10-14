"""Timeline: a deterministic partial-order view of the recorded evidence.

Three rules make this different from "sort the log by timestamp":

* **Causation comes from the recorded parent graph, not from wall clocks.** The
  display is a topological order of the known edges with stable tie-breaks
  (attempt sequence, source sequence, wall time, event id).
* **Concurrency stays ambiguous.** Two events with no causal path between them are
  reported as an ambiguous pair. Sibling retries or a fork/join are not a
  sequential story, and pretending otherwise invents causation.
* **Missing parents stay visible.** An event whose parent is absent from the trace
  is a root with a recorded gap — never an inferred edge.

A cyclic parent graph is refused, or (on request) quarantined so the offending
portion is visible without being ordered.
"""

from __future__ import annotations

import heapq
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from itertools import pairwise
from typing import Any

from .event_v1 import Event, Gap, ValidationResult
from .redact import safe_text

__all__ = [
    "AMBIGUITY_LIMIT",
    "DEFAULT_STALL_THRESHOLD_S",
    "Timeline",
    "TimelineContradiction",
    "TimelineEntry",
    "build_timeline",
]

#: Wall-clock delta above which a gap is *reported* (as a hypothesis unless clock
#: evidence supports it).
DEFAULT_STALL_THRESHOLD_S = 60.0
#: Above this many events, ambiguity detection falls back to sibling groups only.
AMBIGUITY_LIMIT = 2000


class TimelineContradiction(ValueError):
    """The parent graph cannot be ordered (a cycle). Never silently flattened."""


@dataclass(frozen=True)
class TimelineEntry:
    event_id: str
    depth: int
    order: int
    event: Event
    ambiguous_with: tuple[str, ...] = ()

    @property
    def kind(self) -> str:
        return self.event.event_kind

    @property
    def status(self) -> str:
        return self.event.reported_status

    @property
    def causal_parents(self) -> tuple[str, ...]:
        return self.event.causal_parents

    def as_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "event_ref": self.event_id,
            "attempt_ref": self.event.attempt_id,
            "kind": self.kind,
            "name": self.event.name,
            "status": self.status,
            "at": self.event.wall_time,
            "monotonic_ms": self.event.monotonic_ms,
            "clock_quality": self.event.clock.quality,
            "provenance": self.event.semantic_provenance,
            "depth": self.depth,
            "causal_parents": list(self.causal_parents),
            "ambiguous_with": list(self.ambiguous_with),
        }


@dataclass
class Timeline:
    run_id: str
    entries: list[TimelineEntry] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    ambiguous_pairs: list[tuple[str, str]] = field(default_factory=list)
    quarantined: list[Event] = field(default_factory=list)
    suspect_windows: list[dict[str, Any]] = field(default_factory=list)
    clock_notes: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: Attempt records (as dicts) so callers can reason about reported outcomes
    #: without re-reading the store.
    attempts: list[dict[str, Any]] = field(default_factory=list)

    def entry(self, event_id: str) -> TimelineEntry | None:
        for item in self.entries:
            if item.event_id == event_id:
                return item
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "entries": [entry.as_dict() for entry in self.entries],
            "gaps": [gap.as_dict() for gap in self.gaps],
            "ambiguous_pairs": [list(pair) for pair in self.ambiguous_pairs],
            "quarantined": [event.event_id for event in self.quarantined],
            "suspect_windows": self.suspect_windows,
            "clock_notes": self.clock_notes,
            "notes": self.notes,
            "attempts": self.attempts,
        }

    def text(self) -> str:
        lines: list[str] = [
            f"timeline for run {safe_text(self.run_id)}",
            "ordering: recorded causal parents first, then attempt/source sequence; "
            "wall-clock order is not causation.",
        ]
        for note in self.notes:
            lines.append(f"note: {safe_text(note)}")
        for entry in self.entries:
            label = f" {entry.event.name}" if entry.event.name else ""
            usage = entry.event.usage
            token_note = ""
            if usage.total_tokens() is not None:
                token_note = f" tokens={usage.total_tokens()} (reported)"
            ambiguity = f" ambiguous-with={','.join(entry.ambiguous_with)}" if entry.ambiguous_with else ""
            lines.append(
                f"{entry.order:04d} depth={entry.depth} {entry.kind}{label} "
                f"status={entry.status} at={entry.event.wall_time or 'unknown'} "
                f"clock={entry.event.clock.quality} [{entry.event.semantic_provenance}]"
                f"{token_note}{ambiguity}"
            )
        if not self.entries:
            lines.append("(no events)")
        for pair in self.ambiguous_pairs:
            lines.append(
                f"ambiguous order: {safe_text(pair[0])} <-> {safe_text(pair[1])} "
                "(no causal path between them, so their order is unknown)"
            )
        for window in self.suspect_windows:
            lines.append(
                f"suspect window: {window['after']} -> {window['before']} "
                f"wall_delta={window['wall_delta_s']}s status={window['status']} ({window['why']})"
            )
        for note in self.clock_notes:
            lines.append(f"clock: {safe_text(note)}")
        for gap in self.gaps:
            where = f" (event {gap.event_id})" if gap.event_id else ""
            lines.append(f"gap: {gap.kind.replace('_', ' ')} — {safe_text(gap.detail)}{where}")
        for event in self.quarantined:
            lines.append(
                f"quarantined (contradictory parent graph, not ordered): {safe_text(event.event_id)}"
            )
        return "\n".join(lines) + "\n"


def _parse_wall(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _order_key(event: Event, attempt_sequence: Mapping[str, int]) -> tuple[Any, ...]:
    """Deterministic tie-break: attempt sequence, source sequence, wall time, event id."""
    return (
        int(attempt_sequence.get(event.attempt_id, 0)),
        int(event.source_sequence),
        event.wall_time or "",
        event.event_id,
    )


def _detect_cycle(nodes: Sequence[str], edges: Sequence[tuple[str, str]]) -> list[str]:
    adjacency: dict[str, list[str]] = {}
    for parent, child in edges:
        adjacency.setdefault(parent, []).append(child)
    colour: dict[str, int] = dict.fromkeys(nodes, 0)
    for start in nodes:
        if colour.get(start, 0) != 0:
            continue
        stack: list[tuple[str, int]] = [(start, 0)]
        path: list[str] = []
        while stack:
            node, index = stack.pop()
            if index == 0:
                colour[node] = 1
                path.append(node)
            neighbours = adjacency.get(node, [])
            if index < len(neighbours):
                stack.append((node, index + 1))
                nxt = neighbours[index]
                state = colour.get(nxt, 0)
                if state == 1:
                    position = path.index(nxt) if nxt in path else 0
                    return [*path[position:], nxt]
                if state == 0:
                    stack.append((nxt, 0))
            else:
                colour[node] = 2
                if path and path[-1] == node:
                    path.pop()
    return []


def _reachable(nodes: Sequence[str], edges: Sequence[tuple[str, str]]) -> dict[str, set[str]]:
    adjacency: dict[str, list[str]] = {}
    for parent, child in edges:
        adjacency.setdefault(parent, []).append(child)
    memo: dict[str, set[str]] = {}

    def walk(node: str, seen: set[str]) -> set[str]:
        if node in memo:
            return memo[node]
        result: set[str] = set()
        for child in adjacency.get(node, []):
            if child in seen:
                continue
            result.add(child)
            result |= walk(child, seen | {child})
        memo[node] = result
        return result

    return {node: walk(node, {node}) for node in nodes}


def build_timeline(
    result: ValidationResult,
    *,
    quarantine: bool = False,
    stall_threshold_s: float = DEFAULT_STALL_THRESHOLD_S,
) -> Timeline:
    """Build the deterministic partial-order timeline for a validated result."""
    attempt_sequence = {attempt.attempt_id: attempt.sequence for attempt in result.attempts}
    events = list(result.events)
    by_id = {event.event_id: event for event in events}
    edges = [(parent, child) for parent, child in result.parent_edges if parent in by_id and child in by_id]

    timeline = Timeline(run_id=result.trace.run_id if result.trace else "")
    timeline.gaps = list(result.gaps)
    timeline.attempts = [attempt.as_dict() for attempt in result.attempts]
    timeline.notes.append(
        "an absent causal parent is shown as a gap; no edge is inferred for it"
    )

    cycle = _detect_cycle([event.event_id for event in events], edges)
    if cycle:
        offending = [by_id[node] for node in dict.fromkeys(cycle) if node in by_id]
        if not quarantine:
            raise TimelineContradiction(
                "cyclic causal parent graph: " + " -> ".join(cycle)
                + " (refused; pass quarantine=True to display the rest and isolate the cycle)"
            )
        quarantined_ids = {event.event_id for event in offending}
        edges = [(parent, child) for parent, child in edges
                 if parent not in quarantined_ids and child not in quarantined_ids]
        timeline.quarantined = offending
        remaining = [event for event in events if event.event_id not in quarantined_ids]
    else:
        remaining = events

    # Kahn's algorithm with a deterministic priority key.
    indegree: dict[str, int] = {event.event_id: 0 for event in remaining}
    adjacency: dict[str, list[str]] = {}
    for parent, child in edges:
        if parent in indegree and child in indegree:
            adjacency.setdefault(parent, []).append(child)
            indegree[child] += 1
    heap: list[tuple[tuple[Any, ...], str]] = []
    for event in remaining:
        if indegree[event.event_id] == 0:
            heapq.heappush(heap, (_order_key(event, attempt_sequence), event.event_id))
    depth: dict[str, int] = {event.event_id: 0 for event in remaining}
    ordered: list[str] = []
    while heap:
        _key, event_id = heapq.heappop(heap)
        ordered.append(event_id)
        for child in sorted(adjacency.get(event_id, []), key=lambda cid: _order_key(by_id[cid], attempt_sequence)):
            depth[child] = max(depth[child], depth[event_id] + 1)
            indegree[child] -= 1
            if indegree[child] == 0:
                heapq.heappush(heap, (_order_key(by_id[child], attempt_sequence), child))
    if len(ordered) != len(remaining):  # pragma: no cover - defended by cycle handling above
        raise TimelineContradiction("parent graph could not be ordered completely")

    ambiguous: dict[str, set[str]] = {event_id: set() for event_id in ordered}
    if len(ordered) <= AMBIGUITY_LIMIT:
        reached = _reachable(ordered, edges)
        for index, first in enumerate(ordered):
            for second in ordered[index + 1:]:
                if second in reached.get(first, ()) or first in reached.get(second, ()):
                    continue
                ambiguous[first].add(second)
                ambiguous[second].add(first)
                timeline.ambiguous_pairs.append((first, second))
    else:
        siblings: dict[str, list[str]] = {}
        for parent, child in edges:
            siblings.setdefault(parent, []).append(child)
        for group in siblings.values():
            for index, first in enumerate(group):
                for second in group[index + 1:]:
                    ambiguous[first].add(second)
                    ambiguous[second].add(first)
                    timeline.ambiguous_pairs.append((first, second))
        timeline.notes.append(
            f"ambiguity analysis limited to sibling groups above {AMBIGUITY_LIMIT} events"
        )

    timeline.entries = [
        TimelineEntry(
            event_id=event_id,
            depth=depth[event_id],
            order=index,
            event=by_id[event_id],
            ambiguous_with=tuple(sorted(ambiguous.get(event_id, ()))),
        )
        for index, event_id in enumerate(ordered)
    ]

    _annotate_clocks(timeline, timeline.entries, stall_threshold_s)
    timeline.notes.append(
        "concurrent events are reported as ambiguous pairs: wall-clock order alone is not causation"
    )
    return timeline


def _annotate_clocks(
    timeline: Timeline, entries: Sequence[TimelineEntry], stall_threshold_s: float
) -> None:
    by_attempt: dict[str, list[TimelineEntry]] = {}
    for entry in entries:
        by_attempt.setdefault(entry.event.attempt_id, []).append(entry)

    for attempt_entries in by_attempt.values():
        for previous, current in pairwise(attempt_entries):
            previous_time = _parse_wall(previous.event.wall_time)
            current_time = _parse_wall(current.event.wall_time)
            if previous_time is None or current_time is None:
                continue
            delta = (current_time - previous_time).total_seconds()
            if delta < stall_threshold_s:
                continue
            has_monotonic = (
                previous.event.monotonic_ms is not None and current.event.monotonic_ms is not None
            )
            quality = {previous.event.clock.quality, current.event.clock.quality}
            if has_monotonic and not ({"unknown", "low"} & quality):
                timeline.suspect_windows.append({
                    "after": previous.event_id,
                    "before": current.event_id,
                    "wall_delta_s": delta,
                    "monotonic_delta_ms": (
                        current.event.monotonic_ms - previous.event.monotonic_ms  # type: ignore[operator]
                    ),
                    "status": "observed",
                    "why": "monotonic evidence agrees with the wall-clock gap",
                })
            else:
                timeline.suspect_windows.append({
                    "after": previous.event_id,
                    "before": current.event_id,
                    "wall_delta_s": delta,
                    "monotonic_delta_ms": None,
                    "status": "hypothesis",
                    "why": (
                        "no monotonic clock evidence: a wall-clock gap can come from suspend, "
                        "clock drift or a slow step, so a stall here is a hypothesis only"
                    ),
                })

    clock_note_added = False
    for attempt_entries in by_attempt.values():
        for previous, current in pairwise(attempt_entries):
            previous_time = _parse_wall(previous.event.wall_time)
            current_time = _parse_wall(current.event.wall_time)
            if previous_time is None or current_time is None:
                continue
            if current_time < previous_time:
                timeline.clock_notes.append(
                    f"wall-clock order disagrees with source order for "
                    f"{previous.event_id} -> {current.event_id}; source order is displayed and the "
                    "timestamps are treated as low quality"
                )
                clock_note_added = True
    if not clock_note_added:
        low_quality = [entry.event_id for entry in entries
                       if entry.event.clock.quality in {"low", "unknown"}]
        if low_quality:
            timeline.clock_notes.append(
                f"{len(low_quality)} event(s) carry low/unknown clock quality; timing claims are "
                "limited to what the source recorded"
            )


def iter_entry_ids(timeline: Timeline) -> Iterable[str]:
    return (entry.event_id for entry in timeline.entries)
