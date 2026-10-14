"""Trace v1 — the normalisation contract.

Design rules encoded here (each one exists because the obvious alternative
launders bad evidence into good-looking output):

* Strict versions. An unknown schema id or version is refused; it is never
  "best-effort" parsed into the v1 shape.
* Unknown fields are refused by default (``unknown_field_policy="reject"``).
  A field the importer does not understand may be the very fact that explains
  the failure, so silently dropping it would be a lie of omission.
* Outcome is separate from correctness. ``outcome="completed"`` means the run
  finished, never that the task passed; nothing in this module mints a
  correctness claim.
* Provenance is two-dimensional and per-record: OBSERVED / REPORTED / INFERRED /
  UNKNOWN. Imported logs are REPORTED. Correlated external checks may add
  OBSERVED. Diagnosis is INFERRED. Missing values stay UNKNOWN.
* A parent id that is not present in the trace is a visible GAP, never an
  inferred edge. Cyclic parent graphs are refused outright.
* Cost: unknown/partially-reported billing is ``None`` (UNKNOWN), never 0.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .identity import is_valid_id

__all__ = [
    "SCHEMA_ID",
    "SCHEMA_VERSION",
    "EVENT_KINDS",
    "OUTCOMES",
    "PROVENANCE",
    "REPORTED_STATUS",
    "DELIVERY",
    "TraceValidationError",
    "ValidationResult",
    "TraceEnvelope",
    "Attempt",
    "Event",
    "Usage",
    "Clock",
    "Gap",
    "validate_trace_records",
]

SCHEMA_ID = "hermes-run-debugger/trace"
SCHEMA_VERSION = 1

EVENT_KINDS = frozenset({
    "model_call",
    "tool_call",
    "subagent_handoff",
    "retry",
    "approval_request",
    "approval_response",
    "interrupt",
    "session_lifecycle",
    "provider_error",
    "note",
})
OUTCOMES = frozenset({"completed", "failed", "interrupted", "unknown"})
PROVENANCE = frozenset({"observed", "reported", "inferred", "unknown"})
REPORTED_STATUS = frozenset({"ok", "failed", "interrupted", "skipped", "unknown"})
DELIVERY = frozenset({"import", "hook", "live_read", "export", "unknown"})
CLOCK_SOURCES = frozenset({"wall", "monotonic", "mixed", "unknown"})
CLOCK_QUALITY = frozenset({"high", "medium", "low", "unknown"})
COMPLETENESS_STATUS = frozenset({"complete", "partial", "unknown"})
SOURCE_KINDS = frozenset({"file", "export", "hook", "session", "unknown"})
COST_KINDS = frozenset({"actual", "estimated", "unknown"})
GAP_KINDS = frozenset({
    "missing_parent",
    "partial_source",
    "unsupported_kind",
    "truncation",
    "unknown_capture_window",
    "redaction_failure",
})

_WALL_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$")

_TRACE_FIELDS = frozenset({
    "kind", "schema", "version", "trace_id", "run_id", "importer", "importer_version",
    "source_format", "source_scope", "created_at", "source", "redaction", "covered_kinds",
    "unsupported_kinds", "completeness", "private_digests",
})
_SOURCE_FIELDS = frozenset({"kind", "ref", "name"})
_REDACTION_FIELDS = frozenset({"policy", "applied_count", "categories", "limitations"})
_COMPLETENESS_FIELDS = frozenset({
    "status", "missing_kinds", "notes", "source_limits", "truncation", "capture_windows",
})
_ATTEMPT_FIELDS = frozenset({
    "kind", "attempt_id", "run_id", "parent_attempt_id", "model", "provider", "role",
    "branch", "sequence", "started_at", "ended_at", "outcome", "unknowns",
})
_EVENT_FIELDS = frozenset({
    "kind", "event_id", "run_id", "attempt_id", "span_id", "causal_parents", "source_sequence",
    "wall_time", "monotonic_ms", "clock", "event_kind", "reported_status", "reported_error",
    "usage", "evidence_ref", "delivered_via", "semantic_provenance", "gaps", "contradictions",
    # ``name`` is the *reported* subject of the event (tool name, model name) and is
    # bounded/control-character free. ``arguments_ref`` is an opaque reference to
    # tool arguments: the arguments themselves are never persisted by default, so
    # this is a ref, not a payload.
    "name", "arguments_ref",
})
_CLOCK_FIELDS = frozenset({"source", "quality", "drift_ms"})
_USAGE_FIELDS = frozenset({
    "input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens",
    "cost", "cost_kind", "price_source", "price_version",
})


class TraceValidationError(ValueError):
    """The input is not a valid Trace v1 document. Always a refusal, never a repair."""


@dataclass(frozen=True)
class Clock:
    source: str = "unknown"
    quality: str = "unknown"
    drift_ms: int | None = None


@dataclass(frozen=True)
class Usage:
    """Reported usage. Unknown stays ``None`` — never coerced to 0.

    ``cost_kind`` distinguishes ACTUAL reported spend from an ESTIMATE that a
    user-configured price table produced, and from UNKNOWN billing. Imported
    token counts are format-specific facts: deduplicating them is the adapter's
    recorded behaviour, not a universal arithmetic rule.
    """

    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_read_tokens: int | None = None
    cache_write_tokens: int | None = None
    cost: float | None = None
    cost_kind: str = "unknown"
    price_source: str | None = None
    price_version: str | None = None

    def as_reported(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
            "cost": self.cost,
            "cost_kind": self.cost_kind if self.cost is not None else "unknown",
            "price_source": self.price_source,
            "price_version": self.price_version,
        }

    def total_tokens(self) -> int | None:
        """Sum of *reported* token fields, or ``None`` when every field is unknown."""
        values = [v for v in (self.input_tokens, self.output_tokens) if v is not None]
        if not values:
            return None
        return sum(values)


@dataclass(frozen=True)
class Event:
    event_id: str
    run_id: str
    attempt_id: str
    event_kind: str
    semantic_provenance: str
    source_sequence: int
    span_id: str | None = None
    causal_parents: tuple[str, ...] = ()
    wall_time: str | None = None
    monotonic_ms: int | None = None
    clock: Clock = field(default_factory=Clock)
    reported_status: str = "unknown"
    reported_error: str | None = None
    usage: Usage = field(default_factory=Usage)
    evidence_ref: str | None = None
    delivered_via: str = "import"
    gaps: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    #: Reported subject (tool/model name), bounded and control-free. Optional.
    name: str | None = None
    #: Opaque reference to tool arguments. Never the arguments themselves.
    arguments_ref: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "run_id": self.run_id,
            "attempt_id": self.attempt_id,
            "span_id": self.span_id,
            "causal_parents": list(self.causal_parents),
            "source_sequence": self.source_sequence,
            "wall_time": self.wall_time,
            "monotonic_ms": self.monotonic_ms,
            "clock": {"source": self.clock.source, "quality": self.clock.quality},
            "event_kind": self.event_kind,
            "reported_status": self.reported_status,
            "reported_error": self.reported_error,
            "usage": self.usage.as_reported(),
            "evidence_ref": self.evidence_ref,
            "delivered_via": self.delivered_via,
            "semantic_provenance": self.semantic_provenance,
            "gaps": list(self.gaps),
            "contradictions": list(self.contradictions),
            "name": self.name,
            "arguments_ref": self.arguments_ref,
        }


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    run_id: str
    outcome: str
    parent_attempt_id: str | None = None
    model: str | None = None
    provider: str | None = None
    role: str | None = None
    branch: str | None = None
    sequence: int = 0
    started_at: str | None = None
    ended_at: str | None = None
    unknowns: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "run_id": self.run_id,
            "parent_attempt_id": self.parent_attempt_id,
            "model": self.model,
            "provider": self.provider,
            "role": self.role,
            "branch": self.branch,
            "sequence": self.sequence,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "outcome": self.outcome,
            "unknowns": list(self.unknowns),
        }


@dataclass(frozen=True)
class TraceEnvelope:
    trace_id: str
    run_id: str
    importer: str
    importer_version: str
    source_format: str
    source_scope: str
    created_at: str
    source: Mapping[str, Any]
    redaction: Mapping[str, Any]
    covered_kinds: tuple[str, ...]
    unsupported_kinds: tuple[str, ...]
    completeness: Mapping[str, Any]
    private_digests: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self, *, include_private: bool = False) -> dict[str, Any]:
        out = {
            "schema": SCHEMA_ID,
            "version": SCHEMA_VERSION,
            "trace_id": self.trace_id,
            "run_id": self.run_id,
            "importer": self.importer,
            "importer_version": self.importer_version,
            "source_format": self.source_format,
            "source_scope": self.source_scope,
            "created_at": self.created_at,
            "source": dict(self.source),
            "redaction": dict(self.redaction),
            "covered_kinds": list(self.covered_kinds),
            "unsupported_kinds": list(self.unsupported_kinds),
            "completeness": dict(self.completeness),
        }
        if include_private:
            out["private_digests"] = dict(self.private_digests)
        return out


@dataclass(frozen=True)
class Gap:
    kind: str
    detail: str
    event_id: str | None = None
    parent_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "detail": self.detail, "event_id": self.event_id,
                "parent_id": self.parent_id}


@dataclass
class ValidationResult:
    trace: TraceEnvelope | None = None
    attempts: list[Attempt] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    # Only *known* parent→child edges. A missing parent never appears here.
    parent_edges: list[tuple[str, str]] = field(default_factory=list)
    # Correctness claims (e.g. "task passed"). v1 mints none: a run's outcome is
    # not a verdict on the work, and an imported log cannot pass a test.
    correctness_claims: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.refused

    def events_by_id(self) -> dict[str, Event]:
        return {e.event_id: e for e in self.events}

    def children_of(self, event_id: str) -> list[str]:
        return [child for parent, child in self.parent_edges if parent == event_id]


def _refuse(issues: list[str], message: str) -> None:
    issues.append(message)


def _check_nonfinite(value: Any, path: str, issues: list[str]) -> None:
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            _refuse(issues, f"{path}: non-finite number {value!r} is refused")
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _check_nonfinite(item, f"{path}.{key}", issues)
    elif isinstance(value, (list, tuple)):
        for idx, item in enumerate(value):
            _check_nonfinite(item, f"{path}[{idx}]", issues)


def _check_fields(
    record: Mapping[str, Any],
    allowed: frozenset[str],
    where: str,
    issues: list[str],
    warnings: list[str],
    policy: str,
) -> None:
    unknown = sorted(set(record) - allowed)
    if not unknown:
        return
    message = f"{where}: unknown field(s) {', '.join(unknown)}"
    if policy == "reject":
        _refuse(issues, message + " — refused, not silently dropped")
    else:
        warnings.append(message + " — ignored by policy")


def _require_str(
    record: Mapping[str, Any], key: str, where: str, issues: list[str], *, optional: bool = False
) -> str | None:
    value = record.get(key)
    if value is None:
        if not optional:
            _refuse(issues, f"{where}: missing required field {key!r}")
        return None
    if not isinstance(value, str) or len(value) > 512:
        _refuse(issues, f"{where}.{key}: must be a bounded string")
        return None
    return value


def _require_id(
    record: Mapping[str, Any], key: str, where: str, issues: list[str], *, optional: bool = False
) -> str | None:
    value = record.get(key)
    if value is None:
        if not optional:
            _refuse(issues, f"{where}: missing required id field {key!r}")
        return None
    if not is_valid_id(value):
        _refuse(issues, f"{where}.{key}: {value!r} is not a valid id")
        return None
    return value


def _require_int(
    record: Mapping[str, Any], key: str, where: str, issues: list[str], *, optional: bool = False
) -> int | None:
    value = record.get(key)
    if value is None:
        if not optional:
            _refuse(issues, f"{where}: missing required integer field {key!r}")
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        _refuse(issues, f"{where}.{key}: must be an integer, got {type(value).__name__}")
        return None
    return value


def _check_str_list(
    record: Mapping[str, Any], key: str, where: str, issues: list[str], *, ids: bool = False
) -> list[str]:
    value = record.get(key, [])
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        _refuse(issues, f"{where}.{key}: must be a list of strings")
        return []
    out: list[str] = []
    for idx, item in enumerate(value):
        if not isinstance(item, str):
            _refuse(issues, f"{where}.{key}[{idx}]: must be a string")
            continue
        if ids and not is_valid_id(item):
            _refuse(issues, f"{where}.{key}[{idx}]: {item!r} is not a valid id")
            continue
        out.append(item)
    return out


def _check_wall_time(value: Any, where: str, issues: list[str]) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _WALL_RE.match(value):
        _refuse(issues, f"{where}: wall_time must be ISO-8601 with an offset, got {value!r}")
        return None
    return value


def _parse_clock(raw: Any, where: str, issues: list[str], policy: str, warnings: list[str]) -> Clock:
    if raw is None:
        return Clock()
    if not isinstance(raw, Mapping):
        _refuse(issues, f"{where}.clock: must be an object")
        return Clock()
    _check_fields(raw, _CLOCK_FIELDS, f"{where}.clock", issues, warnings, policy)
    source = str(raw.get("source", "unknown")).lower()
    quality = str(raw.get("quality", "unknown")).lower()
    if source not in CLOCK_SOURCES:
        _refuse(issues, f"{where}.clock.source: unknown clock source {source!r}")
        source = "unknown"
    if quality not in CLOCK_QUALITY:
        _refuse(issues, f"{where}.clock.quality: unknown clock quality {quality!r}")
        quality = "unknown"
    drift = raw.get("drift_ms")
    if drift is not None and (isinstance(drift, bool) or not isinstance(drift, int)):
        _refuse(issues, f"{where}.clock.drift_ms: must be an integer or null")
        drift = None
    return Clock(source=source, quality=quality, drift_ms=drift)


def _parse_usage(raw: Any, where: str, issues: list[str], policy: str, warnings: list[str]) -> Usage:
    if raw is None:
        return Usage()
    if not isinstance(raw, Mapping):
        _refuse(issues, f"{where}.usage: must be an object")
        return Usage()
    _check_fields(raw, _USAGE_FIELDS, f"{where}.usage", issues, warnings, policy)

    def _token(key: str) -> int | None:
        value = raw.get(key)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            _refuse(issues, f"{where}.usage.{key}: must be a non-negative integer or null")
            return None
        return value

    cost = raw.get("cost")
    if cost is not None and (isinstance(cost, bool) or not isinstance(cost, (int, float))):
        _refuse(issues, f"{where}.usage.cost: must be a number or null")
        cost = None
    cost_kind = str(raw.get("cost_kind", "unknown")).lower()
    if cost_kind not in COST_KINDS:
        _refuse(issues, f"{where}.usage.cost_kind: unknown cost kind {cost_kind!r}")
        cost_kind = "unknown"
    if cost is None:
        cost_kind = "unknown"
    elif cost_kind == "unknown":
        _refuse(issues, f"{where}.usage: a reported cost must declare cost_kind actual|estimated")
    price_source = raw.get("price_source")
    price_version = raw.get("price_version")
    if cost_kind == "estimated" and not price_source:
        _refuse(issues, f"{where}.usage: an estimated cost must name its price_source")
    return Usage(
        input_tokens=_token("input_tokens"),
        output_tokens=_token("output_tokens"),
        cache_read_tokens=_token("cache_read_tokens"),
        cache_write_tokens=_token("cache_write_tokens"),
        cost=float(cost) if cost is not None else None,
        cost_kind=cost_kind,
        price_source=str(price_source) if isinstance(price_source, str) else None,
        price_version=str(price_version) if isinstance(price_version, str) else None,
    )


def _detect_cycle(edges: Sequence[tuple[str, str]]) -> list[str] | None:
    """Return the offending cycle as a node list, or ``None`` when the graph is acyclic."""
    adjacency: dict[str, list[str]] = {}
    for parent, child in edges:
        adjacency.setdefault(parent, []).append(child)
    WHITE, GREY, BLACK = 0, 1, 2
    colour: dict[str, int] = {}
    for node in adjacency:
        colour.setdefault(node, WHITE)
    for start in list(adjacency):
        if colour.get(start) != WHITE:
            continue
        stack: list[tuple[str, int]] = [(start, 0)]
        path: list[str] = []
        while stack:
            node, index = stack.pop()
            if index == 0:
                colour[node] = GREY
                path.append(node)
            neighbours = adjacency.get(node, [])
            if index < len(neighbours):
                stack.append((node, index + 1))
                nxt = neighbours[index]
                state = colour.get(nxt, WHITE)
                if state == GREY:
                    return path[path.index(nxt):] + [nxt] if nxt in path else [nxt, nxt]
                if state == WHITE:
                    stack.append((nxt, 0))
            else:
                colour[node] = BLACK
                if path and path[-1] == node:
                    path.pop()
    return None


def validate_trace_records(
    records: Iterable[Mapping[str, Any]],
    *,
    max_records: int = 200_000,
    unknown_field_policy: str = "reject",
    refuse: str = "raise",
) -> ValidationResult:
    """Validate raw Trace v1 records into typed objects.

    ``refuse="raise"`` (default) throws :class:`TraceValidationError` on any
    refusal. ``refuse="collect"`` returns the partial result with ``.refused``
    populated, for callers that must report a refusal instead of crashing.
    """
    if unknown_field_policy not in {"reject", "ignore"}:
        raise ValueError("unknown_field_policy must be 'reject' or 'ignore'")
    if refuse not in {"raise", "collect"}:
        raise ValueError("refuse must be 'raise' or 'collect'")

    issues: list[str] = []
    result = ValidationResult()
    warnings = result.warnings  # same list object: what callers append to is what they read
    items = list(records)
    if len(items) > max_records:
        issues.append(f"trace has {len(items)} records, exceeding max_records {max_records}")
    if not items:
        issues.append("trace is empty: no records to import")
        return _finish(result, issues, refuse)

    head = items[0]
    if not isinstance(head, Mapping) or head.get("kind") != "trace":
        issues.append("first record must be the 'trace' envelope record")
        return _finish(result, issues, refuse)

    _check_nonfinite(head, "trace", issues)
    _check_fields(head, _TRACE_FIELDS, "trace", issues, warnings, unknown_field_policy)

    schema = head.get("schema")
    if schema != SCHEMA_ID:
        issues.append(f"trace.schema: {schema!r} is not {SCHEMA_ID!r}")
    version = head.get("version")
    if version != SCHEMA_VERSION:
        issues.append(
            f"trace.version: unsupported version {version!r} (this build supports {SCHEMA_VERSION})"
        )

    source_raw = head.get("source")
    if not isinstance(source_raw, Mapping):
        issues.append("trace.source: must be an object")
        source_raw = {}
    else:
        _check_fields(source_raw, _SOURCE_FIELDS, "trace.source", issues, warnings, unknown_field_policy)
        if source_raw.get("kind") not in SOURCE_KINDS:
            issues.append(f"trace.source.kind: unknown source kind {source_raw.get('kind')!r}")
        ref = source_raw.get("ref")
        if not isinstance(ref, str) or not ref:
            issues.append("trace.source.ref: required string (private content digest)")

    redaction_raw = head.get("redaction")
    if not isinstance(redaction_raw, Mapping):
        issues.append("trace.redaction: must be an object")
        redaction_raw = {}
    else:
        _check_fields(
            redaction_raw, _REDACTION_FIELDS, "trace.redaction", issues, warnings, unknown_field_policy
        )

    completeness_raw = head.get("completeness")
    if not isinstance(completeness_raw, Mapping):
        issues.append("trace.completeness: must be an object")
        completeness_raw = {}
    else:
        _check_fields(
            completeness_raw,
            _COMPLETENESS_FIELDS,
            "trace.completeness",
            issues,
            warnings,
            unknown_field_policy,
        )
        status = completeness_raw.get("status")
        if status not in COMPLETENESS_STATUS:
            issues.append(f"trace.completeness.status: unknown status {status!r}")

    covered = _check_str_list(head, "covered_kinds", "trace", issues)
    unsupported = _check_str_list(head, "unsupported_kinds", "trace", issues)
    for kind in covered + unsupported:
        if kind not in EVENT_KINDS:
            issues.append(f"trace covered/unsupported kind {kind!r} is not a known event kind")

    _check_wall_time(head.get("created_at"), "trace.created_at", issues)

    envelope = TraceEnvelope(
        trace_id=_require_id(head, "trace_id", "trace", issues) or "",
        run_id=_require_id(head, "run_id", "trace", issues) or "",
        importer=str(head.get("importer") or ""),
        importer_version=str(head.get("importer_version") or ""),
        source_format=str(head.get("source_format") or ""),
        source_scope=str(head.get("source_scope") or ""),
        created_at=str(head.get("created_at") or ""),
        source=dict(source_raw),
        redaction=dict(redaction_raw),
        covered_kinds=tuple(covered),
        unsupported_kinds=tuple(unsupported),
        completeness=dict(completeness_raw),
        private_digests=dict(head.get("private_digests") or {}),
    )
    for kind in unsupported:
        result.gaps.append(
            Gap("unsupported_kind", f"source declared unsupported kind {kind!r} (not parsed)", None)
        )

    attempt_ids: list[str] = []
    for idx, record in enumerate(items[1:], start=2):
        if not isinstance(record, Mapping):
            issues.append(f"record {idx}: must be an object")
            continue
        kind = record.get("kind")
        if kind == "attempt":
            attempt = _parse_attempt(record, idx, issues, warnings, unknown_field_policy)
            if attempt is not None:
                attempt_ids.append(attempt.attempt_id)
                result.attempts.append(attempt)
        elif kind == "event":
            event = _parse_event(record, idx, issues, warnings, unknown_field_policy)
            if event is not None:
                result.events.append(event)
        else:
            issues.append(f"record {idx}: unknown record kind {kind!r}")

    duplicates = _duplicates(attempt_ids)
    for dup in duplicates:
        issues.append(f"duplicate attempt id {dup!r}")
    seen_events: list[str] = []
    for event in result.events:
        if event.run_id != envelope.run_id:
            issues.append(
                f"event {event.event_id}: run_id {event.run_id!r} does not match trace run_id "
                f"{envelope.run_id!r}"
            )
        seen_events.append(event.event_id)
    for dup in _duplicates(seen_events):
        issues.append(f"duplicate event id {dup!r}")

    known_attempts = set(attempt_ids)
    for event in result.events:
        if event.attempt_id not in known_attempts:
            issues.append(
                f"event {event.event_id}: attempt_id {event.attempt_id!r} is not declared by any "
                "attempt record"
            )

    known_events = set(seen_events)
    for event in result.events:
        for parent in event.causal_parents:
            if parent in known_events:
                result.parent_edges.append((parent, event.event_id))
            else:
                result.gaps.append(
                    Gap(
                        "missing_parent",
                        "causal parent is not present in this trace; no edge was inferred",
                        event.event_id,
                        parent,
                    )
                )

    cycle = _detect_cycle(result.parent_edges)
    if cycle:
        issues.append(f"cyclic causal parent graph refused: {' -> '.join(cycle)}")
    self_loops = [e for e in result.events if e.event_id in e.causal_parents]
    for event in self_loops:
        issues.append(f"event {event.event_id}: causal parent references itself")

    result.trace = envelope
    return _finish(result, issues, refuse)


def _finish(result: ValidationResult, issues: list[str], refuse: str) -> ValidationResult:
    result.refused = issues
    if issues and refuse == "raise":
        raise TraceValidationError("; ".join(issues[:8]) + (" …" if len(issues) > 8 else ""))
    return result


def _duplicates(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    dups: list[str] = []
    for value in values:
        if value in seen and value not in dups:
            dups.append(value)
        seen.add(value)
    return dups


def _parse_attempt(
    record: Mapping[str, Any],
    idx: int,
    issues: list[str],
    warnings: list[str],
    policy: str,
) -> Attempt | None:
    where = f"record {idx} (attempt)"
    _check_nonfinite(record, where, issues)
    _check_fields(record, _ATTEMPT_FIELDS, where, issues, warnings, policy)
    attempt_id = _require_id(record, "attempt_id", where, issues)
    run_id = _require_id(record, "run_id", where, issues)
    outcome = record.get("outcome")
    if outcome not in OUTCOMES:
        issues.append(f"{where}.outcome: unknown outcome {outcome!r}")
        outcome = "unknown"
    parent = _require_id(record, "parent_attempt_id", where, issues, optional=True)
    sequence = _require_int(record, "sequence", where, issues, optional=True) or 0
    _check_wall_time(record.get("started_at"), f"{where}.started_at", issues)
    _check_wall_time(record.get("ended_at"), f"{where}.ended_at", issues)
    unknowns = _check_str_list(record, "unknowns", where, issues)
    if attempt_id is None or run_id is None:
        return None
    return Attempt(
        attempt_id=attempt_id,
        run_id=run_id,
        outcome=str(outcome),
        parent_attempt_id=parent,
        model=_opt_str(record.get("model")),
        provider=_opt_str(record.get("provider")),
        role=_opt_str(record.get("role")),
        branch=_opt_str(record.get("branch")),
        sequence=sequence,
        started_at=record.get("started_at") if isinstance(record.get("started_at"), str) else None,
        ended_at=record.get("ended_at") if isinstance(record.get("ended_at"), str) else None,
        unknowns=tuple(unknowns),
    )


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    return value


def _parse_event(
    record: Mapping[str, Any],
    idx: int,
    issues: list[str],
    warnings: list[str],
    policy: str,
) -> Event | None:
    where = f"record {idx} (event)"
    _check_nonfinite(record, where, issues)
    _check_fields(record, _EVENT_FIELDS, where, issues, warnings, policy)

    event_id = _require_id(record, "event_id", where, issues)
    run_id = _require_id(record, "run_id", where, issues)
    attempt_id = _require_id(record, "attempt_id", where, issues)
    kind = record.get("event_kind")
    if kind not in EVENT_KINDS:
        issues.append(f"{where}.event_kind: {kind!r} is not a supported event kind")
    provenance = record.get("semantic_provenance")
    if provenance not in PROVENANCE:
        issues.append(
            f"{where}.semantic_provenance: {provenance!r} is not one of "
            f"{sorted(PROVENANCE)} — missing evidence stays UNKNOWN"
        )
    status = record.get("reported_status", "unknown")
    if status not in REPORTED_STATUS:
        issues.append(f"{where}.reported_status: unknown status {status!r}")
        status = "unknown"
    delivered = record.get("delivered_via", "import")
    if delivered not in DELIVERY:
        issues.append(f"{where}.delivered_via: unknown delivery channel {delivered!r}")
        delivered = "unknown"
    sequence = _require_int(record, "source_sequence", where, issues)
    if sequence is None or sequence < 0:
        if sequence is not None:
            issues.append(f"{where}.source_sequence: must be >= 0")
        sequence = 0
    monotonic = record.get("monotonic_ms")
    if monotonic is not None and (isinstance(monotonic, bool) or not isinstance(monotonic, int)):
        issues.append(f"{where}.monotonic_ms: must be an integer or null")
        monotonic = None
    parents = _check_str_list(record, "causal_parents", where, issues, ids=True)
    gaps = _check_str_list(record, "gaps", where, issues)
    contradictions = _check_str_list(record, "contradictions", where, issues)
    name = _opt_str(record.get("name"))
    if name is not None and (len(name) > 128 or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        issues.append(f"{where}.name: must be a bounded, control-character-free string")
        name = None
    arguments_ref = _opt_str(record.get("arguments_ref"))
    if arguments_ref is not None and not is_valid_id(arguments_ref):
        issues.append(
            f"{where}.arguments_ref: must be an opaque reference token, not a payload"
        )
        arguments_ref = None
    error = record.get("reported_error")
    if error is not None and not isinstance(error, str):
        issues.append(f"{where}.reported_error: must be a string or null")
        error = None
    if error is not None and len(error) > 4096:
        issues.append(f"{where}.reported_error: exceeds 4096 characters")
        error = None

    if event_id is None or run_id is None or attempt_id is None:
        return None
    return Event(
        event_id=event_id,
        run_id=run_id,
        attempt_id=attempt_id,
        event_kind=str(kind) if kind in EVENT_KINDS else "note",
        semantic_provenance=str(provenance) if provenance in PROVENANCE else "unknown",
        source_sequence=sequence,
        span_id=_opt_str(record.get("span_id")),
        causal_parents=tuple(parents),
        wall_time=_check_wall_time(record.get("wall_time"), f"{where}.wall_time", issues),
        monotonic_ms=monotonic,
        clock=_parse_clock(record.get("clock"), where, issues, policy, warnings),
        reported_status=str(status),
        reported_error=str(error) if isinstance(error, str) else None,
        usage=_parse_usage(record.get("usage"), where, issues, policy, warnings),
        evidence_ref=_opt_str(record.get("evidence_ref")),
        delivered_via=str(delivered),
        gaps=tuple(gaps),
        contradictions=tuple(contradictions),
        name=name,
        arguments_ref=arguments_ref,
    )
