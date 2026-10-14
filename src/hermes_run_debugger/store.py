"""Profile-owned store: one authoritative SQLite journal, redact-before-persist.

Design decisions worth naming, because each one is a place a debugger usually
lies to its user:

* **Redaction happens before the write, not after.** Every value that reaches
  this module is redacted and scrub-guarded first; there is no code path that
  stores a raw record "for later" and no raw-whole-database copy.
* **One journal.** ``import_journal`` is the authoritative record of import
  intent; ``import_revisions`` records snapshot identity. A crash leaves a
  ``running`` journal row, and the next open marks that run ``incomplete``
  instead of pretending the partial rows are the run.
* **Idempotent imports.** Re-importing the same snapshot changes nothing. A
  *changed* file is a new revision with its own snapshot identity, so a growing
  file can never blend new rows into older counts.
* **Deletion is contained.** ``delete_run`` removes this store's own rows and
  never follows a path stored in a record.
* **No global path caching.** The data directory is a constructor argument
  resolved by the caller for the active profile, per operation.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import migrations as _migrations
from .event_v1 import Attempt, Clock, Event, Usage
from .identity import is_digest_value, opaque_ref
from .redact import (
    RedactionPolicy,
    ScrubFailure,
    iter_high_risk_fields,
    minimal_policy,
    redact_record,
    sanitise_message,
    scan_high_risk,
    scrub_guard_payload,
)
from .report import build_report, render, write_report

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "ImportOutcome",
    "RunDebugStore",
    "StoreError",
    "StoredRun",
    "migration_backup_path",
]

CURRENT_SCHEMA_VERSION = _migrations.CURRENT_SCHEMA_VERSION

_COUNTABLE_TABLES = frozenset({
    "runs", "attempts", "events", "gaps", "diagnoses", "import_journal", "import_revisions", "refs",
})


class StoreError(RuntimeError):
    """The store refused an operation. Never a silent partial write."""


def migration_backup_path(data_dir: str | Path, version: int = CURRENT_SCHEMA_VERSION) -> Path:
    """Path of the protected pre-migration copy of the store file."""
    return _migrations.backup_path(Path(data_dir), version)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ImportOutcome:
    run_id: str
    revision: int
    deduplicated: bool
    events: int
    attempts: int
    gaps: int
    redaction_applied: int
    completeness: str


@dataclass
class StoredRun:
    run_id: str
    trace: dict[str, Any]
    events: list[Event]
    attempts: list[dict[str, Any]]
    gaps: list[dict[str, Any]]
    completeness: str
    may_claim_complete: bool
    revisions: list[dict[str, Any]]
    imported_at: str
    source: dict[str, Any]
    redaction: dict[str, Any]
    diagnosis: dict[str, Any] | None = None
    journal: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "imported_at": self.imported_at,
            "completeness": self.completeness,
            "may_claim_complete": self.may_claim_complete,
            "events": len(self.events),
            "attempts": len(self.attempts),
            "gaps": len(self.gaps),
            "revisions": len(self.revisions),
        }


class RunDebugStore:
    """A profile-scoped store. Construct with the directory the host resolved."""

    DB_FILENAME = "rundebug.db"

    def __init__(
        self,
        data_dir: str | Path,
        *,
        policy: RedactionPolicy | None = None,
        lock_timeout_s: float = 10.0,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.policy = policy or minimal_policy()
        self.lock_timeout_s = float(lock_timeout_s)
        self.db_path = self.data_dir / self.DB_FILENAME
        self._conn: sqlite3.Connection | None = None

    # -- lifecycle ---------------------------------------------------------
    def open(self) -> RunDebugStore:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            self.db_path,
            timeout=self.lock_timeout_s,
            isolation_level=None,  # explicit transactions
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute(f"pragma busy_timeout={int(self.lock_timeout_s * 1000)}")
        with suppress(sqlite3.DatabaseError):  # a concurrent writer may hold the lock briefly
            conn.execute("pragma journal_mode=WAL")
        conn.execute("pragma foreign_keys=on")
        self._conn = conn
        self._apply_migrations()
        return self

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> RunDebugStore:
        return self.open()

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise StoreError("store is not open; use it as a context manager or call open()")
        return self._conn

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = self.conn
        conn.execute("begin immediate")
        try:
            yield conn
        except BaseException:
            conn.execute("rollback")
            raise
        else:
            conn.execute("commit")

    # -- schema ------------------------------------------------------------
    def schema_version(self) -> int:
        if self._conn is None:
            raise StoreError("store is not open")
        row = self.conn.execute(
            "select name from sqlite_master where type='table' and name='schema_migrations'"
        ).fetchone()
        if row is None:
            return 0
        applied = [int(r["version"]) for r in self.conn.execute("select version from schema_migrations")]
        return max(applied) if applied else 0

    def _apply_migrations(self) -> None:
        applied = [int(r["version"]) for r in
                   self.conn.execute("select version from schema_migrations").fetchall()] \
            if self._has_table("schema_migrations") else []
        todo = _migrations.pending(applied)
        if not todo:
            return
        _migrations.protect_previous_file(self.db_path, self.data_dir, todo[-1].version)
        for migration in todo:
            with self._tx() as conn:
                for statement in migration.statements:
                    conn.execute(statement)
                conn.execute(
                    "insert or ignore into schema_migrations(version, applied_at) values (?, ?)",
                    (migration.version, _now()),
                )

    def _has_table(self, name: str) -> bool:
        row = self.conn.execute(
            "select name from sqlite_master where type='table' and name=?", (name,)
        ).fetchone()
        return row is not None

    # -- import ------------------------------------------------------------
    def import_trace(
        self,
        result: Any,
        *,
        source_summary: Mapping[str, Any] | None = None,
        imported_at: str | None = None,
        expected_records: int | None = None,
    ) -> ImportOutcome:
        """Persist a validated trace. Idempotent per source snapshot."""
        if getattr(result, "trace", None) is None:
            raise StoreError("import_trace requires a validated trace with an envelope")
        if not getattr(result, "ok", False):
            raise StoreError(f"refusing to store a refused trace: {result.refused[:3]}")

        source_summary = dict(source_summary or {})
        run_id = str(result.trace.run_id)
        snapshot = str(
            source_summary.get("sha256")
            or result.trace.source.get("ref")
            or result.trace.private_digests.get("content")
            or ""
        )
        if not snapshot:
            raise StoreError("source snapshot identity is required for an import")

        existing = self._journal_row(run_id, snapshot)
        if existing is not None and existing["status"] == "complete":
            return ImportOutcome(
                run_id=run_id,
                revision=int(existing["revision"] or self._current_revision(run_id)),
                deduplicated=True,
                events=0,
                attempts=0,
                gaps=0,
                redaction_applied=0,
                completeness=self._completeness(run_id),
            )

        redacted_source, source_counts = redact_record(source_summary, stage="pre-store", policy=self.policy)
        safe_path = _relative_safe(str(redacted_source.get("path", "")))
        trace_payload, trace_counts = redact_record(result.trace.as_dict(), stage="pre-store", policy=self.policy)
        applied = _sum_counts(source_counts) + _sum_counts(trace_counts)

        # A sensitive-shaped value found in an identifier/reference/digest field is
        # refused outright. Silently rewriting it would break evidence linkage, and
        # persisting it would be the very leak this store exists to prevent. The note
        # names the field only — never the value.
        blocked_fields: list[str] = []
        if source_counts.get("blocked_identifier"):
            blocked_fields.append("source summary (identifier/reference field)")
        if trace_counts.get("blocked_identifier"):
            blocked_fields.append("trace envelope (identifier/reference field)")

        event_payloads: list[tuple[Event, dict[str, Any]]] = []
        for index, event in enumerate(result.events, start=1):
            payload, counts = redact_record(event.as_dict(), stage="pre-store", policy=self.policy)
            if counts.get("blocked_identifier"):
                # Position, never the value: a refusal message must not echo the secret
                # back into a log, a terminal or the operator's clipboard.
                blocked_fields.append(f"event #{index} (identifier/reference field)")
            scrub_guard_payload(payload, self.policy)
            applied += _sum_counts(counts)
            event_payloads.append((event, payload))
        attempt_payloads: list[tuple[Attempt, dict[str, Any]]] = []
        for index, attempt in enumerate(result.attempts, start=1):
            payload, counts = redact_record(attempt.as_dict(), stage="pre-store", policy=self.policy)
            if counts.get("blocked_identifier"):
                blocked_fields.append(f"attempt #{index} (identifier/reference field)")
            scrub_guard_payload(payload, self.policy)
            applied += _sum_counts(counts)
            attempt_payloads.append((attempt, payload))
        gap_payloads: list[dict[str, Any]] = []
        for gap in result.gaps:
            payload, counts = redact_record(gap.as_dict(), stage="pre-store", policy=self.policy)
            if counts.get("blocked_identifier"):
                blocked_fields.append("evidence gap (identifier/reference field)")
            scrub_guard_payload(payload, self.policy)
            applied += _sum_counts(counts)
            gap_payloads.append(payload)
        scrub_guard_payload(trace_payload, self.policy)
        scrub_guard_payload(redacted_source, self.policy)

        # The envelope's private digest map is not persisted (private digests live in
        # the store's own columns), but a value smuggled into a digest-shaped field is
        # refused: it means the trace is not the shape it claims to be, and refusing
        # keeps a credential from being quietly dropped in one place and kept in another.
        envelope_hits = iter_high_risk_fields(result.trace.private_digests or {}, self.policy)
        digest_keys = {"content", "sha256", "content_sha256", "digest"}
        bad_digests = [
            key
            for key, value in (result.trace.private_digests or {}).items()
            if key.lower() in digest_keys and isinstance(value, str) and not is_digest_value(value)
        ]
        for entry in (result.trace.private_digests or {}).get("files", []) or []:
            if isinstance(entry, Mapping):
                bad_digests.extend(
                    f"files[].{key}" for key, value in entry.items()
                    if key.lower() in digest_keys and isinstance(value, str) and not is_digest_value(value)
                )

        if blocked_fields:
            raise ScrubFailure(
                "refused: a sensitive-shaped value was found in an identifier/reference field ("
                + ", ".join(sorted(set(blocked_fields)))
                + "). The source is refused rather than persisted: no raw value was written and no "
                "identifier was silently rewritten. Re-export the trace without credentials in id "
                "or reference fields, or choose a different source."
            )
        if envelope_hits or bad_digests:
            detail = "; ".join(
                [f"{path}: {', '.join(categories)}" for path, categories in envelope_hits[:3]]
                + ([f"non-digest value in {sorted(set(bad_digests))}"] if bad_digests else [])
            )
            raise ScrubFailure(
                "refused: the envelope's private digest map contains a value that is not a digest "
                f"or is credential-shaped ({detail}). Digest fields carry digests only; the source "
                "is refused rather than stored or silently dropped."
            )
        # The snapshot identity is written to columns of its own (journal, revisions),
        # so it is value-checked before any of them are touched.
        if scan_high_risk(snapshot, self.policy):
            raise ScrubFailure(
                "refused: the source snapshot identity is credential-shaped. Re-export the trace with "
                "a genuine digest so the import can be identified without storing a secret."
            )

        stamp = imported_at or _now()
        journal_id = uuid.uuid4().hex
        # Step 1: declare intent. This commits on its own so a crash after this
        # point is visible as an unfinished import rather than as a clean one.
        with self._tx() as conn:
            revision = self._next_revision(conn, run_id)
            conn.execute(
                "insert into runs(run_id, trace_id, trace_json, completeness, may_claim_complete,"
                " imported_at, source_kind, source_path, source_ref, redaction_json, current_revision)"
                " values (?,?,?,?,?,?,?,?,?,?,?)"
                " on conflict(run_id) do update set trace_json=excluded.trace_json,"
                " completeness=excluded.completeness, may_claim_complete=excluded.may_claim_complete,"
                " imported_at=excluded.imported_at, source_kind=excluded.source_kind,"
                " source_path=excluded.source_path, source_ref=excluded.source_ref,"
                " redaction_json=excluded.redaction_json, current_revision=excluded.current_revision",
                (
                    run_id,
                    str(result.trace.trace_id),
                    json.dumps(trace_payload, ensure_ascii=False, allow_nan=False),
                    "incomplete",
                    0,
                    stamp,
                    str(result.trace.source.get("kind", "unknown")),
                    safe_path,
                    f"redacted-sha256:{snapshot[:16]}" if snapshot else "",
                    json.dumps({"applied": applied}, ensure_ascii=False),
                    revision,
                ),
            )
            conn.execute(
                "insert into import_journal(journal_id, run_id, snapshot_sha256, status,"
                " expected_records, observed_records, started_at) values (?,?,?,?,?,?,?)",
                (journal_id, run_id, snapshot, "running", expected_records, 0, stamp),
            )
            conn.execute(
                "insert into import_revisions(run_id, revision, snapshot_sha256, source_records,"
                " imported_at) values (?,?,?,?,?)",
                (run_id, revision, snapshot, len(event_payloads), stamp),
            )

        # Step 2: write the payload.
        with self._tx() as conn:
            for event, payload in event_payloads:
                conn.execute(
                    "insert into events(run_id, event_id, attempt_id, source_sequence, event_kind,"
                    " reported_status, provenance, wall_time, monotonic_ms, payload_json)"
                    " values (?,?,?,?,?,?,?,?,?,?)"
                    " on conflict(run_id, event_id) do update set payload_json=excluded.payload_json,"
                    " reported_status=excluded.reported_status, provenance=excluded.provenance",
                    (
                        run_id, event.event_id, event.attempt_id, int(event.source_sequence),
                        event.event_kind, event.reported_status, event.semantic_provenance,
                        event.wall_time, event.monotonic_ms,
                        json.dumps(payload, ensure_ascii=False, allow_nan=False),
                    ),
                )
            for attempt, payload in attempt_payloads:
                conn.execute(
                    "insert into attempts(run_id, attempt_id, payload_json) values (?,?,?)"
                    " on conflict(run_id, attempt_id) do update set payload_json=excluded.payload_json",
                    (run_id, attempt.attempt_id,
                     json.dumps(payload, ensure_ascii=False, allow_nan=False)),
                )
            conn.execute("delete from gaps where run_id=?", (run_id,))
            for payload in gap_payloads:
                conn.execute(
                    "insert into gaps(run_id, event_id, kind, detail, parent_id) values (?,?,?,?,?)",
                    (run_id, payload.get("event_id"), str(payload.get("kind") or "unknown"),
                     str(payload.get("detail") or ""), payload.get("parent_id")),
                )

        # Step 3: declare completion.
        with self._tx() as conn:
            conn.execute(
                "update import_journal set status='complete', observed_records=?, finished_at=?"
                " where journal_id=?",
                (len(event_payloads), _now(), journal_id),
            )
            conn.execute(
                "update runs set completeness='complete', may_claim_complete=? where run_id=?",
                (1 if _may_claim_complete(result) else 0, run_id),
            )

        return ImportOutcome(
            run_id=run_id,
            revision=revision,
            deduplicated=False,
            events=len(event_payloads),
            attempts=len(attempt_payloads),
            gaps=len(gap_payloads),
            redaction_applied=applied,
            completeness=self._completeness(run_id),
        )

    def _next_revision(self, conn: sqlite3.Connection, run_id: str) -> int:
        row = conn.execute(
            "select coalesce(max(revision), 0) as r from import_revisions where run_id=?", (run_id,)
        ).fetchone()
        return int(row["r"]) + 1

    def _current_revision(self, run_id: str) -> int:
        row = self.conn.execute(
            "select coalesce(max(revision), 0) as r from import_revisions where run_id=?", (run_id,)
        ).fetchone()
        return int(row["r"]) if row else 0

    def _journal_row(self, run_id: str, snapshot: str) -> Mapping[str, Any] | None:
        row = self.conn.execute(
            "select j.*, r.revision from import_journal j"
            " left join import_revisions r on r.run_id=j.run_id and r.snapshot_sha256=j.snapshot_sha256"
            " where j.run_id=? and j.snapshot_sha256=? order by j.started_at desc limit 1",
            (run_id, snapshot),
        ).fetchone()
        return dict(row) if row is not None else None

    def _completeness(self, run_id: str) -> str:
        row = self.conn.execute("select completeness from runs where run_id=?", (run_id,)).fetchone()
        return str(row["completeness"]) if row else "unknown"

    def _debug_journal_begin(self, run_id: str, snapshot: str, *, expected_records: int) -> str:
        """Test hook: simulate an import that was interrupted after its intent commit.

        Deliberately private (leading underscore) and used only by the crash-recovery
        test, so production code has no way to reach this state on purpose.
        """
        journal_id = uuid.uuid4().hex
        with self._tx() as conn:
            conn.execute(
                "insert into runs(run_id, trace_id, trace_json, completeness, may_claim_complete,"
                " imported_at, source_kind, redaction_json, current_revision)"
                " values (?,?,?,?,?,?,?,?,?)"
                " on conflict(run_id) do update set completeness='incomplete', may_claim_complete=0",
                (run_id, f"t-{run_id}", "{}", "incomplete", 0, _now(), "file", "{}", 0),
            )
            conn.execute(
                "insert into import_journal(journal_id, run_id, snapshot_sha256, status,"
                " expected_records, observed_records, started_at) values (?,?,?,?,?,?,?)"
                " on conflict(run_id, snapshot_sha256) do update set status='running'",
                (journal_id, run_id, snapshot, "running", expected_records, 0, _now()),
            )
        return journal_id

    def recover_incomplete_imports(self) -> list[str]:
        """Mark unfinished imports ``recovered``. Their runs make no completeness claim."""
        rows = self.conn.execute(
            "select journal_id, run_id from import_journal where status='running'"
        ).fetchall()
        if not rows:
            return []
        run_ids = [str(row["run_id"]) for row in rows]
        with self._tx() as conn:
            for row in rows:
                conn.execute(
                    "update import_journal set status='recovered', finished_at=?,"
                    " detail='interrupted before completion; partial rows retained as incomplete'"
                    " where journal_id=?",
                    (_now(), row["journal_id"]),
                )
                conn.execute(
                    "update runs set completeness='incomplete', may_claim_complete=0 where run_id=?",
                    (row["run_id"],),
                )
        return run_ids

    # -- reads -------------------------------------------------------------
    def list_runs(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "select run_id, completeness, may_claim_complete, imported_at, current_revision"
            " from runs order by imported_at, run_id"
        ).fetchall()
        return [dict(row) for row in rows]

    def revisions(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "select revision, snapshot_sha256, source_records, imported_at from import_revisions"
            " where run_id=? order by revision",
            (run_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def count_rows(self, table: str, *, run_id: str | None = None) -> int:
        if table not in _COUNTABLE_TABLES:
            raise StoreError(f"unknown table {table!r}")
        if run_id is None:
            row = self.conn.execute(f"select count(*) as c from {table}").fetchone()
        else:
            column = "run_id"
            row = self.conn.execute(
                f"select count(*) as c from {table} where {column}=?", (run_id,)
            ).fetchone()
        return int(row["c"])

    def load_run(self, run_id: str) -> StoredRun:
        row = self.conn.execute("select * from runs where run_id=?", (run_id,)).fetchone()
        if row is None:
            raise StoreError(f"unknown run: {sanitise_message(run_id)}")
        events = [
            _event_from_payload(json.loads(r["payload_json"]))
            for r in self.conn.execute(
                "select payload_json from events where run_id=? order by source_sequence, event_id",
                (run_id,),
            )
        ]
        attempts = [
            json.loads(r["payload_json"])
            for r in self.conn.execute(
                "select payload_json from attempts where run_id=? order by attempt_id", (run_id,)
            )
        ]
        gaps = [
            dict(r) for r in self.conn.execute(
                "select event_id, kind, detail, parent_id from gaps where run_id=? order by gap_id", (run_id,)
            )
        ]
        diagnosis_row = self.conn.execute(
            "select payload_json from diagnoses where run_id=?", (run_id,)
        ).fetchone()
        journal = [dict(r) for r in self.conn.execute(
            "select journal_id, snapshot_sha256, status, expected_records, observed_records,"
            " started_at, finished_at from import_journal where run_id=? order by started_at",
            (run_id,),
        )]
        return StoredRun(
            run_id=str(row["run_id"]),
            trace=json.loads(row["trace_json"]),
            events=events,
            attempts=attempts,
            gaps=gaps,
            completeness=str(row["completeness"]),
            may_claim_complete=bool(row["may_claim_complete"]),
            revisions=self.revisions(run_id),
            imported_at=str(row["imported_at"]),
            source={
                "kind": row["source_kind"],
                "path": row["source_path"],
                "ref": row["source_ref"],
            },
            redaction=json.loads(row["redaction_json"] or "{}"),
            diagnosis=json.loads(diagnosis_row["payload_json"]) if diagnosis_row else None,
            journal=journal,
        )

    def journal(self, *, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "select journal_id, run_id, snapshot_sha256, status, started_at, finished_at, detail"
            " from import_journal order by started_at desc limit ?",
            (int(limit),),
        ).fetchall()
        return [dict(row) for row in rows]

    # -- writes ------------------------------------------------------------
    def record_diagnosis(self, run_id: str, diagnosis: Mapping[str, Any]) -> None:
        payload, counts = redact_record(dict(diagnosis), stage="pre-store", policy=self.policy)
        with self._tx() as conn:
            conn.execute(
                "insert into diagnoses(run_id, payload_json, created_at) values (?,?,?)"
                " on conflict(run_id) do update set payload_json=excluded.payload_json,"
                " created_at=excluded.created_at",
                (run_id, json.dumps(payload, ensure_ascii=False, allow_nan=False), _now()),
            )
        del counts

    def delete_run(self, run_id: str) -> dict[str, int]:
        """Delete only this store's rows for *run_id*. Never follows a source path."""
        deleted: dict[str, int] = {}
        with self._tx() as conn:
            for table in ("events", "attempts", "gaps", "diagnoses", "import_revisions", "import_journal"):
                cursor = conn.execute(f"delete from {table} where run_id=?", (run_id,))
                deleted[table] = int(cursor.rowcount or 0)
            cursor = conn.execute("delete from runs where run_id=?", (run_id,))
            deleted["runs"] = int(cursor.rowcount or 0)
        return deleted

    def prune(self, *, retention_days: int, now: datetime | None = None) -> list[str]:
        if retention_days < 0:
            raise StoreError("retention_days must be >= 0")
        cutoff = (now or datetime.now(UTC)) - timedelta(days=retention_days)
        cutoff_stamp = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        rows = self.conn.execute(
            "select run_id from runs where imported_at < ? order by imported_at", (cutoff_stamp,)
        ).fetchall()
        removed: list[str] = []
        for row in rows:
            self.delete_run(str(row["run_id"]))
            removed.append(str(row["run_id"]))
        return removed

    # -- refs and export ---------------------------------------------------
    def refs_salt(self) -> str:
        row = self.conn.execute("select value from refs where key='salt'").fetchone()
        if row is not None:
            return str(row["value"])
        salt = secrets.token_hex(32)
        with self._tx() as conn:
            conn.execute("insert or ignore into refs(key, value) values ('salt', ?)", (salt,))
        row = self.conn.execute("select value from refs where key='salt'").fetchone()
        return str(row["value"])

    def opaque(self, kind: str, raw_id: str) -> str:
        return opaque_ref(self.refs_salt(), kind, raw_id)

    def build_report_for(self, run_id: str, *, opaque: bool = False) -> dict[str, Any]:
        run = self.load_run(run_id)
        ref_fn = (lambda kind, raw: self.opaque(kind, raw)) if opaque else None
        trace = {
            key: run.trace.get(key)
            for key in (
                "schema", "version", "importer", "importer_version", "source_format", "source_scope",
                "covered_kinds", "unsupported_kinds", "completeness",
            )
        }
        return build_report(
            run_id=run.run_id,
            events=run.events,
            attempts=run.attempts,
            gaps=run.gaps,
            trace=trace,
            completeness=run.completeness,
            may_claim_complete=run.may_claim_complete,
            revisions=len(run.revisions),
            imported_at=run.imported_at,
            diagnosis=run.diagnosis,
            opaque=ref_fn,
            redaction=run.redaction,
        )

    def export_run(self, run_id: str, path: str | Path, *, fmt: str = "markdown") -> Path:
        """Private export. Opaque refs outward, no paths, no raw digests, no egress."""
        report = self.build_report_for(run_id, opaque=True)
        text = render(report, fmt)
        return write_report(text, path)


def _sum_counts(counts: Mapping[str, Any]) -> int:
    return sum(int(v) for k, v in counts.items() if k not in {"stage", "applied"})


def _relative_safe(path: str) -> str:
    """Store only the basename of a source path: the directory is not needed to debug."""
    if not path:
        return ""
    return Path(path).name


def _may_claim_complete(result: Any) -> bool:
    status = str((result.trace.completeness or {}).get("status", "unknown"))
    if status != "complete":
        return False
    return not any(gap.kind in {"missing_parent", "partial_source", "truncation"} for gap in result.gaps)


def _event_from_payload(payload: Mapping[str, Any]) -> Event:
    """Rebuild an Event from this store's own redacted payload (no revalidation)."""
    clock = payload.get("clock") or {}
    usage = payload.get("usage") or {}
    return Event(
        event_id=str(payload.get("event_id", "")),
        run_id=str(payload.get("run_id", "")),
        attempt_id=str(payload.get("attempt_id", "")),
        event_kind=str(payload.get("event_kind", "note")),
        semantic_provenance=str(payload.get("semantic_provenance", "unknown")),
        source_sequence=int(payload.get("source_sequence", 0) or 0),
        span_id=payload.get("span_id"),
        causal_parents=tuple(payload.get("causal_parents") or ()),
        wall_time=payload.get("wall_time"),
        monotonic_ms=payload.get("monotonic_ms"),
        clock=Clock(
            source=str(clock.get("source", "unknown")),
            quality=str(clock.get("quality", "unknown")),
        ),
        reported_status=str(payload.get("reported_status", "unknown")),
        reported_error=payload.get("reported_error"),
        usage=Usage(
            input_tokens=usage.get("input_tokens"),
            output_tokens=usage.get("output_tokens"),
            cache_read_tokens=usage.get("cache_read_tokens"),
            cache_write_tokens=usage.get("cache_write_tokens"),
            cost=usage.get("cost"),
            cost_kind=str(usage.get("cost_kind", "unknown")),
            price_source=usage.get("price_source"),
            price_version=usage.get("price_version"),
        ),
        evidence_ref=payload.get("evidence_ref"),
        delivered_via=str(payload.get("delivered_via", "import")),
        gaps=tuple(payload.get("gaps") or ()),
        contradictions=tuple(payload.get("contradictions") or ()),
        name=payload.get("name"),
        arguments_ref=payload.get("arguments_ref"),
    )
