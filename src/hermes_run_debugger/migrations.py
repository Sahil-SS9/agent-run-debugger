"""Versioned store migrations.

One migration list, applied in order inside a single transaction, each preceded
by a protected copy of the previous file. The migration chain is the only way the
schema is created: a fresh database is simply one that has no applied version
yet, so there is no separate "create tables" path that can drift from the
migrated one.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

__all__ = ["CURRENT_SCHEMA_VERSION", "MIGRATIONS", "Migration", "backup_path"]

CURRENT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Migration:
    version: int
    description: str
    statements: tuple[str, ...]


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        description="initial schema: runs, import journal, revisions, attempts, events, gaps, diagnoses, refs",
        statements=(
            "create table if not exists schema_migrations ("
            "  version integer primary key,"
            "  applied_at text not null)",
            "create table if not exists runs ("
            "  run_id text primary key,"
            "  trace_id text,"
            "  trace_json text not null,"
            "  completeness text not null,"
            "  may_claim_complete integer not null default 0,"
            "  imported_at text not null,"
            "  source_kind text,"
            "  source_path text,"
            "  source_ref text,"
            "  redaction_json text not null default '{}',"
            "  current_revision integer not null default 0)",
            "create table if not exists import_journal ("
            "  journal_id text primary key,"
            "  run_id text not null,"
            "  snapshot_sha256 text not null,"
            "  status text not null,"
            "  expected_records integer,"
            "  observed_records integer not null default 0,"
            "  started_at text not null,"
            "  finished_at text,"
            "  detail text,"
            "  unique (run_id, snapshot_sha256))",
            "create table if not exists import_revisions ("
            "  run_id text not null,"
            "  revision integer not null,"
            "  snapshot_sha256 text not null,"
            "  source_records integer not null,"
            "  imported_at text not null,"
            "  primary key (run_id, revision))",
            "create table if not exists attempts ("
            "  run_id text not null,"
            "  attempt_id text not null,"
            "  payload_json text not null,"
            "  primary key (run_id, attempt_id))",
            "create table if not exists events ("
            "  run_id text not null,"
            "  event_id text not null,"
            "  attempt_id text,"
            "  source_sequence integer not null default 0,"
            "  event_kind text,"
            "  reported_status text,"
            "  provenance text,"
            "  wall_time text,"
            "  monotonic_ms integer,"
            "  payload_json text not null,"
            "  primary key (run_id, event_id))",
            "create index if not exists events_by_run on events(run_id, source_sequence)",
            "create table if not exists gaps ("
            "  gap_id integer primary key autoincrement,"
            "  run_id text not null,"
            "  event_id text,"
            "  kind text not null,"
            "  detail text not null,"
            "  parent_id text)",
            "create table if not exists diagnoses ("
            "  run_id text primary key,"
            "  payload_json text not null,"
            "  created_at text not null)",
            "create table if not exists refs ("
            "  key text primary key,"
            "  value text not null)",
        ),
    ),
)


def backup_path(data_dir: Path, version: int = CURRENT_SCHEMA_VERSION) -> Path:
    """Where the pre-migration copy of the store file is kept."""
    return Path(data_dir) / f"rundebug.db.pre-v{version}.bak"


def pending(state: Iterable[int]) -> list[Migration]:
    applied = set(state)
    return [m for m in MIGRATIONS if m.version not in applied]


def protect_previous_file(db_path: Path, data_dir: Path, version: int) -> Path | None:
    """Copy the current file before a migration changes it. Restrictive perms."""
    db_path = Path(db_path)
    if not db_path.exists() or db_path.stat().st_size == 0:
        return None
    target = backup_path(data_dir, version)
    if target.exists():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(db_path, target)
    target.chmod(0o600)
    return target
