"""DT14 — store: idempotency, revisions, crash recovery, migrations, isolation,
owned-delete containment and retention.

No test here may touch the user's source files: the store owns record ids and
nothing else, and a delete must never follow a source-path reference.
"""

from __future__ import annotations

import json
import sqlite3
import stat
import threading
from datetime import datetime, timedelta, timezone

from hermes_run_debugger.event_v1 import validate_trace_records
from hermes_run_debugger.store import (
    CURRENT_SCHEMA_VERSION,
    RunDebugStore,
    migration_backup_path,
)


def make_trace(run_id: str, *, events: int = 2, payload: str = "ok", trace_id: str | None = None):
    records = [{
        "kind": "trace",
        "schema": "hermes-run-debugger/trace",
        "version": 1,
        "trace_id": trace_id or f"t-{run_id}",
        "run_id": run_id,
        "importer": "import_v1",
        "importer_version": "0.1.0",
        "source_format": "event-v1",
        "source_scope": "explicit-selection",
        "created_at": "2026-10-14T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "c" * 64, "name": "selected.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["tool_call"],
        "unsupported_kinds": [],
        "completeness": {"status": "complete", "missing_kinds": [], "notes": []},
    }, {
        "kind": "attempt",
        "attempt_id": f"att-{run_id}",
        "run_id": run_id,
        "parent_attempt_id": None,
        "model": "example-model",
        "provider": "example-provider",
        "role": "primary",
        "branch": "main",
        "sequence": 0,
        "started_at": "2026-10-14T10:00:00Z",
        "ended_at": "2026-10-14T10:01:00Z",
        "outcome": "failed",
        "unknowns": [],
    }]
    for idx in range(events):
        records.append({
            "kind": "event",
            "event_id": f"e-{run_id}-{idx}",
            "run_id": run_id,
            "attempt_id": f"att-{run_id}",
            "span_id": None,
            "causal_parents": [f"e-{run_id}-{idx - 1}"] if idx else [],
            "source_sequence": idx,
            "wall_time": f"2026-10-14T10:00:{idx:02d}Z",
            "monotonic_ms": idx * 1000,
            "clock": {"source": "wall", "quality": "low"},
            "event_kind": "tool_call",
            "reported_status": "failed",
            "reported_error": payload,
            "usage": {"input_tokens": 1, "output_tokens": 2},
            "evidence_ref": f"ref:{idx:04d}",
            "delivered_via": "import",
            "semantic_provenance": "reported",
            "gaps": [],
            "contradictions": [],
        })
    return validate_trace_records(records)


def test_import_is_idempotent_for_the_same_snapshot(tmp_path):
    trace = make_trace("r-1")
    with RunDebugStore(tmp_path) as store:
        first = store.import_trace(trace, source_summary={"path": "a.jsonl", "sha256": "s1"})
        second = store.import_trace(trace, source_summary={"path": "a.jsonl", "sha256": "s1"})
        assert first.deduplicated is False
        assert second.deduplicated is True
        assert second.revision == first.revision
        assert store.count_rows("events", run_id="r-1") == 2
        assert len(store.revisions("r-1")) == 1


def test_growing_source_records_a_new_revision_without_losing_history(tmp_path):
    with RunDebugStore(tmp_path) as store:
        store.import_trace(make_trace("r-1", events=2), source_summary={"path": "a.jsonl", "sha256": "s1"})
        second = store.import_trace(
            make_trace("r-1", events=3), source_summary={"path": "a.jsonl", "sha256": "s2"}
        )
        assert second.revision == 2
        revisions = store.revisions("r-1")
        assert [r["revision"] for r in revisions] == [1, 2]
        assert revisions[0]["snapshot_sha256"] == "s1"
        assert revisions[1]["source_records"] == 3


def test_crashed_import_is_recoverable_and_makes_no_completeness_claim(tmp_path):
    db_path = tmp_path / "rundebug.db"
    with RunDebugStore(tmp_path) as store:
        store.import_trace(make_trace("r-1"), source_summary={"path": "a.jsonl", "sha256": "s1"})
        # Simulate a crash mid-import: journal row left in 'running'.
        store._debug_journal_begin("r-2", "s-crash", expected_records=2)
    with RunDebugStore(tmp_path) as reopened:
        recovered = reopened.recover_incomplete_imports()
        assert recovered == ["r-2"]
        run = reopened.load_run("r-2")
        assert run.completeness == "incomplete"
        assert run.may_claim_complete is False
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute("select run_id, status from import_journal").fetchall()
    finally:
        conn.close()
    assert ("r-2", "recovered") in rows


def test_migration_runs_once_and_protects_the_previous_file(tmp_path):
    db_path = tmp_path / "rundebug.db"
    conn = sqlite3.connect(db_path)
    conn.execute("create table legacy_note (note text)")
    conn.execute("insert into legacy_note values ('pre-migration')")
    conn.commit()
    conn.close()

    with RunDebugStore(tmp_path) as store:
        assert store.schema_version() == CURRENT_SCHEMA_VERSION
        assert store.count_rows("events") == 0
    backup = migration_backup_path(tmp_path)
    assert backup.exists(), "a migration must protect the previous file before changing it"
    assert stat.S_IMODE(backup.stat().st_mode) & 0o077 == 0
    assert sqlite3.connect(backup).execute("select note from legacy_note").fetchone()[0] == "pre-migration"

    # Re-opening a migrated store does not migrate (or back up) again.
    first_mtime = backup.stat().st_mtime_ns
    with RunDebugStore(tmp_path) as again:
        assert again.schema_version() == CURRENT_SCHEMA_VERSION
    assert backup.stat().st_mtime_ns == first_mtime


def test_profile_directories_do_not_leak_into_each_other(tmp_path):
    with RunDebugStore(tmp_path / "profile-a") as a, RunDebugStore(tmp_path / "profile-b") as b:
        a.import_trace(make_trace("r-a"), source_summary={"path": "a.jsonl", "sha256": "sa"})
        b.import_trace(make_trace("r-b"), source_summary={"path": "b.jsonl", "sha256": "sb"})
        assert [r["run_id"] for r in a.list_runs()] == ["r-a"]
        assert [r["run_id"] for r in b.list_runs()] == ["r-b"]


def test_delete_is_contained_to_owned_record_ids(tmp_path):
    source_dir = tmp_path / "user-sources"
    source_dir.mkdir()
    source_file = source_dir / "trace.jsonl"
    source_file.write_text('{"kind":"trace"}\n', encoding="utf-8")

    with RunDebugStore(tmp_path / "data") as store:
        store.import_trace(make_trace("r-1"), source_summary={"path": str(source_file), "sha256": "s1"})
        store.import_trace(make_trace("r-2"), source_summary={"path": str(source_file), "sha256": "s2"})
        deleted = store.delete_run("r-1")
        assert deleted["events"] == 2
        assert [r["run_id"] for r in store.list_runs()] == ["r-2"]

    assert source_file.exists(), "deleting an import must never delete the user's source"
    assert source_file.read_text(encoding="utf-8") == '{"kind":"trace"}\n'


def test_retention_prune_only_removes_old_owned_runs(tmp_path):
    now = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
    with RunDebugStore(tmp_path) as store:
        store.import_trace(
            make_trace("r-old"),
            source_summary={"path": "a.jsonl", "sha256": "s1"},
            imported_at=(now - timedelta(days=120)).isoformat(),
        )
        store.import_trace(
            make_trace("r-new"),
            source_summary={"path": "b.jsonl", "sha256": "s2"},
            imported_at=(now - timedelta(days=5)).isoformat(),
        )
        removed = store.prune(retention_days=90, now=now)
        assert removed == ["r-old"]
        assert [r["run_id"] for r in store.list_runs()] == ["r-new"]


def test_concurrent_imports_from_two_handles_do_not_lose_events(tmp_path):
    traces = [make_trace(f"r-{i}") for i in range(2)]
    errors: list[Exception] = []

    def worker(index: int) -> None:
        try:
            with RunDebugStore(tmp_path) as store:
                store.import_trace(
                    traces[index], source_summary={"path": f"{index}.jsonl", "sha256": f"s{index}"}
                )
        except Exception as exc:  # pragma: no cover - surfaced by the assert below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors, errors
    with RunDebugStore(tmp_path) as store:
        assert sorted(r["run_id"] for r in store.list_runs()) == ["r-0", "r-1"]
        assert store.count_rows("events") == 4


def test_load_run_round_trips_events_and_provenance(tmp_path):
    with RunDebugStore(tmp_path) as store:
        store.import_trace(make_trace("r-1", events=3), source_summary={"path": "a.jsonl", "sha256": "s1"})
        run = store.load_run("r-1")
        assert run.run_id == "r-1"
        assert len(run.events) == 3
        assert run.events[0].semantic_provenance == "reported"
        assert run.events[2].causal_parents == ("e-r-1-1",)
        assert run.may_claim_complete is True
        assert json.dumps(run.trace)  # serialisable


def test_raw_digests_stay_private_and_exports_use_opaque_refs(tmp_path):
    with RunDebugStore(tmp_path) as store:
        store.import_trace(make_trace("r-1"), source_summary={"path": "/home/kensei/secret-dir/a.jsonl", "sha256": "s1"})
        export = store.export_run("r-1", tmp_path / "out.json", fmt="json")
        text = export.read_text(encoding="utf-8")
        assert "secret-dir" not in text
        assert "sha256:s1" not in text
        assert "ref" in text.lower()
