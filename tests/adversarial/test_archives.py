"""DT04 — archives, binaries and traversal/bomb shapes must be refused before any
extraction exists.

v1 supports JSONL only. The point of these tests is not the refusal message; it is
that there is **no extraction code path to reach**. A future archive adapter has to
validate member count, size, ratio, paths, symlinks and hardlinks first — the
refusal here names those requirements so the bar is recorded, not discovered later.
"""

from __future__ import annotations

import gzip
import io
import json
import sqlite3
import tarfile
import zipfile

import pytest

from hermes_run_debugger.import_v1 import ImportRefused, import_trace
from hermes_run_debugger.jsonio import StreamLimits

PAYLOAD = json.dumps({
    "kind": "trace",
    "schema": "hermes-run-debugger/trace",
    "version": 1,
    "trace_id": "t-archive",
    "run_id": "r-archive",
    "importer": "import_v1",
    "importer_version": "0.1.0",
    "source_format": "event-v1",
    "source_scope": "explicit-selection",
    "created_at": "2026-10-14T10:00:00Z",
    "source": {"kind": "file", "ref": "sha256:" + "e" * 64, "name": "a.jsonl"},
    "redaction": {"policy": "minimal-metadata", "applied_count": 0},
    "covered_kinds": ["tool_call"],
    "unsupported_kinds": [],
    "completeness": {"status": "complete", "missing_kinds": [], "notes": []},
}) + "\n"


@pytest.fixture(autouse=True)
def _no_extraction_allowed(monkeypatch):
    """Any extraction attempt anywhere in this module is a hard failure."""
    def boom(*_args, **_kwargs):
        raise AssertionError("an extraction code path was reached")

    monkeypatch.setattr(zipfile.ZipFile, "extractall", boom, raising=False)
    monkeypatch.setattr(zipfile.ZipFile, "extract", boom, raising=False)
    monkeypatch.setattr(tarfile.TarFile, "extractall", boom, raising=False)
    monkeypatch.setattr(tarfile.TarFile, "extract", boom, raising=False)


def test_zip_containing_a_valid_trace_is_refused(tmp_path):
    archive = tmp_path / "traces.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("trace.jsonl", PAYLOAD)
    before = sorted(p.name for p in tmp_path.iterdir())

    with pytest.raises(ImportRefused) as exc:
        import_trace(archive, fmt="v1")
    message = str(exc.value)
    assert "archive" in message.lower()
    assert "jsonl" in message.lower()
    # the bar a future adapter must meet is recorded in the refusal itself
    assert "member" in message.lower() and ("symlink" in message.lower() or "traversal" in message.lower())
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_tar_with_a_traversal_member_is_refused_without_reading_it(tmp_path):
    archive = tmp_path / "traces.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        data = PAYLOAD.encode()
        info = tarfile.TarInfo("../escape.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    outside = tmp_path.parent / "escape.txt"

    with pytest.raises(ImportRefused):
        import_trace(archive, fmt="v1")
    assert not outside.exists(), "traversal member must never land outside the target"


def test_gzip_and_raw_sqlite_are_refused(tmp_path):
    gz = tmp_path / "traces.jsonl.gz"
    gz.write_bytes(gzip.compress(PAYLOAD.encode()))
    db = tmp_path / "state.db"
    conn = sqlite3.connect(db)
    conn.execute("create table messages (id integer)")
    conn.commit()
    conn.close()

    for path in (gz, db):
        with pytest.raises(ImportRefused) as exc:
            import_trace(path, fmt="v1")
        assert "unsupported" in str(exc.value).lower()


def test_plain_jsonl_with_an_archive_ish_name_still_imports(tmp_path):
    path = tmp_path / "not-an-archive.jsonl"
    path.write_text(PAYLOAD, encoding="utf-8")
    imported = import_trace(path, fmt="v1", limits=StreamLimits())
    assert imported.result.trace.run_id == "r-archive"


def test_format_detection_reports_unsupported_rather_than_guessing(tmp_path):
    path = tmp_path / "binary.dat"
    path.write_bytes(bytes(range(32)))
    with pytest.raises(ImportRefused) as exc:
        import_trace(path, fmt=None)
    assert "determine" in str(exc.value).lower() or "refus" in str(exc.value).lower()
