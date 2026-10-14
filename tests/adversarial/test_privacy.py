"""DT09 — privacy: seeded secrets must not survive into any persisted or exported
artefact, and the limits of deterministic filtering must be stated, not hidden.

The claim under test is deliberately narrow: *these* seeded values, in *these*
shapes, are removed before persistence and before export. It is never "private by
regex therefore safe".
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from hermes_run_debugger.event_v1 import validate_trace_records
from hermes_run_debugger.redact import (
    CATEGORIES,
    RedactionPolicy,
    ScrubFailure,
    minimal_policy,
    redact_record,
    redact_text,
    scan_high_risk,
    scrub_guard,
)
from hermes_run_debugger.store import RunDebugStore

OPENAI_KEY = "sk-A1b2C3d4E5f6G7h8I9j0K1l2"
GITHUB_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SLACK_TOKEN = "xoxb-123456789012-abcdefghijklmn"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"
EMAIL = "sahil@example.com"
PHONE = "+44 7700 900123"
HOME_PATH = "/home/kensei/private/api-keys.txt"
ANSI = "\x1b[31mred text\x1b[0m"
CTRL = "a\x00b\x07c"
BEARER = "Authorization: Bearer 8f3ac21d9b7e4f603a5c"
SK_TOKEN = "sk-abcdef0123456789abcdef"

SEEDED = {
    "openai_key": OPENAI_KEY,
    "github_token": GITHUB_TOKEN,
    "aws_key": AWS_KEY,
    "slack_token": SLACK_TOKEN,
    "jwt": JWT,
    "email": EMAIL,
    "phone": PHONE,
    "bearer": "8f3ac21d9b7e4f603a5c",
}
# A value with no known shape: it must survive redaction, and the policy must say so.
UNPATTERNED = "Zx9Qm4Lp7Rt2Wv5Bn8Kc3Hd6Fj1Gs0"


def trace_with(payload: str):
    record = {
        "kind": "trace",
        "schema": "hermes-run-debugger/trace",
        "version": 1,
        "trace_id": "t-priv",
        "run_id": "r-priv",
        "importer": "import_v1",
        "importer_version": "0.1.0",
        "source_format": "event-v1",
        "source_scope": "explicit-selection",
        "created_at": "2026-10-14T10:00:00Z",
        "source": {"kind": "file", "ref": "sha256:" + "b" * 64, "name": "selected.jsonl"},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["tool_call"],
        "unsupported_kinds": [],
        "completeness": {"status": "complete", "missing_kinds": [], "notes": []},
    }
    attempt = {
        "kind": "attempt",
        "attempt_id": "att-priv",
        "run_id": "r-priv",
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
    }
    event = {
        "kind": "event",
        "event_id": "e-priv",
        "run_id": "r-priv",
        "attempt_id": "att-priv",
        "span_id": None,
        "causal_parents": [],
        "source_sequence": 1,
        "wall_time": "2026-10-14T10:00:05Z",
        "monotonic_ms": 5000,
        "clock": {"source": "wall", "quality": "low"},
        "event_kind": "tool_call",
        "reported_status": "failed",
        "reported_error": payload,
        "usage": {"input_tokens": 5, "output_tokens": 7},
        "evidence_ref": "ref:0001",
        "delivered_via": "import",
        "semantic_provenance": "reported",
        "gaps": [],
        "contradictions": [],
    }
    return validate_trace_records([record, attempt, event])


def test_every_seeded_shape_is_redacted_with_a_category_count():
    payload = " | ".join([
        OPENAI_KEY, GITHUB_TOKEN, AWS_KEY, SLACK_TOKEN, JWT, EMAIL, PHONE, ANSI, CTRL, BEARER,
    ])
    result = redact_text(payload)
    for name, value in SEEDED.items():
        assert value not in result.text, f"{name} survived redaction"
    assert "\x1b" not in result.text and "\x00" not in result.text and "\x07" not in result.text
    assert result.counts["openai_key"] >= 1
    assert result.counts["email"] >= 1
    assert result.applied == sum(result.counts.values())
    assert set(result.counts) <= set(CATEGORIES)


def test_home_paths_keep_structure_and_mask_the_user():
    result = redact_text(f"failed reading {HOME_PATH}")
    assert "api-keys.txt" in result.text  # the fact of the file stays useful
    assert "kensei" not in result.text
    assert result.counts["home_path"] >= 1


def test_untested_shapes_are_a_stated_limitation_not_a_claim_of_safety():
    result = redact_text(UNPATTERNED)
    assert UNPATTERNED in result.text, "an unknown shape is not magically detected"
    limits = minimal_policy().limitations()
    joined = " ".join(limits).lower()
    assert "not a guarantee" in joined or "cannot" in joined
    assert any("unknown" in line.lower() or "unrecognised" in line.lower() for line in limits)


def test_high_risk_scan_and_guard_refuse_rather_than_publish():
    text = f"log line with {OPENAI_KEY} inside"
    assert scan_high_risk(text)
    with pytest.raises(ScrubFailure):
        scrub_guard(text)
    # A policy that disables a category must NOT disable the guard for it:
    # the guard is the last line of defence, not a mirror of the policy.
    leaky = RedactionPolicy(disabled_categories=("openai_key",))
    assert scan_high_risk(text, policy=leaky)
    with pytest.raises(ScrubFailure):
        scrub_guard(text, policy=leaky)
    # Once genuinely redacted, the guard passes.
    scrub_guard(redact_text(text).text, policy=minimal_policy())


def test_scrub_guard_raises_for_seeded_input():
    with pytest.raises(ScrubFailure):
        scrub_guard(f"token={GITHUB_TOKEN}")


def test_record_level_redaction_drops_sensitive_keys_entirely():
    record = {
        "reported_error": f"used {OPENAI_KEY}",
        "authorization": f"Bearer {BEARER}",
        "api_key": OPENAI_KEY,
        "request_messages": [{"role": "user", "content": "raw prompt text"}],
        "raw_body": "raw provider body",
        "safe_field": "kept",
    }
    redacted, counts = redact_record(record, stage="pre-store")
    assert "raw prompt text" not in json.dumps(redacted)
    assert "raw provider body" not in json.dumps(redacted)
    assert OPENAI_KEY not in json.dumps(redacted)
    assert redacted["safe_field"] == "kept"
    assert redacted["authorization"].startswith("[redacted")
    assert redacted["request_messages"].startswith("[redacted")
    assert counts["dropped_key"] >= 3
    assert counts["openai_key"] >= 1


def test_two_stages_are_both_recorded():
    _, first = redact_record({"reported_error": f"key {OPENAI_KEY}"}, stage="pre-store")
    _, second = redact_record({"reported_error": "nothing sensitive"}, stage="pre-egress")
    assert first["stage"] == "pre-store"
    assert second["stage"] == "pre-egress"
    assert second["applied"] == 0


def test_secrets_never_reach_the_store_or_the_export(tmp_path):
    payload = json.dumps(SEEDED)
    result = trace_with(payload.replace('"', ""))
    policy = minimal_policy()

    store_dir = tmp_path / "plugin-data"
    with RunDebugStore(store_dir, policy=policy) as store:
        outcome = store.import_trace(result, source_summary={"path": "selected.jsonl"})
        assert outcome.run_id == "r-priv"
        report_path = tmp_path / "export" / "report.md"
        store.export_run("r-priv", report_path, fmt="markdown")
        # The whole store directory: main DB file, WAL and SHM sidecars alike.
        store_files = {path: path.read_bytes() for path in store_dir.iterdir() if path.is_file()}

    assert store_files, "expected at least the store file"
    for name, value in SEEDED.items():
        for path, blob in store_files.items():
            assert value.encode() not in blob, f"{name} reached {path.name}"
        assert value not in report_path.read_text(encoding="utf-8"), f"{name} reached the export"

    mode = stat.S_IMODE(report_path.stat().st_mode)
    assert mode & 0o077 == 0, f"export must not be group/world readable, got {oct(mode)}"

    # And the second-stage guard refuses to persist a credential that a
    # misconfigured policy would have let through.
    guarded_dir = tmp_path / "guarded"
    leaky = RedactionPolicy(disabled_categories=("github_token",))
    with RunDebugStore(guarded_dir, policy=leaky) as store:
        with pytest.raises(ScrubFailure):
            store.import_trace(
                trace_with(f"leaked {GITHUB_TOKEN} in a log line"),
                source_summary={"path": "x.jsonl", "sha256": "s"},
            )
        assert store.list_runs() == [], "a refused import must not create a run"
    for path in guarded_dir.iterdir():
        if path.is_file():
            assert GITHUB_TOKEN.encode() not in path.read_bytes(), f"{path.name} holds the token"


def test_identifiers_are_never_rewritten_by_redaction():
    """Redaction must not corrupt evidence linkage: ids survive verbatim."""
    ids = [
        "evt_f4f1e2d3c4b5a6b7c8d9e0f1a2b3c4d",
        "att_0be0ef464321a45285a4",
        "ref:0001",
        "redacted-sha256:0123456789abcdef",
        "run_claude_6abf20338e84",
    ]
    text = " ".join(ids)
    result = redact_text(text)
    assert result.text == text, f"identifiers were rewritten: {result.text}"

    # A standalone long digit run in *free text* is card-like and is redacted;
    # identifiers are protected by field name, not by pattern.
    standalone = redact_text("account 4111111111111111 on file")
    assert "4111111111111111" not in standalone.text
    assert standalone.counts.get("card_number", standalone.counts.get("phone", 0)) >= 1

    record, _counts = redact_record(
        {
            "event_id": "evt_1234567890123456",
            "causal_parents": ["evt_1234567890123456"],
            "reported_error": "card 4111 1111 1111 1111 was quoted",
        },
        stage="pre-store",
    )
    assert record["event_id"] == "evt_1234567890123456"
    assert record["causal_parents"] == ["evt_1234567890123456"]
    assert "4111 1111 1111 1111" not in record["reported_error"]


def test_store_round_trip_preserves_event_ids(tmp_path):
    """A stored-then-loaded run keeps the ids the timeline and parents depend on."""
    trace = trace_with("boom")
    with RunDebugStore(tmp_path) as store:
        store.import_trace(trace, source_summary={"path": "x.jsonl", "sha256": "s"})
        run = store.load_run("r-priv")
    assert [event.event_id for event in run.events] == [event.event_id for event in trace.events]
    assert "[redacted" not in run.events[0].event_id


# --------------------------------------------------------------------------
# R1 regressions: credential-shaped values in identifier/reference fields must
# not survive, and must be refused rather than silently rewritten (a silently
# altered id breaks linkage, which is worse than a refusal).
# --------------------------------------------------------------------------

GH_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
SK_KEY = "sk-A1b2C3d4E5f6G7h8I9j0K1l2"


def write_trace_file(tmp_path, *, run_id="r-ids", event_id="evt_a1b2c3d4e5f6", attempt_id="att_0be0ef46",
                     source_ref=None, evidence_ref="claude:request:r1", arguments_ref=None,
                     private_digests=None, name="session.jsonl"):
    """A valid, accepted event-v1 JSONL file (the real import path, not a fabricated result)."""
    header = {
        "kind": "trace", "schema": "hermes-run-debugger/trace", "version": 1,
        "trace_id": "t-ids", "run_id": run_id, "importer": "test", "importer_version": "0.1.0",
        "source_format": "event-v1", "source_scope": "explicit-selection",
        "created_at": "2026-10-14T10:00:00Z",
        "source": {"kind": "file", "ref": source_ref or ("sha256:" + "c" * 64), "name": name},
        "redaction": {"policy": "minimal-metadata", "applied_count": 0},
        "covered_kinds": ["tool_call"], "unsupported_kinds": [],
        "completeness": {"status": "complete", "missing_kinds": [], "notes": []},
    }
    if private_digests is not None:
        header["private_digests"] = private_digests
    attempt = {
        "kind": "attempt", "attempt_id": attempt_id, "run_id": run_id, "parent_attempt_id": None,
        "model": "example-model", "provider": "example-provider", "role": "primary", "branch": "main",
        "sequence": 0, "started_at": "2026-10-14T10:00:00Z", "ended_at": None,
        "outcome": "failed", "unknowns": [],
    }
    event = {
        "kind": "event", "event_id": event_id, "run_id": run_id, "attempt_id": attempt_id,
        "span_id": None, "causal_parents": [], "source_sequence": 0,
        "wall_time": "2026-10-14T10:00:01Z", "monotonic_ms": 1000,
        "clock": {"source": "monotonic", "quality": "high"}, "event_kind": "tool_call",
        "reported_status": "failed", "reported_error": "boom", "usage": {},
        "evidence_ref": evidence_ref, "delivered_via": "import",
        "semantic_provenance": "reported", "gaps": [], "contradictions": [], "name": "Bash",
    }
    if arguments_ref is not None:
        event["arguments_ref"] = arguments_ref
    path = tmp_path / name
    path.write_text("".join(json.dumps(record) + "\n" for record in (header, attempt, event)), encoding="utf-8")
    return path


def _import_through_services(path, tmp_path, **kwargs):
    from hermes_run_debugger.cli import Services

    data_dir = tmp_path / "plugin-data"
    with Services(data_dir=data_dir) as services:
        return services.import_sources([path], **kwargs), data_dir


def _files_under(directory):
    return {item: item.read_bytes() for item in Path(directory).rglob("*") if item.is_file()}


@pytest.mark.parametrize(
    "kwargs, culprit",
    [
        ({"source_ref": GH_TOKEN}, GH_TOKEN),
        ({"event_id": SK_KEY}, SK_KEY),
        ({"attempt_id": "att_" + GH_TOKEN}, GH_TOKEN),
        ({"run_id": "run_" + SK_TOKEN}, SK_TOKEN),
        ({"evidence_ref": SK_KEY}, SK_KEY),
        ({"arguments_ref": GH_TOKEN}, GH_TOKEN),
        ({"private_digests": {"content": GH_TOKEN}}, GH_TOKEN),
        ({"private_digests": {"files": [{"name": "a.jsonl", "sha256": SK_KEY}]}}, SK_KEY),
    ],
)
def test_credential_shaped_identifiers_are_refused_and_never_persisted(tmp_path, kwargs, culprit):
    """Real accepted-file import: a sensitive-shaped id/ref/digest must be refused."""
    from hermes_run_debugger.import_v1 import ImportRefused

    path = write_trace_file(tmp_path, **kwargs)
    with pytest.raises(ImportRefused) as exc:
        _import_through_services(path, tmp_path)
    assert exc.value.kind == "privacy"
    message = " ".join(exc.value.reasons)
    assert culprit not in message, "the refusal must not echo a credential-shaped value back"
    assert "identifier/reference field" in message or "digest" in message

    for name, blob in _files_under(tmp_path / "plugin-data").items():
        assert culprit.encode() not in blob, f"{name} holds the credential"


def test_credential_in_a_free_text_field_is_redacted_not_refused(tmp_path):
    """Non-identifier fields are redacted in place; the import still succeeds."""
    path = write_trace_file(tmp_path)
    text = path.read_text(encoding="utf-8").replace("boom", f"used {GH_TOKEN} in the command")
    path.write_text(text, encoding="utf-8")

    imported, data_dir = _import_through_services(path, tmp_path)
    assert imported and imported[0]["redaction_applied"] >= 1
    for name, blob in _files_under(data_dir).items():
        assert GH_TOKEN.encode() not in blob, f"{name} holds the credential"


def test_legitimate_ids_keep_their_linkage_through_the_store(tmp_path):
    """The guard must not shred normal hex/uuid ids or parent links."""
    from hermes_run_debugger.event_v1 import validate_trace_records

    path = write_trace_file(tmp_path, event_id="evt_0123456789abcdef")
    imported, data_dir = _import_through_services(path, tmp_path)
    assert imported[0]["events"] == 1

    with RunDebugStore(data_dir) as store:
        run = store.load_run("r-ids")
    assert run.events[0].event_id == "evt_0123456789abcdef"
    assert run.events[0].attempt_id == "att_0be0ef46"
    assert run.trace["source"]["ref"].startswith("sha256:")
    assert "[redacted" not in json.dumps(run.trace)
    assert validate_trace_records([run.trace])  # the stored envelope still validates



def test_policy_is_configurable_and_count_only():
    policy = RedactionPolicy(name="minimal-metadata", redact_emails=False)
    result = redact_text(f"mail {EMAIL} key {OPENAI_KEY}", policy=policy)
    assert EMAIL in result.text
    assert OPENAI_KEY not in result.text
    assert policy.name == "minimal-metadata"
