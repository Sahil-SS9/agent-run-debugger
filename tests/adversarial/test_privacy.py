"""DT09 — privacy: seeded secrets must not survive into any persisted or exported
artefact, and the limits of deterministic filtering must be stated, not hidden.

The claim under test is deliberately narrow: *these* seeded values, in *these*
shapes, are removed before persistence and before export. It is never "private by
regex therefore safe".
"""

from __future__ import annotations

import json
import stat

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


def test_policy_is_configurable_and_count_only():
    policy = RedactionPolicy(name="minimal-metadata", redact_emails=False)
    result = redact_text(f"mail {EMAIL} key {OPENAI_KEY}", policy=policy)
    assert EMAIL in result.text
    assert OPENAI_KEY not in result.text
    assert policy.name == "minimal-metadata"
