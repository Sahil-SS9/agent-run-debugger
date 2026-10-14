"""DT18 — end to end on a clean profile, and the export authority boundary.

Clean profile means: one temporary data directory, no sibling plugin, no service,
no daemon. The workflow has to work there, and `export` has to be unreachable from
every route except the operator CLI.
"""

from __future__ import annotations

import json
import stat

import pytest

from hermes_run_debugger.adapters.hermes import TOOL_NAMES
from hermes_run_debugger.cli import (
    EXPORT_REFUSAL,
    Services,
    handle_slash,
    run_cli,
    tool_explain,
    tool_status,
)
from hermes_run_debugger.import_v1 import ImportRefused
from hermes_run_debugger.settings import Settings


@pytest.fixture
def claude_source(tmp_path):
    entries = [
        {"type": "user", "uuid": "u1", "sessionId": "s1", "timestamp": "2026-10-14T10:00:00.000Z",
         "message": {"role": "user", "content": "please fix the failing test"}},
        {"type": "assistant", "uuid": "a1", "parentUuid": "u1", "requestId": "r1", "sessionId": "s1",
         "timestamp": "2026-10-14T10:00:01.000Z",
         "message": {"id": "m1", "role": "assistant", "model": "claude-example",
                     "content": [{"type": "text", "text": "Running the suite."}],
                     "usage": {"input_tokens": 120, "output_tokens": 8}}},
        {"type": "assistant", "uuid": "a2", "parentUuid": "a1", "requestId": "r1", "sessionId": "s1",
         "timestamp": "2026-10-14T10:00:02.000Z",
         "message": {"id": "m1", "role": "assistant", "model": "claude-example",
                     "content": [{"type": "tool_use", "id": "tu1", "name": "Bash",
                                  "input": {"command": "pytest -q"}}],
                     "usage": {"input_tokens": 120, "output_tokens": 12}}},
        {"type": "user", "uuid": "u2", "parentUuid": "a2", "sessionId": "s1",
         "timestamp": "2026-10-14T10:00:03.000Z",
         "message": {"role": "user", "content": [
             {"type": "tool_result", "tool_use_id": "tu1", "is_error": True,
              "content": [{"type": "text", "text": "2 failed, 1 passed"}]}]}},
        {"type": "assistant", "uuid": "a3", "parentUuid": "u2", "requestId": "r2", "sessionId": "s1",
         "timestamp": "2026-10-14T10:00:04.000Z",
         "message": {"id": "m2", "role": "assistant", "model": "claude-example",
                     "content": [{"type": "text", "text": "Still failing."}],
                     "usage": {"input_tokens": 130, "output_tokens": 4}}},
    ]
    path = tmp_path / "session.jsonl"
    path.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")
    return path


def test_clean_profile_workflow(claude_source, tmp_path):
    data_dir = tmp_path / "plugin-data"
    with Services(data_dir=data_dir) as services:
        imported = services.import_sources([claude_source], fmt="claude")
        assert imported and imported[0]["events"] >= 3
        run_id = imported[0]["run_id"]

        timeline = services.timeline_text(run_id)
        assert f"timeline for run {run_id}" in timeline
        assert "Bash" in timeline
        assert "wall-clock order is not causation" in timeline.lower()

        explanation = services.explain_text(run_id)
        assert "hypothes" in explanation.lower(), explanation
        assert "causal findings: none" in explanation.lower()
        assert "root cause" not in explanation.lower()

        replay = services.replay_text(run_id)
        assert "inert replay" in replay.lower()
        assert replay == services.replay_text(run_id), "replay is byte-identical across runs"

        # No sibling plugin, service or daemon is involved: the store is local.
        assert (data_dir / "rundebug.db").exists()

        out = tmp_path / "exports" / "report.md"
        path = services.export_report(run_id, out)
        assert path.exists()
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
        body = path.read_text(encoding="utf-8")
        assert "Limitations" in body
        assert "causal findings: none" in body.lower()


def test_export_is_unreachable_from_slash_and_tool_routes(claude_source, tmp_path):
    data_dir = tmp_path / "plugin-data"
    target = tmp_path / "must-not-exist.md"
    with Services(data_dir=data_dir) as services:
        services.import_sources([claude_source], fmt="claude")

        # Slash route refuses, loudly, and writes nothing.
        reply = handle_slash(f"export --run whatever --out {target}", services)
        assert reply == EXPORT_REFUSAL
        assert "operator-CLI-only" in reply
        assert not target.exists()

        for verb in ("share", "upload"):
            assert handle_slash(f"{verb} --out {target}", services) == EXPORT_REFUSAL
        assert not target.exists()

        # No export tool exists at all.
        assert "rundebug_export" not in TOOL_NAMES
        assert not any("export" in name for name in TOOL_NAMES)

        # The status surface says so explicitly, and names no upload path.
        status = services.status()
        assert "export has no tool, slash or gateway route" in status["honesty"]
        assert tool_status({"run": "x"}, services)


def test_operator_cli_export_path_works_and_reports_its_format(claude_source, tmp_path, capsys):
    data_dir = tmp_path / "plugin-data"
    out = tmp_path / "private" / "report.json"
    with Services(data_dir=data_dir) as services:
        services.import_sources([claude_source], fmt="claude")
        run_id = services.status()["latest_runs"][-1]
        code = run_cli(["export", "--run", run_id, "--out", str(out)], services)
    captured = capsys.readouterr().out
    assert code == 0
    assert "wrote private report" in captured
    assert out.exists()
    json.loads(out.read_text(encoding="utf-8"))


def test_status_reports_implemented_and_refused_lanes(tmp_path):
    with Services(data_dir=tmp_path / "d") as services:
        status = services.status()
        assert status["lanes"]["import"] == "implemented"
        for lane in ("capture", "live_read", "narrative", "experiment"):
            assert status["lanes"][lane] == "not implemented in this build"
        assert status["refusals"] == []

    # Enabling a deferred lane is refused by name — never silently ignored.
    refusing = Settings.from_mapping({"capture_enabled": True, "live_read_enabled": "yes"})
    with Services(data_dir=tmp_path / "d2", settings=refusing) as services:
        refusals = services.status()["refusals"]
        assert len(refusals) == 2
        assert all("not implemented in this build" in item for item in refusals)
        assert services.status()["lanes"]["capture"].startswith("refused")
        with pytest.raises(ImportRefused):
            services.import_sources([tmp_path / "anything.jsonl"])


def test_tools_share_the_same_services_as_the_cli(claude_source, tmp_path):
    data_dir = tmp_path / "plugin-data"
    with Services(data_dir=data_dir) as services:
        imported = services.import_sources([claude_source], fmt="claude")
        run_id = imported[0]["run_id"]
        explanation = tool_explain({"run": run_id}, services)
        assert "hypothes" in explanation.lower(), explanation
        assert explanation == services.explain_text(run_id)
        assert json.loads(tool_status({}, services))["lanes"]["import"] == "implemented"
