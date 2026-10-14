"""D0.1 — install-alone against a real Hermes host.

This is the only test that executes host code. It is skipped unless
``HERMES_HOST_SRC`` names a checkout of the target host, and it refuses to pass if
any host module resolves outside that checkout (a fork's module silently standing
in for the pinned source is exactly how a plugin "passes" locally and fails for a
reviewer).

Run it with the interpreter that carries the host's third-party dependencies, for
example:

    HERMES_HOST_SRC=<pinned-host-checkout> PYTHONPATH=<pinned-host-checkout> \\
        <python-with-host-deps> -m pytest tests/host -q
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HOST_SRC = os.environ.get("HERMES_HOST_SRC", "").strip()
PLUGIN_KEY = "agent-run-debugger"

pytestmark = pytest.mark.skipif(
    not HOST_SRC or not Path(HOST_SRC, "hermes_cli", "plugins.py").is_file(),
    reason="HERMES_HOST_SRC is not set to a target-host checkout",
)


def _tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return [line for line in result.stdout.split() if line]


@pytest.fixture
def host_home(tmp_path):
    """A disposable HERMES_HOME with this plugin installed as a directory plugin."""
    home = tmp_path / "hermes-home"
    plugin_dir = home / "plugins" / PLUGIN_KEY
    plugin_dir.mkdir(parents=True)
    for rel in _tracked_files():
        source = REPO_ROOT / rel
        if not source.is_file():
            continue
        target = plugin_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    (home / "config.yaml").write_text(f"plugins:\n  enabled:\n    - {PLUGIN_KEY}\n", encoding="utf-8")
    return home


def _load_host(monkeypatch, host_home):
    """Import the pinned host source and load plugins under a disposable home."""
    sys.path.insert(0, HOST_SRC)
    try:
        import hermes_cli.plugins as plugins_module
    finally:
        if sys.path and sys.path[0] == HOST_SRC:
            sys.path.pop(0)

    # Prove the harness is the pinned checkout, not a fork's copy or a mixed tree.
    resolved = Path(plugins_module.__file__).resolve()
    assert resolved.is_relative_to(Path(HOST_SRC).resolve()), (
        f"hermes_cli.plugins resolved outside the pinned host checkout: {resolved}"
    )
    for name, module in list(sys.modules.items()):
        module_file = getattr(module, "__file__", None)
        if not module_file:
            continue
        if name.split(".")[0] in {"hermes_cli", "hermes_constants", "agent", "tools", "plugins"}:
            assert Path(module_file).resolve().is_relative_to(Path(HOST_SRC).resolve()), (
                f"host module {name} resolved outside the pinned checkout: {module_file}"
            )

    monkeypatch.setenv("HERMES_HOME", str(host_home))
    return plugins_module


def test_plugin_registers_alone_on_a_real_host(monkeypatch, host_home, tmp_path):
    plugins_module = _load_host(monkeypatch, host_home)
    manager = plugins_module.PluginManager()
    manager.discover_and_load()

    loaded = manager._plugins.get(PLUGIN_KEY)
    assert loaded is not None, f"plugin not discovered; loaded keys: {sorted(manager._plugins)}"
    assert loaded.error is None, f"plugin failed to load: {loaded.error}"
    assert loaded.enabled is True

    registered = sorted(manager._plugin_tool_names)
    for name in ("rundebug_import", "rundebug_timeline", "rundebug_explain",
                 "rundebug_replay", "rundebug_status"):
        assert name in registered, f"{name} was not registered (got {registered})"

    commands = plugins_module.get_plugin_commands()
    assert "rundebug" in commands
    assert "rundebug_command" in getattr(manager, "_cli_commands", {}), "CLI subcommand missing"

    # No hook is registered by this build. An observer on the host's fail-closed
    # pre_tool_call hook could block the user's agent, so its absence is asserted.
    registered_hooks = [hook for hook, callbacks in manager._hooks.items() if callbacks]
    assert registered_hooks == [], f"unexpected hook registrations: {registered_hooks}"

    # Data lands under the disposable home, not in the operator's real profile.
    from plugins.plugin_storage import plugin_data_dir

    data_dir = plugin_data_dir(PLUGIN_KEY)
    assert str(data_dir).startswith(str(host_home)), data_dir
    assert not data_dir.joinpath("rundebug.db").exists(), "no store is opened at registration time"


def test_tool_round_trip_through_the_host_registry(monkeypatch, host_home, tmp_path):
    plugins_module = _load_host(monkeypatch, host_home)
    manager = plugins_module.PluginManager()
    manager.discover_and_load()

    source = tmp_path / "session.jsonl"
    source.write_text(
        '{"kind": "trace", "schema": "hermes-run-debugger/trace", "version": 1, '
        '"trace_id": "t-host", "run_id": "r-host", "importer": "test", "importer_version": "0.1.0", '
        '"source_format": "event-v1", "source_scope": "explicit-selection", '
        '"created_at": "2026-10-14T10:00:00Z", '
        '"source": {"kind": "file", "ref": "sha256:' + "1" * 64 + '", "name": "session.jsonl"}, '
        '"redaction": {"policy": "minimal-metadata", "applied_count": 0}, '
        '"covered_kinds": ["tool_call"], "unsupported_kinds": [], '
        '"completeness": {"status": "complete", "missing_kinds": [], "notes": []}}\n'
        '{"kind": "attempt", "attempt_id": "att-1", "run_id": "r-host", "parent_attempt_id": null, '
        '"model": "example-model", "provider": "example-provider", "role": "primary", '
        '"branch": "main", "sequence": 0, "started_at": "2026-10-14T10:00:00Z", "ended_at": null, '
        '"outcome": "failed", "unknowns": []}\n'
        '{"kind": "event", "event_id": "e1", "run_id": "r-host", "attempt_id": "att-1", '
        '"span_id": null, "causal_parents": [], "source_sequence": 0, '
        '"wall_time": "2026-10-14T10:00:01Z", "monotonic_ms": 1000, '
        '"clock": {"source": "monotonic", "quality": "high"}, "event_kind": "tool_call", '
        '"reported_status": "failed", "reported_error": "boom", "usage": {}, '
        '"evidence_ref": "ref:e1", "delivered_via": "import", "semantic_provenance": "reported", '
        '"gaps": [], "contradictions": [], "name": "Bash"}\n',
        encoding="utf-8",
    )

    from tools.registry import registry

    imported = str(registry.dispatch("rundebug_import", {"files": [str(source)]}, scope=manager.scope_key))
    assert "r-host" in imported, imported
    timeline = str(registry.dispatch("rundebug_timeline", {"run": "r-host"}, scope=manager.scope_key))
    assert "Bash" in timeline and "wall-clock order is not causation" in timeline.lower()
    explanation = str(registry.dispatch("rundebug_explain", {"run": "r-host"}, scope=manager.scope_key))
    assert "hypothesis" in explanation.lower()
    replay = str(registry.dispatch("rundebug_replay", {"run": "r-host"}, scope=manager.scope_key))
    assert "inert replay" in replay.lower()

    store_file = Path(host_home) / "plugin-data" / PLUGIN_KEY / "rundebug.db"
    assert store_file.exists(), "the tool round trip must persist under the disposable home"
    assert not (tmp_path / "exports").exists(), "no route in this test writes an export"
