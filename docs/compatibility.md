# Compatibility — what this build runs against, and how that was verified

Retrieval date for every host fact below: **2026-10-14**.

## Target host (pinned)

| Fact | Value |
|---|---|
| Host source | `NousResearch/hermes-agent` @ `0e427d788d253630d38a3a51cd76849e73cd6925`, extracted read-only via `git archive` and verified byte-identical (blob hash `a652179c…` for `hermes_cli/plugins.py`) |
| Python floor declared by host | `>=3.11,<3.15` (its `pyproject.toml`), while its own `[project].version` is `0.0.0` — the version value is not used to infer a floor |
| Host-lane interpreter | recorded per run: `tests/host` writes `host-interpreter-identity.json` (interpreter path, version, platform, host source, host-helper path, third-party origin) into `HOST_EVIDENCE_DIR`, and the gate prints it. A run in the plugin venv is a **BLOCKED** result, asserted as such |
| Host dependency provisioning | `scripts/host-test-env.sh` — installs the pinned host's own declared dependencies into a throwaway venv. It installs packages, so it runs only with owner approval |
| Gate semantics | `scripts/checks.sh` runs a **fail-fast preflight**: `HERMES_HOST_SRC` and `HERMES_TEST_PYTHON` must both be set, point at a host checkout and an executable interpreter, and that interpreter must be able to import the pinned host's own dependencies — otherwise the gate exits non-zero with `BLOCKED` before any heavy work (no `uv sync`, no build), so it is safe to use as a missing-environment probe. `ALLOW_SKIP_HOST=1` prints `UNVERIFIED` and cannot satisfy a release gate. Failures are never swallowed |

## Plugin contract, verified against that source

- **Distribution path for v1: directory plugin only.** Repo-root `plugin.yaml` +
  `__init__.py`; the host mounts that file as `hermes_plugins.<slug>` with
  `submodule_search_locations=[plugin_dir]` (`hermes_cli/plugins_loader.py::_load_directory_module`),
  which is why the entry point imports the sibling package relatively and falls
  back to the absolute form for dev checkouts. **No pip entry point is declared**:
  one distribution path, not two competing runtime registrations. The wheel is a
  library artefact for a later, separately gated entry-point lane.
- **Manifest version 2**, `kind: standalone`, with `provides_tools`,
  `provides_hooks: []`, `requires_env: []`, `capabilities: []` and a flat
  `config_schema`. `provides_middleware` is deliberately omitted: the host's
  manifest parser reports it as an unknown field (warning, not a load failure)
  and this build registers no middleware.
- **Registration surfaces** (signatures read from the pinned source):
  `ctx.register_tool(name, toolset, schema, handler, …)`,
  `ctx.register_command(name, handler, description, args_hint, argument_mode)`,
  `ctx.register_cli_command(name, help, setup_fn, handler_fn, description)`,
  `ctx.on_unload(callback)`.
- **Settings** are read per call through `ctx.get_config(key, default)`, which
  resolves `plugins.entries.<plugin_id>.settings.<key>`.
- **Storage**: `plugins/plugin_storage.py::plugin_data_dir(name)` resolves
  `get_hermes_home()` on **every call** and creates the directory. Because that
  call has a side effect, this plugin does **not** call it at registration time: the
  adapter passes a resolver, and the directory is resolved and created on the
  first real operation. Nothing is cached across profiles.
- **No hooks are registered.** The host's `pre_tool_call` is fail-closed on
  callback error/timeout (`hermes_cli/plugins_dispatch.py` — a raising or slow
  callback appends a block directive), so an ostensibly passive observer there can
  block the operator's agent. This build therefore registers no hook at all; the
  capture lane is a later phase with its own host-emission tests.
- **Zero privileged capabilities.** No `tools.override`, no `llm.*` override, no
  `gateway.platform_actions`. The manifest declares none and the code probes none.

## Verified by execution, not by reading

`tests/host/test_install_alone.py` (skipped unless `HERMES_HOST_SRC` is set)
loads the pinned host's own `PluginManager` under a disposable `HERMES_HOME` and:

1. builds the set of top-level module names the pinned checkout **itself owns** (every
   top-level `.py` stem and every package directory) and asserts that no loaded module
   under those names resolves outside the pinned checkout — a hand-written allowlist
   would silently miss helpers such as `utils` or `hermes_yaml`;
2. has a **negative control** that injects an outside-pin `hermes_yaml` into
   `sys.modules` and asserts the guard fires, so the guard is proven rather than
   assumed;
3. records the interpreter identity and dependency origins (above): third-party
   packages must resolve from the interpreter's own site-packages, never from the
   plugin repository;
4. asserts the plugin is discovered, loaded with `error is None`, and enabled;
5. asserts the five tools, the slash command and the CLI subcommand are registered
   and that `verify` is untouched;
6. asserts **no hook was registered**;
7. asserts the data directory lands under the disposable home and that no store is
   opened at registration time;
8. exercises a real tool round-trip through the host's `tools.registry`:
   `rundebug_import` → `rundebug_timeline` → `rundebug_explain` → `rundebug_replay`.

What this does **not** prove: real slash-command, CLI-parser or gateway dispatch. The
registry round-trip exercises the tool call path end to end; the slash/CLI surfaces are
covered by unit-level service tests, and a live dispatch test needs an installed profile
(an owner gate).

## Known limits of this compatibility claim

- Verified on **Linux** only. No macOS or Windows native run is claimed.
- Verified against **one pinned host revision**. Drift invalidates assumptions:
  re-pin and re-run the host tests rather than editing identifiers to fit.
- The host lane needs an interpreter that carries the host's third-party
  dependencies. When it does not, the lane reports **BLOCKED** and fails the gate —
  it never skips green and never claims coverage it did not achieve.
- Surfaces not implemented in this build (capture, selected-session live read,
  model narration, sandboxed experiments) make **no** compatibility claim. Their
  settings are refused by name rather than ignored — see `docs/status.md`.
- A local fork's `hermes plugins validate` is not evidence about the target host:
  it validates against whatever Hermes is installed locally.
