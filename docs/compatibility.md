# Compatibility — what this build runs against, and how that was verified

Retrieval date for every host fact below: **2026-10-14**.

## Target host (pinned)

| Fact | Value |
|---|---|
| Host source | `NousResearch/hermes-agent` @ `0e427d788d253630d38a3a51cd76849e73cd6925` |
| Python floor declared by host | `>=3.11,<3.15` (its `pyproject.toml`), while its own `[project].version` is `0.0.0` — the version value is not used to infer a floor |
| Local verification method | `git archive 0e427d…` extracted read-only into a scratch checkout; `hermes_cli/plugins.py` blob hash compared against the pinned Git object (`a652179c…` — identical) |
| Runtime used for the host tests | the pinned checkout's code on `PYTHONPATH`, executed by a Python 3.14.7 interpreter that carries the host's third-party dependencies |

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

1. asserts every host module it imports resolves **inside the pinned checkout**
   (a fork's module silently standing in for the target is how a plugin passes
   locally and fails for a reviewer);
2. asserts the plugin is discovered, loaded with `error is None`, and enabled;
3. asserts the five tools, the slash command and the CLI subcommand are registered
   and that `verify` is untouched;
4. asserts **no hook was registered**;
5. asserts the data directory lands under the disposable home and that no store is
   opened at registration time;
6. exercises a real tool round-trip through the host's `tools.registry`:
   `rundebug_import` → `rundebug_timeline` → `rundebug_explain` → `rundebug_replay`.

## Known limits of this compatibility claim

- Verified on **Linux** only. No macOS or Windows native run is claimed.
- Verified against **one pinned host revision**. Drift invalidates assumptions:
  re-pin and re-run the host tests rather than editing identifiers to fit.
- The host test needs an interpreter that carries the host's third-party
  dependencies; it is skipped, not faked, when `HERMES_HOST_SRC` is absent.
- Surfaces not implemented in this build (capture, selected-session live read,
  model narration, sandboxed experiments) make **no** compatibility claim. Their
  settings are refused by name rather than ignored — see `docs/status.md`.
- A local fork's `hermes plugins validate` is not evidence about the target host:
  it validates against whatever Hermes is installed locally.
