"""Directory-plugin entry point for the Agent Run Debugger.

Hermes loads a directory plugin by mounting this file as ``hermes_plugins.<slug>``
with ``submodule_search_locations=[plugin_dir]``. The plugin directory is NOT on
``sys.path``, so the sibling package must be imported relatively here; the
absolute form covers dev checkouts and installed-package mode.

``register()`` is deliberately the *only* thing that imports the package, and the
import happens inside the function:

* Importing this file has no side effects at all — no host-state read, no file
  write, no capture, no network. That matters for the capability probe, which
  executes ``register()`` in a recording context.
* A caller that imports this file *without* package context (pytest treats a
  repo root holding ``__init__.py`` as a package and imports this module
  standalone) must not explode. A module-level import would fail there; a lazy
  one cannot.
"""

from __future__ import annotations

from typing import Any

__all__ = ["register"]


def register(ctx: Any) -> None:
    """Register this plugin's surfaces. Host contract: ``register(ctx)``."""
    try:  # directory install: this file is mounted as the package root
        from .src.hermes_run_debugger.adapters.hermes import register as _register
    except ImportError:  # dev checkout / installed package
        from hermes_run_debugger.adapters.hermes import register as _register  # type: ignore[no-redef]

    _register(ctx)
