"""Directory-plugin entry point for the Agent Run Debugger.

Hermes loads a directory plugin by mounting this file as ``hermes_plugins.<slug>``
with ``submodule_search_locations=[plugin_dir]``. The plugin directory is NOT on
``sys.path``, so the sibling package must be imported relatively here; the
absolute form covers dev checkouts and tests that put the repo root on
``sys.path``.

Import safety: importing this module must have no side effects. No capture, no
network, no file writes, no host-state reads happen at import or registration
time.
"""

from __future__ import annotations

try:  # directory install: plugin dir is the package root
    from .src.hermes_run_debugger.adapters.hermes import register as register
except ImportError:  # dev checkout / installed package
    from hermes_run_debugger.adapters.hermes import register as register  # type: ignore[no-redef]

__all__ = ["register"]
