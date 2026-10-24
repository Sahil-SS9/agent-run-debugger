"""Agent Run Debugger — local-first evidence debugger for agent runs.

Domain core is host-neutral: nothing in this package imports Hermes internals.
Host mapping lives in :mod:`hermes_run_debugger.adapters.hermes`; the domain
modules take plain paths, records and settings.

Importing this package must have no side effects.
"""

from __future__ import annotations

__version__ = "0.1.1"

__all__ = ["__version__"]
