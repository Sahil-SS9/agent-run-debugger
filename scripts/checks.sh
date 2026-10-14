#!/usr/bin/env bash
# Reproducible check sequence for this repository.
#
# Usage: scripts/checks.sh [pinned-host-checkout]
#
# The optional argument is a checkout of the *target* host (hermes-agent) used for
# the host tests. Without it, tests/host skips — the suite never fakes host
# coverage. Use an interpreter that carries that host's third-party dependencies.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST_SRC="${1:-${HERMES_HOST_SRC:-}}"
cd "$REPO"

echo "== lock and environment =="
uv sync --locked --extra dev

echo "== unit + adversarial =="
uv run python -m pytest tests/unit tests/adversarial --strict-markers -ra

echo "== integration =="
uv run python -m pytest tests/integration --strict-markers -ra

echo "== platform/surface honesty =="
uv run python -m pytest tests/platform --strict-markers -ra

echo "== host (skips without a target-host checkout) =="
if [ -n "$HOST_SRC" ]; then
  # NOTE: tests/host must run with an interpreter that carries the TARGET host's
  # third-party dependencies; the plugin venv does not have them. Run it with that
  # interpreter and the host checkout on PYTHONPATH, e.g.:
  #   HERMES_HOST_SRC=<host> PYTHONPATH=<host> <host-deps-python> -m pytest tests/host -q
  HERMES_HOST_SRC="$HOST_SRC" PYTHONPATH="$HOST_SRC" \
    uv run python -m pytest tests/host --strict-markers -ra
else
  uv run python -m pytest tests/host --strict-markers -ra || true
  echo "(host tests skipped: pass a target-host checkout as \$1 to run them)"
fi

echo "== lint =="
uv run ruff check .

echo "== build =="
uv run python -m build

echo "== done: no install, no deploy, no publish =="
