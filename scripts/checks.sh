#!/usr/bin/env bash
# Reproducible check sequence for this repository.
#
# Usage:
#   HERMES_HOST_SRC=<pinned-host-checkout> \
#   HERMES_TEST_PYTHON=<interpreter-with-host-deps> \
#   scripts/checks.sh
#
# The host lane is REQUIRED here: it is never skipped silently and never swallowed.
# An unset or unusable host environment fails the gate with BLOCKED. For local
# development of the plugin alone, set ALLOW_SKIP_HOST=1 to run the offline suites and
# have the host lane printed as UNVERIFIED — which cannot satisfy a release gate.
#
# docs/compatibility.md records exactly which interpreter and target source the gate
# was last run against; scripts/host-test-env.sh holds the dependency-provisioning
# recipe a verifier runs after owner approval.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

HOST_SRC="${HERMES_HOST_SRC:-}"
HOST_PYTHON="${HERMES_TEST_PYTHON:-}"
ALLOW_SKIP_HOST="${ALLOW_SKIP_HOST:-0}"
EVIDENCE_DIR="${RUNDEBUG_EVIDENCE_DIR:-}"

echo "== lock and environment =="
uv sync --locked --extra dev

echo "== unit + adversarial =="
uv run python -m pytest tests/unit tests/adversarial --strict-markers -ra

echo "== integration =="
uv run python -m pytest tests/integration --strict-markers -ra

echo "== platform/surface honesty (Linux claim-honesty only, NOT native Windows/macOS) =="
uv run python -m pytest tests/platform --strict-markers -ra

echo "== lint =="
uv run ruff check .

echo "== build =="
uv run python -m build

if [ -n "$HOST_SRC" ] && [ -n "$HOST_PYTHON" ]; then
  if [ ! -f "$HOST_SRC/hermes_cli/plugins.py" ]; then
    echo "BLOCKED: HERMES_HOST_SRC=$HOST_SRC does not look like a hermes-agent checkout" >&2
    exit 3
  fi
  if [ ! -x "$HOST_PYTHON" ] && ! command -v "$HOST_PYTHON" >/dev/null 2>&1; then
    echo "BLOCKED: HERMES_TEST_PYTHON=$HOST_PYTHON is not an executable interpreter" >&2
    exit 3
  fi
  echo "== host: target source $HOST_SRC =="
  echo "== host: interpreter $HOST_PYTHON ($("$HOST_PYTHON" -c 'import sys, platform; print(sys.version.split()[0], platform.platform())')) =="
  HERMES_HOST_SRC="$HOST_SRC" \
  PYTHONPATH="$HOST_SRC" \
  HOST_EVIDENCE_DIR="$EVIDENCE_DIR" \
    "$HOST_PYTHON" -m pytest tests/host --strict-markers -ra
else
  if [ "$ALLOW_SKIP_HOST" = "1" ]; then
    echo "UNVERIFIED: host lane NOT run (set HERMES_HOST_SRC and HERMES_TEST_PYTHON to run it)."
    echo "            This result cannot satisfy a release gate."
  else
    echo "BLOCKED: the host lane is required. Set HERMES_HOST_SRC and HERMES_TEST_PYTHON, or" >&2
    echo "         ALLOW_SKIP_HOST=1 to mark it UNVERIFIED explicitly." >&2
    exit 3
  fi
fi

echo "== done: no install, no deploy, no publish =="
