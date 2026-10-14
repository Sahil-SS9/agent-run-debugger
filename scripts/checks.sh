#!/usr/bin/env bash
# Reproducible check sequence for this repository.
#
# Usage:
#   HERMES_HOST_SRC=<pinned-host-checkout> \
#   HERMES_TEST_PYTHON=<interpreter-with-host-deps> \
#   scripts/checks.sh
#
# The host lane is REQUIRED: it is never skipped silently and never swallowed. An unset,
# unusable or under-provisioned host environment fails the gate with BLOCKED **before any
# heavy work** (no `uv sync`, no build), so this script never reports success it did not
# earn and is safe to use as a missing-environment probe. For plugin-only local work, set
# ALLOW_SKIP_HOST=1 to run the offline suites and have the host lane printed as UNVERIFIED
# — which cannot satisfy a release gate.
#
# docs/compatibility.md records exactly which interpreter and target source the gate was
# last run against; scripts/host-test-env.sh holds the dependency-provisioning recipe a
# verifier runs after owner approval. This script installs nothing.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

HOST_SRC="${HERMES_HOST_SRC:-}"
HOST_PYTHON="${HERMES_TEST_PYTHON:-}"
ALLOW_SKIP_HOST="${ALLOW_SKIP_HOST:-0}"
EVIDENCE_DIR="${RUNDEBUG_EVIDENCE_DIR:-}"

host_lane_ready=0

# -- preflight: validate the host lane BEFORE touching the environment ----------------
if [ -n "$HOST_SRC" ] || [ -n "$HOST_PYTHON" ]; then
  if [ -z "$HOST_SRC" ] || [ -z "$HOST_PYTHON" ]; then
    echo "BLOCKED: set BOTH HERMES_HOST_SRC (target host checkout) and HERMES_TEST_PYTHON" >&2
    echo "         (interpreter carrying that host's dependencies)." >&2
    exit 3
  fi
  if [ ! -f "$HOST_SRC/hermes_cli/plugins.py" ]; then
    echo "BLOCKED: HERMES_HOST_SRC=$HOST_SRC does not look like a hermes-agent checkout" >&2
    exit 3
  fi
  if [ ! -x "$HOST_PYTHON" ] && ! command -v "$HOST_PYTHON" >/dev/null 2>&1; then
    echo "BLOCKED: HERMES_TEST_PYTHON=$HOST_PYTHON is not an executable interpreter" >&2
    exit 3
  fi
  if ! "$HOST_PYTHON" -c "import sys; sys.path.insert(0, '$HOST_SRC'); import hermes_yaml" 2>/dev/null; then
    echo "BLOCKED: $HOST_PYTHON cannot import the pinned host's own dependencies" >&2
    echo "         (the pinned host imports hermes_yaml, which needs ruamel). Provision an" >&2
    echo "         interpreter that can, per scripts/host-test-env.sh (owner approval needed)." >&2
    exit 3
  fi
  host_lane_ready=1
else
  if [ "$ALLOW_SKIP_HOST" != "1" ]; then
    echo "BLOCKED: the host lane is required. Set HERMES_HOST_SRC and HERMES_TEST_PYTHON, or" >&2
    echo "         ALLOW_SKIP_HOST=1 to mark it UNVERIFIED explicitly." >&2
    exit 3
  fi
fi

echo "== lock and environment =="
uv sync --locked --extra dev

echo "== unit + adversarial =="
uv run python -m pytest tests/unit tests/adversarial --strict-markers -ra

echo "== integration =="
uv run python -m pytest tests/integration --strict-markers -ra

echo "== platform/surface honesty (Linux claim-honesty only, NOT native Windows/macOS) =="
uv run python -m pytest tests/platform --strict-markers -ra

if [ "$host_lane_ready" = "1" ]; then
  echo "== host: target source $HOST_SRC =="
  echo "== host: interpreter $HOST_PYTHON ($("$HOST_PYTHON" -c 'import sys, platform; print(sys.version.split()[0], platform.platform())')) =="
  HERMES_HOST_SRC="$HOST_SRC" \
  PYTHONPATH="$HOST_SRC" \
  HOST_EVIDENCE_DIR="$EVIDENCE_DIR" \
    "$HOST_PYTHON" -m pytest tests/host --strict-markers -ra
else
  echo "UNVERIFIED: host lane NOT run. This result cannot satisfy a release gate."
fi

echo "== lint =="
uv run ruff check .

echo "== build =="
uv run python -m build

echo "== done: no install, no deploy, no publish =="
