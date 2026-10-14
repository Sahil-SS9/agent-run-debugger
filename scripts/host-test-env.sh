#!/usr/bin/env bash
# Provision a disposable interpreter for the host lane — recipe, not an action.
#
# The host tests must run against the pinned target host's own code AND an
# interpreter that satisfies that host's dependency declarations (the pinned host
# imports hermes_yaml → ruamel.yaml, among others). Running them in the plugin venv
# produced "missing ruamel", which is a BLOCKED verification, not a plugin defect.
#
# This script INSTALLS PACKAGES into a throwaway venv. It exists so the environment
# can be reproduced by a third party, and it must be reviewed and approved by the
# owner before it is run. Nothing in this repository runs it automatically.
#
# Usage (after approval):
#   scripts/host-test-env.sh <pinned-host-checkout> [work-dir]
#   HERMES_HOST_SRC=<pinned-host-checkout> HERMES_TEST_PYTHON=<work-dir>/venv/bin/python \
#     scripts/checks.sh
set -euo pipefail

HOST_SRC="${1:?usage: host-test-env.sh <pinned-host-checkout> [work-dir]}"
WORK="${2:-/tmp/rundebug-host-env}"

if [ ! -f "$HOST_SRC/hermes_cli/plugins.py" ]; then
  echo "not a hermes-agent checkout: $HOST_SRC" >&2
  exit 2
fi

echo "host source : $HOST_SRC"
echo "work dir    : $WORK"
echo "target host dependency declarations:"
sed -n '/^\[project\]/,/^\[tool/p' "$HOST_SRC/pyproject.toml" | sed -n '/^dependencies/,/^\]/p'

mkdir -p "$WORK"
uv venv --python 3.12 "$WORK/venv"
# Install the pinned host's own declared dependencies, then nothing else. No
# packages are added by this repository, and the plugin is never installed here.
VIRTUAL_ENV="$WORK/venv" uv pip install -r <(python3 - "$HOST_SRC" <<'PY'
import sys, tomllib, pathlib
data = tomllib.loads(pathlib.Path(sys.argv[1], "pyproject.toml").read_text())
for spec in data["project"].get("dependencies", []):
    print(spec)
PY
)

"$WORK/venv/bin/python" -c "import ruamel.yaml, hermes_yaml" 2>/dev/null \
  && echo "provisioned: $WORK/venv/bin/python" \
  || echo "provisioned, but hermes_yaml still does not import — check PYTHONPATH=$HOST_SRC"
