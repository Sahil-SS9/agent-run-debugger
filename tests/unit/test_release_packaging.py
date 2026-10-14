"""Release-packaging guards.

Two failure modes this repo must never ship:

1. An exact ``==`` pin in ``[project].dependencies`` / extras. Hermes admits a
   plugin by resolving core's own pins together with the plugin's requirements,
   so one exact pin can refuse admission the moment core bumps that package.
   Reproducibility comes from ``uv.lock``, not from pins.
2. A checkout whose own test modules cannot be collected when the clone folder
   happens to be a valid Python identifier. The repo-root ``__init__.py``
   (the directory-plugin entry point) plus a hyphen-named clone folder can make
   pytest import the same test module under two names; collection then stops
   with an "import file mismatch" before a single test runs.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PIN_RE = re.compile(r"==|~=|!=(?![^,\s]*\*)")


def test_no_exact_pins_in_declared_dependencies():
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    project = data["project"]
    groups = {"project.dependencies": list(project.get("dependencies", []))}
    for extra, specs in (project.get("optional-dependencies") or {}).items():
        groups[f"project.optional-dependencies.{extra}"] = list(specs)

    offenders = []
    for where, specs in groups.items():
        for spec in specs:
            if PIN_RE.search(spec):
                offenders.append(f"{where}: {spec}")
    assert not offenders, f"exact pins are forbidden: {offenders}"


def test_manifest_declares_no_python_dependencies_beside_pyproject():
    """A populated manifest list with an empty [project].dependencies is a trap:
    the pyproject wins and the installer resolves nothing."""
    manifest = (REPO_ROOT / "plugin.yaml").read_text(encoding="utf-8")
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]
    pyproject_empty = not project.get("dependencies")
    if pyproject_empty:
        assert "python_dependencies" not in manifest, (
            "plugin.yaml declares python_dependencies while [project].dependencies is empty; "
            "the pyproject would silently override it"
        )


@pytest.mark.slow_collection
def test_collects_from_an_identifier_named_clone(tmp_path):
    """Collect the suite from a clone folder named like Python code (``myplugin``)."""
    if shutil.which("git") is None:
        pytest.skip("git unavailable")
    files = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    clone = tmp_path / "myplugin"
    clone.mkdir()
    for rel in files:
        src = REPO_ROOT / rel
        if not src.is_file():
            continue
        dest = clone / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)

    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"],
        cwd=clone,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO_ROOT / "src"), "HOME": str(tmp_path)},
        timeout=300,
    )
    combined = proc.stdout + proc.stderr
    assert "import file mismatch" not in combined, combined
    assert "found no collectors" not in combined, combined
    assert proc.returncode == 0, combined
