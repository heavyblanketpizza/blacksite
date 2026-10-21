"""Offline install bundles: the wheels, the lock, the example config, model weights, and a checksummed manifest.

A bundle is built from a checkout on a connected computer like the target (same operating
system, CPU, and Python minor version), carried over, verified with the ``verify.py`` it
contains, and installed with ``pip install --no-index``. Its ``README.txt`` has the steps.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import sysconfig
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .checksums import write_manifest


class BundleError(RuntimeError):
    pass


Runner = Callable[[Sequence[str], Path], None]

# The repository, when Blacksite runs from a checkout; bundles are built from source.
CHECKOUT = Path(__file__).resolve().parents[2]
NOTES = "README.txt"


def run_command(command: Sequence[str], cwd: Path) -> None:
    """Run a build tool, showing its output; fail with the command's name when it does."""
    try:
        completed = subprocess.run(list(command), cwd=cwd)
    except OSError as exc:
        raise BundleError(f"Cannot run {command[0]}: {exc}") from None
    if completed.returncode:
        raise BundleError(f"{' '.join(command[:3])} failed with exit code {completed.returncode}")


def build(target: Path, models: Sequence[Path] = (), checkout: Path = CHECKOUT,
          runner: Runner | None = None) -> dict[str, Any]:
    """Write a bundle into ``target``, which must be new or empty; returns its manifest."""
    run = runner or run_command
    if not (checkout / "pyproject.toml").is_file() or not (checkout / "uv.lock").is_file():
        raise BundleError(f"{checkout} is not a Blacksite checkout with uv.lock; bundles are built from source")
    if target.is_dir() and any(target.iterdir()):
        raise BundleError(f"{target} is not empty")
    missing = [str(model) for model in models if not model.exists()]
    if missing:
        raise BundleError(f"Model path not found: {', '.join(missing)}")

    wheels = target / "wheels"
    wheels.mkdir(parents=True, exist_ok=True)
    requirements = target / "requirements.txt"
    run(["uv", "export", "--frozen", "--no-dev", "--all-extras", "--no-emit-project", "--no-hashes",
         "--format", "requirements.txt", "--output-file", str(requirements)], checkout)
    run(["uv", "build", "--wheel", "--out-dir", str(wheels)], checkout)
    # The lock is complete, so no resolving; a dependency without a wheel for this computer
    # fails here rather than at the offline install, where a source build would need the network.
    run([*_pip(), "download", "--requirement", str(requirements), "--dest", str(wheels), "--no-deps",
         "--only-binary=:all:", "--disable-pip-version-check"], checkout)

    shutil.copy2(checkout / "blacksite.example.toml", target / "blacksite.example.toml")
    shutil.copy2(Path(__file__).with_name("checksums.py"), target / "verify.py")
    for model in models:
        destination = target / "models" / model.name
        if model.is_dir():
            shutil.copytree(model, destination)
        else:
            destination.parent.mkdir(exist_ok=True)
            shutil.copy2(model, destination)
    python = f"{sys.version_info.major}.{sys.version_info.minor}"
    platform = sysconfig.get_platform()
    (target / NOTES).write_text(install_notes(python, platform, [model.name for model in models]), encoding="utf-8")
    return write_manifest(target, created=datetime.now(UTC).isoformat(timespec="seconds"), blacksite=__version__,
                          python=python, platform=platform)


def _pip() -> list[str]:
    """pip as installed beside Blacksite, else run by uv as a tool."""
    if importlib.util.find_spec("pip") is not None:
        return [sys.executable, "-m", "pip"]
    return ["uv", "tool", "run", "pip"]


def install_notes(python: str, platform: str, models: Sequence[str]) -> str:
    listed = "\n".join(f"    models/{name}" for name in models) or "    (none)"
    return f"""Blacksite {__version__} offline bundle
Wheels for CPython {python} on {platform}. Install on a computer like the one that built it.

1. Check the files (needs only Python 3):

    python verify.py .

2. Install into a virtual environment:

    python{python} -m venv blacksite
    blacksite/bin/pip install --no-index --find-links wheels --requirement requirements.txt "blacksite[agent,hybrid]"

   On Windows use blacksite\\Scripts\\pip.exe and blacksite\\Scripts\\blacksite.exe.

3. Copy blacksite.example.toml to blacksite.toml, set [model] to your model server, and check it:

    blacksite/bin/blacksite check

Model files in this bundle:
{listed}

Point llama.cpp or vLLM at a model file or folder with `blacksite serve model`; for Ollama,
create the model from a Modelfile whose FROM line names the file.
"""
