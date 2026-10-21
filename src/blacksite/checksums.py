"""Checksummed file manifests: written when a bundle is built, checked offline with only the standard library.

Every bundle carries a copy of this file as ``verify.py``, so it must not import anything from Blacksite.
Run it as ``python verify.py [DIR]``; it exits 1 when a file is missing, changed, or not listed.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

MANIFEST = "manifest.json"
FORMAT = "blacksite-bundle/1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_names(root: Path) -> list[str]:
    """Every file under ``root`` but the manifest, as sorted POSIX paths relative to it."""
    names = (path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
    return sorted(name for name in names if name != MANIFEST)


def write_manifest(root: Path, **about: Any) -> dict[str, Any]:
    """List every file under ``root`` with its size and SHA-256 in ``root/manifest.json``."""
    files = {name: {"bytes": (root / name).stat().st_size, "sha256": sha256_file(root / name)}
             for name in file_names(root)}
    manifest = {"format": FORMAT, **about, "files": files}
    (root / MANIFEST).write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return manifest


def verify(root: Path) -> list[str]:
    """Problems with the bundle in ``root``: files missing, changed, or not listed in its manifest."""
    path = root / MANIFEST
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"cannot read {path}: {exc}"]
    expected = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(expected, dict) or manifest.get("format") != FORMAT:
        return [f"{path} is not a {FORMAT} manifest"]
    problems = []
    for name, entry in expected.items():
        file = root / name
        if not file.is_file():
            problems.append(f"missing: {name}")
        elif file.stat().st_size != entry.get("bytes") or sha256_file(file) != entry.get("sha256"):
            problems.append(f"changed: {name}")
    problems += [f"not listed: {name}" for name in file_names(root) if name not in expected]
    return problems


if __name__ == "__main__":
    bundle = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    found = verify(bundle)
    print("\n".join(found) if found else f"OK: every file listed in {bundle / MANIFEST} is present and unchanged")
    sys.exit(1 if found else 0)
