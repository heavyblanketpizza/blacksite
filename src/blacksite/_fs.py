"""File operations that behave the same on Windows, macOS, and Linux."""

from __future__ import annotations

import contextlib
import os
import time
from pathlib import Path


def replace(source: Path, target: Path, attempts: int = 20) -> None:
    """Atomically move ``source`` over ``target``.

    On Windows a replace fails while another process has ``target`` open (a reader, a
    virus scanner, the search indexer). Those holds are brief, so retry for up to ~2 s.
    """
    for attempt in range(attempts):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.1)


def remove_quietly(path: Path) -> None:
    """Delete a file if possible; a file still open elsewhere (Windows) is left for later."""
    with contextlib.suppress(OSError):
        path.unlink(missing_ok=True)
