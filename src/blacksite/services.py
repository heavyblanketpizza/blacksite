"""The keys, access store, and audit ledger that the web app and the CLI share."""

from __future__ import annotations

import getpass
import time
from dataclasses import dataclass
from typing import Callable

from .audit.ledger import Ledger
from .auth.store import AccessStore
from .config import Settings
from .keys import Keys


@dataclass
class Services:
    settings: Settings
    keys: Keys
    access: AccessStore
    ledger: Ledger

    @classmethod
    def open(cls, settings: Settings, clock: Callable[[], float] = time.time) -> Services:
        keys = Keys(settings.auth.keys_dir)
        access = AccessStore(settings.auth.store_path, keys, settings.auth, clock=clock)
        ledger = Ledger(settings.audit.store_path, keys, settings.audit.checkpoint_every, clock=clock)
        if ledger.head()[0] == 0:
            ledger.append("ledger.created", actor="system", detail={"key_id": keys.key_id})
        return cls(settings, keys, access, ledger)


def cli_actor() -> str:
    """The ledger's name for whoever runs the CLI: the OS account."""
    try:
        return f"cli:{getpass.getuser()}"
    except (KeyError, OSError):  # no passwd entry (containers) or no login name
        return "cli:unknown"
