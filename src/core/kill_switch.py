from __future__ import annotations

import threading
from typing import Optional


class KillSwitch:
    """A global kill-switch for long-running workers."""

    _instance: Optional["KillSwitch"] = None

    def __init__(self):
        self._lock = threading.Lock()
        self._triggered = False

    @classmethod
    def instance(cls) -> "KillSwitch":
        if cls._instance is None:
            cls._instance = KillSwitch()
        return cls._instance

    def trigger(self) -> None:
        with self._lock:
            self._triggered = True

    def reset(self) -> None:
        with self._lock:
            self._triggered = False

    def is_triggered(self) -> bool:
        with self._lock:
            return self._triggered


def get_kill_switch() -> KillSwitch:
    return KillSwitch.instance()
