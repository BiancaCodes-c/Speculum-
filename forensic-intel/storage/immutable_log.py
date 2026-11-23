"""Immutable security log.

Append-only, hash-chained security log. Each entry carries the
hash of the one before it, so an edited or deleted entry breaks
the chain and shows itself.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union
import uuid


@dataclass
class LogEntry:
    """A single immutable record."""
    index: int
    timestamp: str                          # ISO-8601
    event_type: str
    payload: Dict[str, Any]
    prev_hash: str
    entry_hash: str
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogEntry":
        return cls(**data)


class ImmutableLog:
    """Append-only, hash-chained log.

    Storage is a simple JSON-lines file by default so it is easy to
    inspect and does not require a database. The chain is verified
    on every read and after every append.
    """

    GENESIS_HASH = "0" * 64

    def __init__(self, path: Union[str, Path] = "speculum_evidence.jsonl"):
        self.path = Path(path)
        self._entries: List[LogEntry] = []
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, event_type: str, payload: Dict[str, Any]) -> LogEntry:
        """Append a new entry. Returns the created LogEntry."""
        prev_hash = self._entries[-1].entry_hash if self._entries else self.GENESIS_HASH
        index = len(self._entries)

        entry = LogEntry(
            index=index,
            timestamp=datetime.utcnow().isoformat() + "Z",
            event_type=event_type,
            payload=payload,
            prev_hash=prev_hash,
            entry_hash="",  # filled below
        )
        entry.entry_hash = self._compute_hash(entry)

        self._entries.append(entry)
        self._persist(entry)
        return entry

    def verify(self) -> bool:
        """Return True if the entire chain is intact."""
        if not self._entries:
            return True

        expected_prev = self.GENESIS_HASH
        for entry in self._entries:
            if entry.prev_hash != expected_prev:
                return False
            if self._compute_hash(entry) != entry.entry_hash:
                return False
            expected_prev = entry.entry_hash
        return True

    def verify_or_raise(self) -> None:
        if not self.verify():
            raise ValueError("Immutable log chain is broken — evidence may have been tampered with.")

    def get(self, index: int) -> Optional[LogEntry]:
        if 0 <= index < len(self._entries):
            return self._entries[index]
        return None

    def latest(self, n: int = 1) -> List[LogEntry]:
        if n <= 0:
            return []
        return self._entries[-n:]

    def filter(self, event_type: Optional[str] = None) -> List[LogEntry]:
        if event_type is None:
            return list(self._entries)
        return [e for e in self._entries if e.event_type == event_type]

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self) -> Iterator[LogEntry]:
        return iter(self._entries)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _compute_hash(self, entry: LogEntry) -> str:
        """Hash of everything except entry_hash itself."""
        material = {
            "index": entry.index,
            "timestamp": entry.timestamp,
            "event_type": entry.event_type,
            "payload": entry.payload,
            "prev_hash": entry.prev_hash,
            "entry_id": entry.entry_id,
        }
        raw = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _persist(self, entry: LogEntry) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict(), separators=(",", ":")) + "\n")

    def _load(self) -> None:
        if not self.path.exists():
            return
        loaded: List[LogEntry] = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                loaded.append(LogEntry.from_dict(data))
        self._entries = loaded
        # Fail fast if the on-disk chain is already broken
        if not self.verify():
            raise ValueError(
                f"Loaded log at {self.path} has a broken hash chain."
            )


# Convenience functions matching the original stubs
def append_entry(
    event_type: str,
    payload: Dict[str, Any],
    log: Optional[ImmutableLog] = None,
    path: Union[str, Path] = "speculum_evidence.jsonl",
) -> LogEntry:
    if log is None:
        log = ImmutableLog(path)
    return log.append(event_type, payload)


def verify_chain(
    log: Optional[ImmutableLog] = None,
    path: Union[str, Path] = "speculum_evidence.jsonl",
) -> bool:
    if log is None:
        log = ImmutableLog(path)
    return log.verify()
