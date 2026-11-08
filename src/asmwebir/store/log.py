"""Append-only edit log (section 13): the source of truth for replay and memory.

Entries are never updated or deleted. An in-memory list is always kept; when a
path is given the log is mirrored to SQLite.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field


@dataclass
class Entry:
    seq: int
    kind: str  # claim | retract | nogood | conflict | submit | complete
    payload: dict
    time: float = field(default_factory=time.time)


class Log:
    def __init__(self, path: str | None = None):
        self.entries: list[Entry] = []
        self.db = None
        if path:
            self.db = sqlite3.connect(path)
            self.db.execute("CREATE TABLE IF NOT EXISTS log (seq INTEGER PRIMARY KEY, kind TEXT, payload TEXT, time REAL)")
            for seq, kind, payload, t in self.db.execute("SELECT seq, kind, payload, time FROM log ORDER BY seq"):
                self.entries.append(Entry(seq, kind, json.loads(payload), t))

    def append(self, kind: str, payload: dict) -> Entry:
        e = Entry(len(self.entries) + 1, kind, payload)
        self.entries.append(e)
        if self.db is not None:
            self.db.execute("INSERT INTO log VALUES (?, ?, ?, ?)", (e.seq, kind, json.dumps(payload, default=str), e.time))
            self.db.commit()
        return e

    def of(self, kind: str) -> list[Entry]:
        return [e for e in self.entries if e.kind == kind]
