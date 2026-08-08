from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def new_id() -> str:
    return str(uuid.uuid4())


def default_db_path() -> Path:
    configured = os.environ.get("BACKSTABBER_DB")
    if configured:
        return Path(configured).expanduser()
    return Path.cwd() / "data" / "backstabber.db"


def encode_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def decode_json(value: Optional[str], fallback: Any = None) -> Any:
    if value in (None, ""):
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


class Database:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path or default_db_path()).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.initialize()

    def initialize(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS engagements (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                scope_cidrs TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                approval_required INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                address TEXT NOT NULL,
                hostname TEXT,
                tags TEXT NOT NULL DEFAULT '[]',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(engagement_id, address),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL,
                dry_run INTEGER NOT NULL DEFAULT 0,
                approval_id TEXT,
                run_after TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_jobs_status_created
                ON jobs(status, created_at);

            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                job_id TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                requested_by TEXT NOT NULL,
                decided_by TEXT,
                requested_at TEXT NOT NULL,
                decided_at TEXT,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_approvals_status_requested
                ON approvals(status, requested_at);

            CREATE TABLE IF NOT EXISTS executions (
                id TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                job_id TEXT,
                operation TEXT NOT NULL,
                status TEXT NOT NULL,
                dry_run INTEGER NOT NULL DEFAULT 0,
                requested_by TEXT NOT NULL,
                requested_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                params TEXT NOT NULL,
                result TEXT,
                error TEXT,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_executions_engagement_requested
                ON executions(engagement_id, requested_at);

            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                metadata TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_ts
                ON audit_log(ts);
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        cur = self.conn.execute(sql, tuple(params))
        self.conn.commit()
        return cur

    def executemany(self, sql: str, params: Iterable[Iterable[Any]]) -> None:
        self.conn.executemany(sql, params)
        self.conn.commit()

    def fetch_one(self, sql: str, params: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
        row = self.conn.execute(sql, tuple(params)).fetchone()
        return dict(row) if row else None

    def fetch_all(self, sql: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
        rows = self.conn.execute(sql, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def audit(
        self,
        actor: str,
        action: str,
        entity_type: str,
        entity_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        entry = {
            "id": new_id(),
            "ts": utc_now(),
            "actor": actor or "system",
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "metadata": metadata or {},
        }
        self.execute(
            """
            INSERT INTO audit_log (id, ts, actor, action, entity_type, entity_id, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry["id"],
                entry["ts"],
                entry["actor"],
                entry["action"],
                entry["entity_type"],
                entry["entity_id"],
                encode_json(entry["metadata"]),
            ),
        )
        return entry
