#!/usr/bin/env python3
"""
State Management — SQLite-backed persistence for findings, tech stack, attack surface.

Tables:
- sessions: scan session metadata
- findings: discovered items with severity
- tech_stack: detected technologies
- attack_surface: open ports, services
- service_queue: pending service interaction checks
- artifacts: downloaded evidence metadata
- tool_actions: exact action identity for multi-pass tools
"""

import sqlite3
import json
import uuid
import os
from datetime import datetime, timezone
from typing import Optional


class ReconStateStore:
    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self._init_tables()

    def _init_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                skill TEXT DEFAULT 'recon-gather',
                steps INTEGER DEFAULT 0,
                max_steps INTEGER DEFAULT 100,
                status TEXT DEFAULT 'running',
                error TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                skill TEXT,
                tool TEXT,
                severity TEXT CHECK(severity IN ('critical','high','medium','low','info')),
                summary TEXT NOT NULL,
                detail TEXT,
                evidence TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS tech_stack (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                host TEXT,
                tech TEXT NOT NULL,
                version TEXT,
                confidence TEXT DEFAULT 'tentative'
            );

            CREATE TABLE IF NOT EXISTS attack_surface (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                host TEXT NOT NULL,
                port INTEGER,
                protocol TEXT,
                service TEXT,
                status TEXT DEFAULT 'open'
            );

            CREATE TABLE IF NOT EXISTS service_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT,
                status TEXT DEFAULT 'pending',
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                source TEXT NOT NULL,
                local_path TEXT NOT NULL,
                category TEXT,
                service TEXT,
                reason TEXT,
                size INTEGER,
                sha256 TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS tool_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                action_key TEXT NOT NULL,
                tool TEXT NOT NULL,
                target TEXT,
                params_json TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                UNIQUE(session_id, action_key)
            );
        """)
        self.conn.commit()

    # --- Sessions ---

    def create_session(self, target: str, max_steps: int = 100) -> str:
        session_id = uuid.uuid4().hex[:12]
        self.conn.execute(
            "INSERT INTO sessions (id, target, max_steps) VALUES (?, ?, ?)",
            (session_id, target, max_steps)
        )
        self.conn.commit()
        return session_id

    def get_session(self, session_id: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        ).fetchone()
        if not row:
            return None
        return dict(row)

    def update_skill(self, session_id: str, skill: str):
        self.conn.execute(
            "UPDATE sessions SET skill = ? WHERE id = ?", (skill, session_id)
        )
        self.conn.commit()

    def increment_steps(self, session_id: str):
        self.conn.execute(
            "UPDATE sessions SET steps = steps + 1 WHERE id = ?", (session_id,)
        )
        self.conn.commit()

    def complete_session(self, session_id: str):
        self.conn.execute(
            "UPDATE sessions SET status = 'completed', completed_at = datetime('now') WHERE id = ?",
            (session_id,)
        )
        self.conn.commit()

    def fail_session(self, session_id: str, error: str):
        self.conn.execute(
            "UPDATE sessions SET status = 'failed', error = ?, completed_at = datetime('now') WHERE id = ?",
            (error, session_id)
        )
        self.conn.commit()

    # --- Findings ---

    def add_finding(self, session_id: str, skill: str, tool: str,
                    severity: str, summary: str, detail: str = "",
                    evidence: str = ""):
        self.conn.execute(
            """INSERT INTO findings (session_id, skill, tool, severity, summary, detail, evidence)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (session_id, skill, tool, severity, summary, detail, evidence)
        )
        self.conn.commit()

    def get_recent_findings(self, session_id: str, limit: int = 5) -> list[dict]:
        rows = self.conn.execute(
            """SELECT severity, tool, summary, skill, created_at
               FROM findings
               WHERE session_id = ?
               ORDER BY
                 CASE severity
                   WHEN 'critical' THEN 0
                   WHEN 'high' THEN 1
                   WHEN 'medium' THEN 2
                   WHEN 'low' THEN 3
                   WHEN 'info' THEN 4
                 END,
                 created_at DESC
               LIMIT ?""",
            (session_id, limit)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_all_findings(self, session_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY created_at",
            (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def count_by_severity(self, session_id: str) -> dict:
        rows = self.conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings WHERE session_id = ? GROUP BY severity",
            (session_id,)
        ).fetchall()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for r in rows:
            counts[r["severity"]] = r["cnt"]
        return counts

    # --- Tech Stack ---

    def update_tech_stack(self, session_id: str, host: str,
                          tech: str, version: str = "",
                          confidence: str = "tentative"):
        self.conn.execute(
            "INSERT INTO tech_stack (session_id, host, tech, version, confidence) VALUES (?, ?, ?, ?, ?)",
            (session_id, host, tech, version, confidence)
        )
        self.conn.commit()

    def get_tech_summary(self, session_id: str) -> str:
        rows = self.conn.execute(
            "SELECT DISTINCT tech, version FROM tech_stack WHERE session_id = ?",
            (session_id,)
        ).fetchall()
        if not rows:
            return ""
        return ", ".join(f"{r['tech']} {r['version'] or ''}" for r in rows)

    # --- Attack Surface ---

    def add_surface_item(self, session_id: str, host: str,
                         port: int, protocol: str = "tcp",
                         service: str = ""):
        existing = self.conn.execute(
            """
            SELECT id FROM attack_surface
            WHERE session_id = ? AND host = ? AND port = ? AND protocol = ? AND service = ?
            """,
            (session_id, host, port, protocol, service),
        ).fetchone()
        if existing:
            return
        self.conn.execute(
            "INSERT INTO attack_surface (session_id, host, port, protocol, service) VALUES (?, ?, ?, ?, ?)",
            (session_id, host, port, protocol, service)
        )
        self.conn.commit()

    def get_surface_summary(self, session_id: str) -> dict:
        ports = self.conn.execute(
            "SELECT DISTINCT port, service FROM attack_surface WHERE session_id = ? ORDER BY port, service",
            (session_id,)
        ).fetchall()
        items = [dict(r) for r in ports]
        return {
            "ports": [f"{r['port']}/{r['service']}" for r in ports],
            "items": items,
            "count": len(ports)
        }

    # --- Service Queue ---

    def queue_service_check(self, session_id: str, host: str,
                            port: int, service: str = ""):
        # Avoid duplicates
        existing = self.conn.execute(
            "SELECT id FROM service_queue WHERE session_id = ? AND host = ? AND port = ? AND status = 'pending'",
            (session_id, host, port)
        ).fetchone()
        if not existing:
            self.conn.execute(
                "INSERT INTO service_queue (session_id, host, port, service) VALUES (?, ?, ?, ?)",
                (session_id, host, port, service)
            )
            self.conn.commit()

    def get_pending_checks(self, session_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM service_queue WHERE session_id = ? AND status = 'pending' ORDER BY created_at",
            (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def mark_check_done(self, check_id: int):
        self.conn.execute(
            "UPDATE service_queue SET status = 'done' WHERE id = ?", (check_id,)
        )
        self.conn.commit()

    # --- Artifacts ---

    def add_artifact(self, session_id: str, item: dict):
        self.conn.execute(
            """
            INSERT INTO artifacts (session_id, source, local_path, category, service, reason, size, sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                item.get("source", ""),
                item.get("local_path", ""),
                item.get("category", ""),
                item.get("service", ""),
                item.get("reason", ""),
                int(item.get("size") or 0),
                item.get("sha256", ""),
            ),
        )
        self.conn.commit()

    def get_artifacts(self, session_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM artifacts WHERE session_id = ? ORDER BY created_at", (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Tool Actions ---
    # Exact action dedup prevents false skips when one tool legitimately runs
    # multiple times with different targets/params.

    def add_tool_action(self, session_id: str, action_key: str, tool: str, target: str = "", params: Optional[dict] = None):
        self.conn.execute(
            """
            INSERT OR IGNORE INTO tool_actions (session_id, action_key, tool, target, params_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, action_key, tool, target or "", json.dumps(params or {}, sort_keys=True)),
        )
        self.conn.commit()

    def has_tool_action(self, session_id: str, action_key: str) -> bool:
        row = self.conn.execute(
            "SELECT id FROM tool_actions WHERE session_id = ? AND action_key = ?",
            (session_id, action_key),
        ).fetchone()
        return row is not None

    def get_tool_actions(self, session_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM tool_actions WHERE session_id = ? ORDER BY created_at",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # --- Cleanup ---

    def close(self):
        self.conn.close()
