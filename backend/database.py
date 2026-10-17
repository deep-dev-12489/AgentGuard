"""SQLite persistence for AgentGuard approval workflows and audit events."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

_DEFAULT_DB_PATH = Path(__file__).resolve().parent / "agentguard_audit.db"
DB_PATH = Path(os.getenv("AGENTGUARD_DB_PATH", str(_DEFAULT_DB_PATH))).expanduser().resolve()
APPROVAL_TTL = timedelta(minutes=10)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=10.0, isolation_level="DEFERRED")
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout = 10000")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _to_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def compute_canonical_hash(tool_name: str, tool_args: Dict[str, Any]) -> str:
    """Compute stable SHA-256 integrity hash over action name and JSON args."""
    canonical_json = json.dumps(
        {"tool_name": str(tool_name), "tool_args": tool_args},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def init_db() -> None:
    """Create required schemas and supporting indexes if they do not exist."""
    with _connection() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_approvals (
                approval_id TEXT PRIMARY KEY,
                tool_name TEXT NOT NULL,
                tool_args TEXT NOT NULL,
                args_hash TEXT NOT NULL,
                reason TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                provenance_source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                approval_id TEXT,
                tool_name TEXT NOT NULL,
                tool_args TEXT NOT NULL,
                decision TEXT NOT NULL,
                result TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS security_audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                file_name TEXT,
                user_prompt TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reason TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pending_status_created ON pending_approvals(status, created_at)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_security_audit_id ON security_audit_logs(id DESC)")


def save_pending_approval(
    approval_id: str,
    tool_name: str,
    tool_args: Dict[str, Any],
    reason: str,
    risk_level: str,
    provenance_source: str,
) -> str:
    init_db()
    args_hash = compute_canonical_hash(tool_name, tool_args)
    created_at = utc_now_iso()
    with _connection() as conn:
        conn.execute(
            """
            INSERT INTO pending_approvals
              (approval_id, tool_name, tool_args, args_hash, reason, risk_level,
               provenance_source, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING')
            """,
            (
                approval_id,
                tool_name,
                json.dumps(tool_args, sort_keys=True, ensure_ascii=False, allow_nan=False),
                args_hash,
                str(reason)[:2_000],
                str(risk_level)[:30],
                str(provenance_source)[:80],
                created_at,
            ),
        )
    return args_hash


def get_all_pending_approvals() -> List[Dict[str, Any]]:
    """Return non-expired pending approvals and persist expired statuses."""
    init_db()
    now = datetime.now(timezone.utc)
    with _connection() as conn:
        rows = conn.execute(
            """
            SELECT approval_id, tool_name, tool_args, args_hash, reason, risk_level,
                   provenance_source, created_at, status
            FROM pending_approvals
            WHERE status = 'PENDING'
            ORDER BY created_at ASC
            """
        ).fetchall()
        output: List[Dict[str, Any]] = []
        for row in rows:
            try:
                expired = now - _to_utc(row["created_at"]) > APPROVAL_TTL
            except (ValueError, TypeError):
                expired = True
            if expired:
                conn.execute(
                    "UPDATE pending_approvals SET status = 'EXPIRED' WHERE approval_id = ? AND status = 'PENDING'",
                    (row["approval_id"],),
                )
                continue
            try:
                args = json.loads(row["tool_args"])
                if not isinstance(args, dict):
                    args = {}
            except (TypeError, json.JSONDecodeError):
                args = {}
            output.append(
                {
                    "approval_id": row["approval_id"],
                    "tool_name": row["tool_name"],
                    "tool_args": args,
                    "args_hash": row["args_hash"],
                    "reason": row["reason"],
                    "risk_level": row["risk_level"],
                    "provenance_source": row["provenance_source"],
                    "created_at": row["created_at"],
                    "status": row["status"],
                }
            )
        return output


def claim_pending_approval(approval_id: str) -> bool:
    """Atomically claim a pending approval so concurrent reviewers cannot run it twice."""
    init_db()
    with _connection() as conn:
        cursor = conn.execute(
            "UPDATE pending_approvals SET status = 'PROCESSING' "
            "WHERE approval_id = ? AND status = 'PENDING'",
            (approval_id,),
        )
        return cursor.rowcount == 1


def update_approval_status(approval_id: str, status: str) -> bool:
    """Update state and return whether a row was changed."""
    init_db()
    allowed = {"PENDING", "PROCESSING", "APPROVED", "REJECTED", "EXPIRED", "FAILED", "BLOCKED"}
    state = str(status).upper()
    if state not in allowed:
        raise ValueError("Invalid approval status.")
    with _connection() as conn:
        cursor = conn.execute(
            "UPDATE pending_approvals SET status = ? WHERE approval_id = ?",
            (state, approval_id),
        )
        return cursor.rowcount == 1


def log_audit_event(
    approval_id: str,
    tool_name: str,
    tool_args: Dict[str, Any],
    decision: str,
    result: str,
) -> None:
    init_db()
    with _connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_history (approval_id, tool_name, tool_args, decision, result, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(approval_id)[:100],
                str(tool_name)[:120],
                json.dumps(tool_args, sort_keys=True, ensure_ascii=False, allow_nan=False)[:20_000],
                str(decision)[:80],
                str(result)[:4_000],
                utc_now_iso(),
            ),
        )


def log_security_evaluation(
    verdict: str,
    reason: str,
    user_prompt: str = "",
    file_name: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Persist a bounded audit record. Avoid storing unbounded user input."""
    init_db()
    timestamp = timestamp or utc_now_iso()
    raw_verdict = str(verdict).upper()
    if "BLOCK" in raw_verdict or "ERROR" in raw_verdict:
        clean_verdict = "BLOCK"
    elif "REVIEW" in raw_verdict or "PROCESSING" in raw_verdict:
        clean_verdict = "REVIEW"
    else:
        clean_verdict = "ALLOW"

    safe_filename = os.path.basename(file_name or "N/A")[:255]
    prompt_value = str(user_prompt or "")[:4_000]
    reason_value = str(reason or "")[:2_000]
    with _connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO security_audit_logs (timestamp, file_name, user_prompt, verdict, reason)
            VALUES (?, ?, ?, ?, ?)
            """,
            (timestamp, safe_filename, prompt_value, clean_verdict, reason_value),
        )
        row_id = cursor.lastrowid
    return {
        "id": row_id,
        "timestamp": timestamp,
        "file_name": safe_filename,
        "user_prompt": prompt_value,
        "verdict": clean_verdict,
        "reason": reason_value,
    }


def get_security_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Return the newest audit events, with a hard bound on requested rows."""
    init_db()
    bounded_limit = max(1, min(int(limit), 100))
    with _connection() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, file_name, user_prompt, verdict, reason
            FROM security_audit_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()
        return [dict(row) for row in rows]


class AuditLogger:
    """Small adapter used by FastAPI routes."""

    @staticmethod
    def log_evaluation(
        verdict: str,
        reason: str,
        user_prompt: str = "",
        file_name: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        return log_security_evaluation(
            verdict=verdict,
            reason=reason,
            user_prompt=user_prompt,
            file_name=file_name,
            timestamp=timestamp,
        )

    @staticmethod
    def get_recent_logs(limit: int = 50) -> List[Dict[str, Any]]:
        return get_security_audit_logs(limit=limit)


audit_logger = AuditLogger()

# Initialize schema at import time so the health check can start predictably.
init_db()
