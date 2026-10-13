import sqlite3
import os
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "agentguard_audit.db")

def compute_canonical_hash(tool_name: str, tool_args: Dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 hash for tool arguments."""
    canonical_json = json.dumps({"tool_name": tool_name, "tool_args": tool_args}, sort_keys=True)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

def init_db():
    """Initializes SQLite database schemas for pending approvals, audit history, and security evaluations."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Pending Approvals Table for Human-in-the-Loop workflows
    cursor.execute("""
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
    """)
    
    # 2. Historical audit of executed/rejected tools
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        approval_id TEXT,
        tool_name TEXT NOT NULL,
        tool_args TEXT NOT NULL,
        decision TEXT NOT NULL,
        result TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )
    """)

    # 3. Dedicated Security Evaluation Audit Log (Threat Matrix)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        file_name TEXT,
        user_prompt TEXT NOT NULL,
        verdict TEXT NOT NULL,
        reason TEXT NOT NULL
    )
    """)
    
    conn.commit()
    conn.close()

def save_pending_approval(
    approval_id: str,
    tool_name: str,
    tool_args: Dict[str, Any],
    reason: str,
    risk_level: str,
    provenance_source: str
) -> str:
    init_db()
    args_hash = compute_canonical_hash(tool_name, tool_args)
    created_at = datetime.utcnow().isoformat()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO pending_approvals 
    (approval_id, tool_name, tool_args, args_hash, reason, risk_level, provenance_source, created_at, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        approval_id,
        tool_name,
        json.dumps(tool_args),
        args_hash,
        reason,
        risk_level,
        provenance_source,
        created_at,
        "PENDING"
    ))
    conn.commit()
    conn.close()
    return args_hash

def get_all_pending_approvals() -> List[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT approval_id, tool_name, tool_args, args_hash, reason, risk_level, provenance_source, created_at, status FROM pending_approvals WHERE status = 'PENDING'")
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    now = datetime.utcnow()
    for r in rows:
        created_time = datetime.fromisoformat(r[7])
        if now - created_time > timedelta(minutes=10):
            continue  # Expired approval
        results.append({
            "approval_id": r[0],
            "tool_name": r[1],
            "tool_args": json.loads(r[2]),
            "args_hash": r[3],
            "reason": r[4],
            "risk_level": r[5],
            "provenance_source": r[6],
            "created_at": r[7],
            "status": r[8]
        })
    return results

def update_approval_status(approval_id: str, status: str):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE pending_approvals SET status = ? WHERE approval_id = ?", (status, approval_id))
    conn.commit()
    conn.close()

def log_audit_event(approval_id: str, tool_name: str, tool_args: Dict[str, Any], decision: str, result: str):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO audit_history (approval_id, tool_name, tool_args, decision, result, timestamp)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        approval_id,
        tool_name,
        json.dumps(tool_args),
        decision,
        result,
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()

def log_security_evaluation(
    verdict: str,
    reason: str,
    user_prompt: str = "",
    file_name: Optional[str] = None,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Logs every security evaluation event into SQLite security_audit_logs.
    Fields: Timestamp, File Name, User Prompt, Verdict (ALLOW/REVIEW/BLOCK), Reason.
    """
    init_db()
    if not timestamp:
        timestamp = datetime.utcnow().isoformat() + "Z"
    
    verdict_str = str(verdict).upper()
    if "BLOCK" in verdict_str:
        clean_verdict = "BLOCK"
    elif "REVIEW" in verdict_str:
        clean_verdict = "REVIEW"
    else:
        clean_verdict = "ALLOW"

    fname = file_name if file_name else "N/A"
    prompt_val = user_prompt if user_prompt else ""
    reason_val = reason if reason else ""

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO security_audit_logs (timestamp, file_name, user_prompt, verdict, reason)
    VALUES (?, ?, ?, ?, ?)
    """, (timestamp, fname, prompt_val, clean_verdict, reason_val))
    conn.commit()
    row_id = cursor.lastrowid
    conn.close()

    return {
        "id": row_id,
        "timestamp": timestamp,
        "file_name": fname,
        "user_prompt": prompt_val,
        "verdict": clean_verdict,
        "reason": reason_val
    }

def get_security_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves the last N recorded security events from SQLite ordered by most recent."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, timestamp, file_name, user_prompt, verdict, reason
    FROM security_audit_logs
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

class AuditLogger:
    """Lightweight persistent SQLite audit logger for security evaluations."""
    @staticmethod
    def log_evaluation(
        verdict: str,
        reason: str,
        user_prompt: str = "",
        file_name: Optional[str] = None,
        timestamp: Optional[str] = None
    ) -> Dict[str, Any]:
        return log_security_evaluation(
            verdict=verdict,
            reason=reason,
            user_prompt=user_prompt,
            file_name=file_name,
            timestamp=timestamp
        )

    @staticmethod
    def get_recent_logs(limit: int = 50) -> List[Dict[str, Any]]:
        return get_security_audit_logs(limit=limit)

audit_logger = AuditLogger()
