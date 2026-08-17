""" 
security.py — Phase 1: Security Core

Adds, without touching bot.py's existing tables or data:
- Security Event System   (record_event)
- User Behavior Tracking  (user_behavior table)
- Risk Score              (0-100, LOW/MEDIUM/HIGH)
- Audit Log                (audit_log table)

Design constraints (Render Background Worker friendly):
- Standard library only (sqlite3, time, logging, enum).
- No network/API calls, no background threads or processes.
- Every public call does a small number of local SQLite writes and returns.
- Uses CREATE TABLE IF NOT EXISTS only; never touches bot.py's tables. 
- """

import sqlite3
import time
import logging
from enum import Enum

logger = logging.getLogger("modbot.security")

# Shares the same SQLite file as bot.py (bot.py sets DB_PATH = "bot.db").
DB_PATH = "bot.db"


class SecurityEvent(str, Enum):
    SPAM = "SPAM"
    FORBIDDEN_WORD = "FORBIDDEN_WORD"
    BLOCKED_LINK = "BLOCKED_LINK"          # wired up in Phase 2 (Anti-Link)
    MENTION_SPAM = "MENTION_SPAM"          # wired up in Phase 2 (Anti-Mention)
    WARNING = "WARNING"
    MUTE = "MUTE"
    MESSAGE_DELETED = "MESSAGE_DELETED"
    AI_FLAGGED_SPAM = "AI_FLAGGED_SPAM"    # wired up in Phase 5 (Gemini Spam Classifier)


# How much each event type adds to a user's risk score.
EVENT_WEIGHTS = {
    SecurityEvent.SPAM: 15,
    SecurityEvent.FORBIDDEN_WORD: 10,
    SecurityEvent.BLOCKED_LINK: 15,
    SecurityEvent.MENTION_SPAM: 15,
    SecurityEvent.WARNING: 10,
    SecurityEvent.MUTE: 25,
    SecurityEvent.MESSAGE_DELETED: 5,
    SecurityEvent.AI_FLAGGED_SPAM: 20,
}

RISK_LOW_MAX = 29
RISK_MEDIUM_MAX = 69


def risk_level(score: int) -> str:
    """0-29 LOW, 30-69 MEDIUM, 70-100 HIGH."""
    if score <= RISK_LOW_MAX:
        return "LOW"
    if score <= RISK_MEDIUM_MAX:
        return "MEDIUM"
    return "HIGH"


# ---------------- Database ----------------


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def security_db_init():
    """Create Phase 1 tables only. Never drops or modifies existing bot.py tables/data."""
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        event_type TEXT NOT NULL,
        detail TEXT,
        created_at INTEGER NOT NULL
    )""")
    conn.execute("""CREATE INDEX IF NOT EXISTS idx_security_events_chat_user
        ON security_events (chat_id, user_id)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS user_behavior (
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        risk_score INTEGER NOT NULL DEFAULT 0,
        event_count INTEGER NOT NULL DEFAULT 0,
        last_event_at INTEGER,
        PRIMARY KEY (chat_id, user_id)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        detail TEXT,
        created_at INTEGER NOT NULL
    )""")
    conn.commit()
    conn.close()
    logger.info("SECURITY DATABASE: OK")


# ---------------- Risk Score / Behavior Tracking ----------------


def get_risk_score(chat_id: int, user_id: int) -> int:
    conn = _conn()
    row = conn.execute(
        "SELECT risk_score FROM user_behavior WHERE chat_id=? AND user_id=?",
        (chat_id, user_id),
    ).fetchone()
    conn.close()
    return row["risk_score"] if row else 0


def get_behavior(chat_id: int, user_id: int):
    conn = _conn()
    row = conn.execute(
        "SELECT risk_score, event_count, last_event_at FROM user_behavior "
        "WHERE chat_id=? AND user_id=?",
        (chat_id, user_id),
    ).fetchone()
    conn.close()
    if not row:
        return {"risk_score": 0, "event_count": 0, "last_event_at": None, "risk_level": "LOW"}
    return {
        "risk_score": row["risk_score"],
        "event_count": row["event_count"],
        "last_event_at": row["last_event_at"],
        "risk_level": risk_level(row["risk_score"]),
    }


def _bump_behavior(chat_id: int, user_id: int, weight: int) -> int:
    now = int(time.time())
    conn = _conn()
    conn.execute(
        "INSERT INTO user_behavior (chat_id, user_id, risk_score, event_count, last_event_at) "
        "VALUES (?, ?, ?, 1, ?) "
        "ON CONFLICT(chat_id, user_id) DO UPDATE SET "
        "risk_score = MIN(100, risk_score + excluded.risk_score), "
        "event_count = event_count + 1, "
        "last_event_at = excluded.last_event_at",
        (chat_id, user_id, min(100, weight), now),
    )
    conn.commit()
    row = conn.execute(
        "SELECT risk_score FROM user_behavior WHERE chat_id=? AND user_id=?",
        (chat_id, user_id),
    ).fetchone()
    conn.close()
    return row["risk_score"]
    
# ---------------- Security Event Recording ----------------

def record_event(chat_id: int, user_id: int, event_type: SecurityEvent, detail: str = "") -> dict:
    """Record a security event, bump the user's risk score, and write an audit log entry.

    Lightweight and synchronous: a few local SQLite writes, no network calls,
    no background work — safe to call directly from message handlers.
    """
    now = int(time.time())
    conn = _conn()
    conn.execute(
        "INSERT INTO security_events (chat_id, user_id, event_type, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (chat_id, user_id, event_type.value, detail, now),
    )
    conn.commit()
    conn.close()
    
    weight = EVENT_WEIGHTS.get(event_type, 5)
    score = _bump_behavior(chat_id, user_id, weight)
    level = risk_level(score)
    
    write_audit_log(chat_id, user_id, actor="system", action=event_type.value, detail=detail)
    
    logger.info(
        f"SECURITY EVENT | Chat ID: {chat_id} | User ID: {user_id} | "
        f"Type: {event_type.value} | Risk: {score} ({level})"
    )
    return {"event_type": event_type.value, "risk_score": score, "risk_level": level}
    
# ---------------- Audit Log ----------------

def write_audit_log(chat_id: int, user_id, actor: str, action: str, detail: str = ""):
    now = int(time.time())
    conn = _conn()
    conn.execute(
        "INSERT INTO audit_log (chat_id, user_id, actor, action, detail, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (chat_id, user_id, actor, action, detail, now),
    )
    conn.commit()
    conn.close()
    
def get_recent_audit_log(chat_id: int, limit: int = 20):
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE chat_id=? ORDER BY id DESC LIMIT ?",
        (chat_id, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
