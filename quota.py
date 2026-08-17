"""
quota.py — Phase 4: AI Usage Quota

Daily per-user Gemini usage limits: regular members get a small daily
cap, admins get a much higher (or unlimited) cap, so Gemini API cost
stays predictable once billing is turned on.

Design constraints (matches security.py / analytics.py):
- Standard library only.
- No network/API calls, no background threads.
- CREATE TABLE IF NOT EXISTS only; never touches other modules' tables.
"""

import os
import sqlite3
import time
import logging

logger = logging.getLogger("modbot.quota")

DB_PATH = "bot.db"

# 0 = unlimited. Override via env without touching code.
MEMBER_DAILY_LIMIT = int(os.getenv("AI_MEMBER_DAILY_LIMIT", "10"))
ADMIN_DAILY_LIMIT = int(os.getenv("AI_ADMIN_DAILY_LIMIT", "0"))

# Chat-wide cap on automatic Gemini spam-classifier calls (0 = unlimited).
CLASSIFIER_DAILY_LIMIT = int(os.getenv("AI_CLASSIFIER_DAILY_LIMIT", "300"))


def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def quota_db_init():
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS ai_usage (
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        usage_date TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (chat_id, user_id, usage_date)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS ai_classifier_usage (
        chat_id INTEGER NOT NULL,
        usage_date TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (chat_id, usage_date)
    )""")
    conn.commit()
    conn.close()
    logger.info("QUOTA DATABASE: OK")


def check_and_use_quota(chat_id: int, user_id: int, is_admin: bool):
    """Checks today's usage against the caller's limit.
    Returns (allowed: bool, used_count: int, limit: int) — limit 0 means
    unlimited. Only increments the counter when allowed is True, so a
    blocked request never eats into tomorrow's quota either."""
    limit = ADMIN_DAILY_LIMIT if is_admin else MEMBER_DAILY_LIMIT
    today = time.strftime("%Y-%m-%d", time.gmtime())

    conn = _conn()
    row = conn.execute(
        "SELECT count FROM ai_usage WHERE chat_id=? AND user_id=? AND usage_date=?",
        (chat_id, user_id, today),
    ).fetchone()
    used = row["count"] if row else 0

    if limit > 0 and used >= limit:
        conn.close()
        return False, used, limit

    conn.execute(
        "INSERT INTO ai_usage (chat_id, user_id, usage_date, count) VALUES (?, ?, ?, 1) "
        "ON CONFLICT(chat_id, user_id, usage_date) DO UPDATE SET count = count + 1",
        (chat_id, user_id, today),
    )
    conn.commit()
    conn.close()
    return True, used + 1, limit

def check_and_use_classifier_quota(chat_id: int):
    """Chat-wide daily cap on automatic Gemini spam-classifier calls.
    Same allow-then-increment pattern as check_and_use_quota, but keyed
    by chat only since the classifier runs on incoming messages, not on
    a per-user command. Returns (allowed, used_count, limit)."""
    limit = CLASSIFIER_DAILY_LIMIT
    today = time.strftime("%Y-%m-%d", time.gmtime())

    conn = _conn()
    row = conn.execute(
        "SELECT count FROM ai_classifier_usage WHERE chat_id=? AND usage_date=?",
        (chat_id, today),
    ).fetchone()
    used = row["count"] if row else 0

    if limit > 0 and used >= limit:
        conn.close()
        return False, used, limit

    conn.execute(
        "INSERT INTO ai_classifier_usage (chat_id, usage_date, count) VALUES (?, ?, 1) "
        "ON CONFLICT(chat_id, usage_date) DO UPDATE SET count = count + 1",
        (chat_id, today),
    )
    conn.commit()
    conn.close()
    return True, used + 1, limit
