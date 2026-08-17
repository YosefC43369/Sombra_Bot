"""
analytics.py — Phase 3: Group-Level Behavior Analytics (aggregate only)

Tracks group-wide word frequency and active-hour patterns for admin
strategy/planning use. Deliberately aggregate-only — no per-user
breakdown, no verbatim message archive.

Design constraints (matches security.py):
- Standard library only, plus optional pythainlp for real Thai word
  segmentation (falls back to phrase-level counting if not installed).
- No network/API calls, no background threads.
- CREATE TABLE IF NOT EXISTS only; never touches other modules' tables.
"""

import sqlite3
import time
import re
import logging

logger = logging.getLogger("modbot.analytics")

DB_PATH = "bot.db"

STOPWORDS = {
    "ครับ", "ค่ะ", "ค่า", "จ้า", "จ้ะ", "นะ", "น่ะ", "อ่ะ", "อะ",
    "ที่", "และ", "แล้ว", "ก็", "ไป", "มา", "ให้", "ได้", "ไม่",
    "เป็น", "อยู่", "จะ", "มี", "คือ", "กับ", "ของ", "นี้", "นั้น",
    "ใน", "ว่า", "แต่", "หรือ", "ยัง", "ทำ", "เอา", "ดู", "บ้าง",
    "กัน", "เลย", "มาก", "ด้วย", "จาก", "ต้อง", "อย่าง", "ทุก",
    "คน", "พวก", "ควย", "สัตว์นรก", "หวีด", "กัญชา", "น้ำเขียว",
    "the", "a", "is", "are", "to", "of", "and",
}

WORD_RE = re.compile(r"[\w\u0E00-\u0E7F]+", re.UNICODE)

# Thai has no spaces between words, so plain regex splitting can only
# chunk text into whole phrases, not real words (confirmed by testing).
# Use pythainlp for real segmentation when it's installed; otherwise
# fall back to phrase-level counting and say so once in the log.
try:
    from pythainlp.tokenize import word_tokenize as _thai_word_tokenize
    _HAS_PYTHAINLP = True
except ImportError:
    _HAS_PYTHAINLP = False
    logger.warning(
        "pythainlp not installed — group_word_stats will count whole "
        "space-delimited phrases, not individual Thai words. "
        "Install with: pip install pythainlp"
    )
    
    
def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
    
    
def analytics_db_init():
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS group_activity_hours (
        chat_id INTEGER NOT NULL,
        hour INTEGER NOT NULL,
        message_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (chat_id, hour)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS group_word_stats (
        chat_id INTEGER NOT NULL,
        word TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (chat_id, word)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS group_activity_summary (
        chat_id INTEGER PRIMARY KEY,
        total_messages INTEGER NOT NULL DEFAULT 0,
        first_recorded_at INTEGER,
        last_recorded_at INTEGER
    )""")
    conn.commit()
    conn.close()
    logger.info("ANALYTICS DATABASE: OK")
    
    
def _extract_words(text:str):
    if _HAS_PYTHAINLP:
        raw_tokens = _thai_word_tokenize(text, engine="newmm")
    else:
        raw_tokens = WORD_RE.findall(text)
    tokens = [t.strip().lower() for t in raw_tokens]
    return [t for t in tokens if len(t) >= 2 and t not in STOPWORDS]
    
def record_message_activity(chat_id: int, text: str, _now=None):
    """Aggregate-only: bumps the group's word-frequency table and
    active-hour histogram. No per-user data, no verbatim message log."""
    now = _now if _now is not None else int(time.time())
    hour = time.gmtime(now).tm_hour  # UTC hour bucket (0-23)
    words = _extract_words(text)
    
    conn = _conn()
    conn.execute(
        "INSERT INTO group_activity_summary (chat_id, total_messages, first_recorded_at, last_recorded_at) "
        "VALUES (?, 1, ?, ?) "
        "ON CONFLICT(chat_id) DO UPDATE SET "
        "total_messages = total_messages + 1, last_recorded_at = excluded.last_recorded_at",
        (chat_id, now, now),
    )
    conn.execute(
        "INSERT INTO group_activity_hours (chat_id, hour, message_count) VALUES (?, ?, 1) "
        "ON CONFLICT(chat_id, hour) DO UPDATE SET message_count = message_count + 1",
        (chat_id, hour),
    )
    for word in words:
        conn.execute(
            "INSERT INTO group_word_stats (chat_id, word, count) VALUES (?, ?, 1) "
            "ON CONFLICT(chat_id, word) DO UPDATE SET count = count + 1",
            (chat_id, word),
        )
    conn.commit()
    conn.close()
    
def get_group_summary(chat_id: int, top_words: int = 10, top_hours: int = 5) -> dict:
    conn = _conn()
    summary_row = conn.execute(
        "SELECT total_messages, first_recorded_at, last_recorded_at "
        "FROM group_activity_summary WHERE chat_id=?",
        (chat_id,),
    ).fetchone()
    word_rows = conn.execute(
        "SELECT word, count FROM group_word_stats WHERE chat_id=? "
        "ORDER BY count DESC LIMIT ?",
        (chat_id, top_words),
    ).fetchall()
    hour_rows = conn.execute(
        "SELECT hour, message_count FROM group_activity_hours WHERE chat_id=? "
        "ORDER BY message_count DESC LIMIT ?",
        (chat_id, top_hours),
    ).fetchall()
    conn.close()

    return {
        "total_messages": summary_row["total_messages"] if summary_row else 0,
        "first_recorded_at": summary_row["first_recorded_at"] if summary_row else None,
        "top_words": [(r["word"], r["count"]) for r in word_rows],
        "top_hours": [(r["hour"], r["message_count"]) for r in hour_rows],
    }
