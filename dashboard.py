"""
dashboard.py — Phase 6: Admin Dashboard

Read-only summary: pulls together security events, group analytics, and
Gemini usage from tables that security.py / analytics.py / quota.py
already own, formatted as one Thai report. No Telegram/network calls
here (matches security.py/analytics.py/quota.py) — the command handler
and admin-permission check live in app.py.
"""

import sqlite3
import time
import logging

from security import risk_level
from analytics import get_group_summary

logger = logging.getLogger("modbot.dashboard")

DB_PATH = "bot.db"

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _security_summary(chat_id: int, since_ts: int, top_n: int = 5) -> dict:
    conn = _conn()
    event_rows = conn.execute(
        "SELECT event_type, COUNT(*) as n FROM security_events "
        "WHERE chat_id=? AND created_at >= ? GROUP BY event_type ORDER BY n DESC",
        (chat_id, since_ts),
    ).fetchall()
    risky_rows = conn.execute(
        "SELECT user_id, risk_score, event_count FROM user_behavior "
        "WHERE chat_id=? ORDER BY risk_score DESC LIMIT ?",
        (chat_id, top_n),
    ).fetchall()
    conn.close()
    return {
        "events_by_type": [(r["event_type"], r["n"]) for r in event_rows],
        "top_risk_users": [
            {"user_id": r["user_id"], "risk_score": r["risk_score"],
             "risk_level": risk_level(r["risk_score"]), "event_count": r["event_count"]}
            for r in risky_rows
        ],
    }


def _quota_summary(chat_id: int, top_n: int = 5) -> dict:
    today = time.strftime("%Y-%m-%d", time.gmtime())
    conn = _conn()
    total_row = conn.execute(
        "SELECT COALESCE(SUM(count), 0) as total FROM ai_usage WHERE chat_id=? AND usage_date=?",
        (chat_id, today),
    ).fetchone()
    top_rows = conn.execute(
        "SELECT user_id, count FROM ai_usage WHERE chat_id=? AND usage_date=? ORDER BY count DESC LIMIT ?",
        (chat_id, today, top_n),
    ).fetchall()
    classifier_row = conn.execute(
        "SELECT count FROM ai_classifier_usage WHERE chat_id=? AND usage_date=?",
        (chat_id, today),
    ).fetchone()
    conn.close()
    return {
        "total_requests_today": total_row["total"],
        "top_users_today": [(r["user_id"], r["count"]) for r in top_rows],
        "classifier_calls_today": classifier_row["count"] if classifier_row else 0,
    }


def get_dashboard_data(chat_id: int, hours: int = 24) -> dict:
    since_ts = int(time.time()) - hours * 3600
    return {
        "hours": hours,
        "security": _security_summary(chat_id, since_ts),
        "analytics": get_group_summary(chat_id, top_words=5, top_hours=3),
        "quota": _quota_summary(chat_id),
    }


_EVENT_LABEL_TH = {
    "SPAM": "สแปม", "FORBIDDEN_WORD": "คำต้องห้าม", "BLOCKED_LINK": "ลิงก์ต้องห้าม",
    "MENTION_SPAM": "แท็กสแปม", "WARNING": "คำเตือน", "MUTE": "การปิดเสียง",
    "MESSAGE_DELETED": "ข้อความถูกลบ", "AI_FLAGGED_SPAM": "AI ตรวจพบสแปม",
}


def format_dashboard_message(data: dict) -> str:
    """Formats get_dashboard_data()'s output for Telegram parse_mode='HTML'."""
    lines = [f"📊 <b>สรุปรายงานกลุ่ม ({data['hours']} ชม. ที่ผ่านมา)</b>", ""]

    sec = data["security"]
    lines.append("🛡️ <b>เหตุการณ์ความปลอดภัย</b>")
    if sec["events_by_type"]:
        for event_type, n in sec["events_by_type"]:
            lines.append(f"  • {_EVENT_LABEL_TH.get(event_type, event_type)}: {n}")
    else:
        lines.append("  • ไม่มีเหตุการณ์ในช่วงนี้")

    if sec["top_risk_users"]:
        lines.append("")
        lines.append("⚠️ <b>ผู้ใช้ความเสี่ยงสูงสุด</b>")
        for u in sec["top_risk_users"]:
            lines.append(
                f"  • <code>{u['user_id']}</code> — {u['risk_score']}/100 "
                f"({u['risk_level']}, {u['event_count']} เหตุการณ์)"
            )

    an = data["analytics"]
    lines.append("")
    lines.append("💬 <b>กิจกรรมกลุ่ม (สะสมทั้งหมด)</b>")
    lines.append(f"  • ข้อความทั้งหมด: {an['total_messages']}")
    if an["top_words"]:
        lines.append("  • คำยอดฮิต: " + ", ".join(f"{w}({c})" for w, c in an["top_words"]))
    if an["top_hours"]:
        lines.append("  • ช่วงเวลาคึกคักสุด: " + ", ".join(f"{h}:00 UTC({c})" for h, c in an["top_hours"]))

    q = data["quota"]
    lines.append("")
    lines.append("🤖 <b>การใช้งาน Gemini วันนี้</b>")
    lines.append(f"  • คำขอ /ask ทั้งหมด: {q['total_requests_today']}")
    lines.append(f"  • ตรวจสแปมอัตโนมัติ: {q['classifier_calls_today']} ครั้ง")
    if q["top_users_today"]:
        lines.append("  • ผู้ใช้งานสูงสุด: " + ", ".join(f"{uid}:{c}" for uid, c in q["top_users_today"]))

    return "\n".join(lines)