"""
expense_report.py — Formatting layer for expense.py (Expense Tracker).

Mirrors wallet_report.py's / debt_report.py's read-only reporting
pattern: owns no tables of its own, performs no arithmetic of its own
beyond formatting numbers expense.py already computed, and makes no
network/LLM calls. Every satang figure shown here was produced by
expense.py's integer arithmetic — this module only turns that data into
Thai-language, Telegram-ready text.

Standard library only. No dependency on gemini.py/OpenAI — this layer
must stay usable even if the AI provider is down (same rationale as
debt_report.py's and wallet_report.py's own docstrings).
"""

from typing import List

import expense as ex

EXPENSE_DENY_TH = {
    "INVALID_AMOUNT": "จำนวนเงินไม่ถูกต้อง (ต้องเป็นตัวเลขมากกว่า 0)",
    "INVALID_CATEGORY": "หมวดหมู่ไม่ถูกต้อง",
    "INVALID_DATE": "รูปแบบวันที่ไม่ถูกต้อง (ใช้ YYYY-MM-DD)",
    "DESCRIPTION_TOO_LONG": f"รายละเอียดยาวเกินไป (จำกัด {ex.MAX_DESCRIPTION_LEN} ตัวอักษร)",
    "NOT_FOUND": "ไม่พบรายการรายจ่ายนี้ (หรือไม่ใช่รายการของคุณ)",
    "NO_CHANGES": "ไม่ได้ระบุสิ่งที่ต้องการแก้ไข",
    "DB_ERROR": "เกิดข้อผิดพลาดกับฐานข้อมูล ลองใหม่อีกครั้ง",
}


def deny_text(reason: str) -> str:
    return "❌ " + EXPENSE_DENY_TH.get(reason, reason)


def category_list_text() -> str:
    """The valid-category help block, shown on INVALID_CATEGORY and in
    /expense's usage message. Built from expense.CATEGORIES so the two
    can never drift apart."""
    lines = ["หมวดหมู่ที่ใช้ได้:"]
    for key, meta in ex.CATEGORIES.items():
        lines.append(f"  {meta['emoji']} {key} ({meta['th']})")
    return "\n".join(lines)


def _display_date(iso_date: str) -> str:
    """'2026-08-19' -> '19/08/2026' (matches debt_report.py's own
    convention; Gregorian, not Buddhist Era)."""
    try:
        y, m, d = iso_date.split("-")
        return f"{d}/{m}/{y}"
    except (ValueError, AttributeError):
        return iso_date


def format_expense_added(data: dict) -> str:
    lines = [
        "✅ บันทึกรายจ่ายแล้ว",
        f"เลขที่รายการ: #{data['expense_id']}",
        f"หมวดหมู่: {ex.category_label(data['category'])}",
        f"จำนวน: {ex.format_baht(data['amount_satang'])}",
    ]
    if data.get("description"):
        lines.append(f"รายละเอียด: {data['description']}")
    lines.append(f"วันที่: {_display_date(data['expense_date'])}")
    return "\n".join(lines)


def format_expense_updated(expense_row: dict) -> str:
    lines = [
        f"✏️ แก้ไขรายการ #{expense_row['expense_id']} แล้ว",
        f"หมวดหมู่: {ex.category_label(expense_row['category'])}",
        f"จำนวน: {ex.format_baht(expense_row['amount_satang'])}",
    ]
    if expense_row.get("description"):
        lines.append(f"รายละเอียด: {expense_row['description']}")
    lines.append(f"วันที่: {_display_date(expense_row['expense_date'])}")
    return "\n".join(lines)


def format_delete_confirm(expense_row: dict) -> str:
    """The two-step delete prompt. This bot has no InlineKeyboard /
    CallbackQuery layer anywhere (verified across the whole repo), so
    confirmation is a typed second command rather than a tap — adding a
    bot-wide callback router just for this would be a much larger
    change than the feature warrants."""
    lines = [
        f"⚠️ ยืนยันการลบรายการ #{expense_row['expense_id']}",
        f"หมวดหมู่: {ex.category_label(expense_row['category'])}",
        f"จำนวน: {ex.format_baht(expense_row['amount_satang'])}",
    ]
    if expense_row.get("description"):
        lines.append(f"รายละเอียด: {expense_row['description']}")
    lines.append(f"วันที่: {_display_date(expense_row['expense_date'])}")
    lines.append("")
    lines.append(f"พิมพ์ /expense_delete {expense_row['expense_id']} confirm เพื่อยืนยัน")
    return "\n".join(lines)


def format_expense_deleted(data: dict) -> str:
    return (
        f"🗑 ลบรายการ #{data['expense_id']} แล้ว "
        f"({ex.format_baht(data['amount_satang'])})"
    )


def format_expense_list(page_data: dict, title: str = "รายจ่ายล่าสุด") -> str:
    """Paginated list, newest first — same layout conventions as
    wallet_report.format_history()."""
    items = page_data["items"]
    if not items:
        return f"{title}: ไม่มีรายการ"

    header = (
        f"📋 {title} (หน้า {page_data['page']}/{page_data['total_pages']}, "
        f"ทั้งหมด {page_data['total_count']} รายการ)"
    )
    lines = [header, ""]
    lines.append("วันที่ | หมวดหมู่ | จำนวนเงิน | รายละเอียด")
    for e in items:
        desc = e.get("description") or "-"
        lines.append(
            f"{_display_date(e['expense_date'])} | {ex.category_label(e['category'])} | "
            f"{ex.format_baht(e['amount_satang'])} | {desc} [#{e['expense_id']}]"
        )
    lines.append("")
    lines.append(f"รวมในช่วงนี้: {ex.format_baht(page_data['total_satang'])}")
    if page_data["total_pages"] > 1:
        lines.append(f"ดูหน้าถัดไป: /expenses page {page_data['page'] + 1}")
    return "\n".join(lines)


def format_category_summary(summary: dict, period_label: str = "") -> str:
    """The /expense_report reply: per-category totals + grand total.
    Every number here was already computed by
    expense.summarize_by_category()."""
    title = "💸 สรุปรายจ่าย"
    if period_label:
        title += f" — {period_label}"
    lines = [title, ""]

    if not summary["by_category"]:
        lines.append("ไม่มีรายการในช่วงเวลานี้")
        return "\n".join(lines)

    for c in summary["by_category"]:
        lines.append(
            f"{ex.category_label(c['category'])}: {ex.format_baht(c['total_satang'])} "
            f"({c['count']} รายการ)"
        )
    lines.append("━━━━━━━━━━━━")
    lines.append(
        f"รวมทั้งหมด: {ex.format_baht(summary['grand_total_satang'])} "
        f"({summary['grand_total_count']} รายการ)"
    )
    return "\n".join(lines)


def format_single_category_report(page_data: dict, summary_row: dict,
                                  period_label: str = "") -> str:
    """/expense_category <cat> — total, count, period, then the matching
    rows. `summary_row` is the one entry for this category out of
    expense.summarize_by_category() (or a zeroed stand-in when there
    are none)."""
    label = ex.category_label(page_data["category"])
    title = f"🏷 รายจ่ายหมวด {label}"
    if period_label:
        title += f" — {period_label}"
    lines = [
        title,
        "",
        f"ยอดรวม: {ex.format_baht(summary_row['total_satang'])}",
        f"จำนวนรายการ: {summary_row['count']}",
    ]
    if page_data.get("date_from") and page_data.get("date_to"):
        lines.append(
            f"ช่วงเวลา: {_display_date(page_data['date_from'])} - "
            f"{_display_date(page_data['date_to'])}"
        )
    if not page_data["items"]:
        lines.append("")
        lines.append("ไม่มีรายการในช่วงเวลานี้")
        return "\n".join(lines)

    lines.append("")
    for e in page_data["items"]:
        desc = e.get("description") or "-"
        lines.append(
            f"  • {_display_date(e['expense_date'])} - {desc} - "
            f"{ex.format_baht(e['amount_satang'])} [#{e['expense_id']}]"
        )
    if page_data["total_pages"] > 1:
        lines.append("")
        lines.append(
            f"(หน้า {page_data['page']}/{page_data['total_pages']}) "
            f"ดูหน้าถัดไป: /expense_category {page_data['category']} page {page_data['page'] + 1}"
        )
    return "\n".join(lines)


def format_admin_summary(summary: dict, period_label: str = "") -> str:
    """Chat-wide per-user totals (Admin only — app.py gates this behind
    its existing is_admin() check)."""
    title = "📊 สรุปรายจ่ายทั้งกลุ่ม"
    if period_label:
        title += f" — {period_label}"
    lines = [title, ""]

    if not summary["by_user"]:
        lines.append("ไม่มีรายการในช่วงเวลานี้")
        return "\n".join(lines)

    lines.append("ผู้ใช้ | จำนวนรายการ | ยอดรวม")
    for u in summary["by_user"]:
        lines.append(
            f"user {u['user_id']} | {u['count']} | {ex.format_baht(u['total_satang'])}"
        )
    lines.append("━━━━━━━━━━━━")
    lines.append(
        f"รวมทั้งหมด: {ex.format_baht(summary['grand_total_satang'])} "
        f"({summary['grand_total_count']} รายการ)"
    )
    return "\n".join(lines)
