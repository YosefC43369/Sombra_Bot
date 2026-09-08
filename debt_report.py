"""
debt_report.py — Formatting layer for the "เซ็นสินค้า" debt ledger.

Mirrors bb_report.py's / dashboard.py's read-only reporting pattern:
owns no tables of its own, performs no arithmetic of its own beyond
formatting numbers debt_ledger.py already computed, and makes no
network/LLM calls. Every baht figure shown here was produced by
debt_ledger.py's integer arithmetic (add_entry / summarize_by_debtor /
mark_debtor_paid) — this module only turns that data into
Thai-language, Telegram-ready text.

Standard library only. No dependency on gemini.py/OpenAI — this layer
must stay usable even if the AI provider is down (matches the
"AI is optional, arithmetic is not" split described in
debt_ledger.py's own docstring).
"""

from typing import List, Optional

import debt_ledger as dl

_STATUS_TH = {
    dl.EntryStatus.UNPAID.value: "ยังไม่จ่าย",
    dl.EntryStatus.PAID.value: "จ่ายแล้ว",
}
_STATUS_TH_LONG = {
    dl.EntryStatus.UNPAID.value: "ยังไม่ชำระ",
    dl.EntryStatus.PAID.value: "ชำระแล้ว",
}


def _display_date(iso_date: str) -> str:
    """'2026-08-19' -> '19/08/2026' (matches the spec's own examples;
    Gregorian, not Buddhist Era)."""
    y, m, d = iso_date.split("-")
    return f"{d}/{m}/{y}"
    
    
def format_sign_confirmation(entry: dict) -> str:
    """The /sign confirmation reply, matching the exact fields/order
    from the spec's own example message."""
    status_th = _STATUS_TH_LONG.get(entry["status"], entry["status"])
    lines = [
        "✅ บันทึกยอดค้างชำระสำเร็จ",
        f"เลขที่รายการ: #{entry['entry_id']}",
        f"ชื่อ: {entry['debtor_name']}",
    ]
    if entry.get("item_description"):
        lines.append(f"รายการ: {entry['item_description']}")
    lines.append(f"ยอด: {dl.format_baht(entry['amount_satang'])}")
    lines.append(f"วันที่: {_display_date(entry['entry_date'])}")
    lines.append(f"สถานะ: {status_th}")
    return "\n".join(lines)


def format_entries_table(entries: List[dict], title: str = "รายการค้างชำระ") -> str:
    """Plain-text table: วันที่ / ชื่อ / รายการ / จำนวนเงิน / สถานะ, one
    line per entry, matching the spec's example table. Each line also
    carries [#entry_id] at the end so an admin can /paid id <n> the
    exact row without re-typing a name."""
    if not entries:
        return f"{title}: ไม่มีรายการ"
    lines = [f"{title} ({len(entries)} รายการ)", "", "วันที่ | ชื่อ | รายการ | จำนวนเงิน | สถานะ"]
    for e in entries:
        status_th = _STATUS_TH.get(e["status"], e["status"])
        item = e.get("item_description") or "-"
        lines.append(
            f"{_display_date(e['entry_date'])} | {e['debtor_name']} | {item} | "
            f"{dl.format_baht(e['amount_satang'])} | {status_th} [#{e['entry_id']}]"
        )
    return "\n".join(lines)


def format_debt_summary(summary: dict, show_details: bool = True) -> str:
    """The /debt_summary reply: per-person totals table + grand total,
    matching the spec's example layout, plus an optional itemized
    breakdown per person (Requirement #4: 'ควรแสดงรายละเอียดรายการของ
    แต่ละคนด้วยเมื่อเหมาะสม'). Every number here was already computed
    by debt_ledger.summarize_by_debtor() — this function only formats."""
    status_label = _STATUS_TH_LONG.get(summary["status"], summary["status"])
    lines = [
        f"📊 สรุปยอด{status_label} รอบ {_display_date(summary['date_from'])} - "
        f"{_display_date(summary['date_to'])}",
        "",
    ]
    if not summary["by_debtor"]:
        lines.append("ไม่มีรายการในช่วงเวลานี้")
        return "\n".join(lines)

    lines.append("ชื่อ | จำนวนรายการ | ยอดค้างชำระ")
    for d in summary["by_debtor"]:
        lines.append(f"{d['debtor_name']} | {d['count']} | {dl.format_baht(d['total_satang'])}")
    lines.append(
        f"รวมทั้งหมด | {summary['grand_total_count']} | "
        f"{dl.format_baht(summary['grand_total_satang'])}"
    )

    if show_details:
        lines.append("")
        lines.append("รายละเอียดรายการ:")
        for d in summary["by_debtor"]:
            lines.append(f"\n{d['debtor_name']} ({dl.format_baht(d['total_satang'])}):")
            for e in d["entries"]:
                item = e.get("item_description") or "-"
                lines.append(
                    f"  • {_display_date(e['entry_date'])} - {item} - "
                    f"{dl.format_baht(e['amount_satang'])} [#{e['entry_id']}]"
                )

    return "\n".join(lines)


def format_paid_single(entry_id: int, total_satang: int) -> str:
    return f"✅ ปิดยอดรายการ #{entry_id} แล้ว ({dl.format_baht(total_satang)})"


def format_paid_bulk(debtor_name: str, updated_count: int, total_satang: int,
                      date_from: Optional[str] = None, date_to: Optional[str] = None) -> str:
    range_note = ""
    if date_from and date_to:
        range_note = f" (รอบ {_display_date(date_from)} - {_display_date(date_to)})"
    return (
        f"✅ ปิดยอด {debtor_name} แล้ว {updated_count} รายการ "
        f"รวม {dl.format_baht(total_satang)}{range_note}"
    )