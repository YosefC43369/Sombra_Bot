"""
wallet_report.py — Formatting layer for wallet.py (Wallet / Payment /
Transaction Ledger).

Mirrors debt_report.py's read-only reporting pattern: owns no tables
of its own, performs no arithmetic beyond formatting numbers wallet.py
already computed, and makes no network/LLM calls. Every satang figure
shown here was produced by wallet.py's integer arithmetic — this
module only turns that data into Thai-language, Telegram-ready text.

Standard library only. No dependency on gemini.py/OpenAI — this layer
must stay usable even if the AI provider is down (same rationale as
debt_report.py's own docstring).
"""

from typing import List

import wallet as wt

_TX_TYPE_TH = {
    wt.TxType.DEPOSIT.value: "ฝากเงิน",
    wt.TxType.WITHDRAWAL.value: "ถอนเงิน",
    wt.TxType.TRANSFER_OUT.value: "โอนออก",
    wt.TxType.TRANSFER_IN.value: "โอนเข้า",
    wt.TxType.PAYMENT.value: "ชำระเงิน",
    wt.TxType.REFUND.value: "คืนเงิน",
    wt.TxType.DEBT_PAYMENT.value: "จ่ายหนี้",
    wt.TxType.ADJUSTMENT.value: "ปรับยอดโดย Admin",
}

_TX_STATUS_TH = {
    wt.TxStatus.PENDING.value: "รอดำเนินการ",
    wt.TxStatus.COMPLETED.value: "สำเร็จ",
    wt.TxStatus.CANCELLED.value: "ยกเลิก",
}

_BILL_STATUS_TH = {
    wt.PaymentStatus.PENDING.value: "รอชำระ",
    wt.PaymentStatus.PAID.value: "จ่ายแล้ว",
    wt.PaymentStatus.FAILED.value: "ล้มเหลว",
    wt.PaymentStatus.EXPIRED.value: "หมดอายุ",
    wt.PaymentStatus.CANCELLED.value: "ยกเลิก",
    wt.PaymentStatus.REFUNDED.value: "คืนเงินแล้ว",
}

WALLET_DENY_TH = {
    "INVALID_AMOUNT": "จำนวนเงินไม่ถูกต้อง (ต้องเป็นตัวเลขมากกว่า 0)",
    "INSUFFICIENT_BALANCE": "ยอดเงินในกระเป๋าไม่พอ",
    "NOT_FOUND": "ไม่พบรายการนี้",
    "ALREADY_PROCESSED": "รายการนี้ถูกดำเนินการไปแล้ว",
    "EXPIRED": "รายการนี้หมดอายุแล้ว",
    "FORBIDDEN": "คุณไม่มีสิทธิ์ทำรายการนี้",
    "SELF_PAYMENT_NOT_ALLOWED": "ชำระบิลของตัวเองไม่ได้",
    "SELF_TRANSFER_NOT_ALLOWED": "โอนเงินให้ตัวเองไม่ได้",
    "DB_ERROR": "เกิดข้อผิดพลาดกับฐานข้อมูล ลองใหม่อีกครั้ง",
    "REASON_REQUIRED": "กรุณาระบุเหตุผล",
    "NOT_A_DEPOSIT": "รายการนี้ไม่ใช่รายการฝากเงิน",
    "ENTRY_NOT_FOUND": "ไม่พบรายการค้างชำระนี้",
    "ALREADY_PAID": "รายการนี้จ่ายไปแล้ว",
}


def deny_text(reason: str) -> str:
    return "❌ " + WALLET_DENY_TH.get(reason, reason)


def format_balance(wallet_row: dict) -> str:
    return f"💰 ยอดเงินคงเหลือ: {wt.format_baht(wallet_row['balance_satang'])}"


def format_deposit_requested(tx: dict) -> str:
    return (
        "🧾 ส่งคำขอฝากเงินแล้ว รอ Admin ยืนยัน\n"
        f"เลขที่รายการ: #{tx['transaction_id']}\n"
        f"จำนวน: {wt.format_baht(tx['amount_satang'])}"
    )


def format_deposit_confirmed(admin_result: dict) -> str:
    return (
        f"✅ ยืนยันการฝากเงิน #{admin_result['transaction_id']} แล้ว "
        f"({wt.format_baht(admin_result['amount_satang'])})"
    )


def format_withdrawal_requested(result_data: dict) -> str:
    tx = result_data["transaction"]
    return (
        "🧾 ส่งคำขอถอนเงินแล้ว รอ Admin อนุมัติ (ยอดถูกกันไว้แล้ว)\n"
        f"เลขที่คำขอ: #{result_data['request_id']}\n"
        f"จำนวน: {wt.format_baht(tx['amount_satang'])}"
    )


def format_transfer_result(out_tx: dict, recipient_label: str) -> str:
    return (
        f"✅ โอนเงินสำเร็จ {wt.format_baht(out_tx['amount_satang'])} ให้ {recipient_label}\n"
        f"ยอดคงเหลือ: {wt.format_baht(out_tx['balance_after_satang'])}"
    )


def format_bill_created(payment_id: int, amount_satang: int, description: str = "") -> str:
    lines = [f"🧾 สร้างบิลแล้ว #{payment_id} จำนวน {wt.format_baht(amount_satang)}"]
    if description:
        lines.append(f"รายละเอียด: {description}")
    lines.append(f"ให้ผู้จ่ายพิมพ์ /bill pay {payment_id}")
    return "\n".join(lines)


def format_bill_paid(payment_id: int, amount_satang: int) -> str:
    return f"✅ ชำระบิล #{payment_id} แล้ว ({wt.format_baht(amount_satang)})"


def format_bill_list(items: List[dict], title: str = "บิล") -> str:
    if not items:
        return f"{title}: ไม่มีรายการ"
    lines = [f"{title} ({len(items)} รายการ)"]
    for b in items:
        status_th = _BILL_STATUS_TH.get(b["status"], b["status"])
        desc = b.get("description") or "-"
        lines.append(
            f"#{b['payment_id']} | {wt.format_baht(b['amount_satang'])} | {desc} | {status_th}"
        )
    return "\n".join(lines)


def format_history(page_data: dict) -> str:
    items = page_data["items"]
    if not items:
        return "ประวัติธุรกรรม: ไม่มีรายการ"
    lines = [
        f"📜 ประวัติธุรกรรม (หน้า {page_data['page']}/{page_data['total_pages']}, "
        f"ทั้งหมด {page_data['total_count']} รายการ)"
    ]
    for t in items:
        type_th = _TX_TYPE_TH.get(t["type"], t["type"])
        status_th = _TX_STATUS_TH.get(t["status"], t["status"])
        lines.append(
            f"#{t['transaction_id']} | {type_th} | {wt.format_baht(t['amount_satang'])} | "
            f"{status_th} | คงเหลือ {wt.format_baht(t['balance_after_satang'])}"
        )
    return "\n".join(lines)


def format_pending_deposits(items: List[dict]) -> str:
    if not items:
        return "ไม่มีคำขอฝากเงินที่รอดำเนินการ"
    lines = ["🧾 คำขอฝากเงินที่รอดำเนินการ:"]
    for t in items:
        lines.append(
            f"#{t['transaction_id']} | user {t['user_id']} | {wt.format_baht(t['amount_satang'])}"
        )
    return "\n".join(lines)


def format_pending_withdrawals(items: List[dict]) -> str:
    if not items:
        return "ไม่มีคำขอถอนเงินที่รอดำเนินการ"
    lines = ["🧾 คำขอถอนเงินที่รอดำเนินการ:"]
    for r in items:
        lines.append(
            f"#{r['request_id']} | user {r['user_id']} | {wt.format_baht(r['amount_satang'])}"
        )
    return "\n".join(lines)


def format_admin_adjust(tx: dict, target_label: str) -> str:
    return (
        f"✅ ปรับยอด {target_label} เรียบร้อย\n"
        f"เลขที่รายการ: #{tx['transaction_id']}\n"
        f"ยอดคงเหลือใหม่: {wt.format_baht(tx['balance_after_satang'])}"
    )


def format_admin_transactions(page_data: dict) -> str:
    items = page_data["items"]
    if not items:
        return "ไม่มีธุรกรรม"
    lines = [
        f"📊 ธุรกรรมทั้งหมด (หน้า {page_data['page']}/{page_data['total_pages']}, "
        f"ทั้งหมด {page_data['total_count']} รายการ)"
    ]
    for t in items:
        type_th = _TX_TYPE_TH.get(t["type"], t["type"])
        status_th = _TX_STATUS_TH.get(t["status"], t["status"])
        lines.append(
            f"#{t['transaction_id']} | user {t['user_id']} | {type_th} | "
            f"{wt.format_baht(t['amount_satang'])} | {status_th}"
        )
    return "\n".join(lines)


def format_debt_paid_via_wallet(entry_id: int, amount_satang: int) -> str:
    return f"✅ จ่ายหนี้รายการ #{entry_id} ด้วยกระเป๋าเงินแล้ว ({wt.format_baht(amount_satang)})"