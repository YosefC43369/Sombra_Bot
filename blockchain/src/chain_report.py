"""
chain_report.py — Formatting layer for chain.py (append-only verifiable
ledger).

Mirrors wallet_report.py / expense_report.py: owns no tables, performs no
arithmetic beyond formatting numbers the Rust component already computed,
and makes no network/LLM calls. Standard library only, and imports nothing
else from this repo, so it stays usable even when the ledger binary itself
is missing.

The Thai text here never calls the system a decentralized blockchain: it is
one node, run by this bot, so it is described as "บัญชีแยกประเภทแบบ
ตรวจสอบได้ (Append-Only Verifiable Ledger)".
"""

from datetime import datetime
from decimal import Decimal
from typing import List, Optional
from zoneinfo import ZoneInfo

BANGKOK_TZ = ZoneInfo("Asia/Bangkok")

CHAIN_DENY_TH = {
    "CHAIN_DISABLED": "ระบบ Ledger ถูกปิดใช้งานอยู่ (CHAIN_ENABLED=false)",
    "CHAIN_UNAVAILABLE": (
        "ยังไม่ได้ติดตั้งส่วนประกอบ Ledger\n"
        "ให้ build ด้วย: cd blockchain && cargo build --release"
    ),
    "CHAIN_TIMEOUT": "ระบบ Ledger ใช้เวลานานเกินกำหนด ลองใหม่อีกครั้ง",
    "CHAIN_NO_OUTPUT": "ระบบ Ledger ไม่ตอบกลับ",
    "CHAIN_BAD_OUTPUT": "ระบบ Ledger ตอบกลับในรูปแบบที่อ่านไม่ได้",
    "DB_ERROR": "เกิดข้อผิดพลาดกับฐานข้อมูล ลองใหม่อีกครั้ง",
    "INVALID_CHAIN": "โครงสร้าง Ledger ไม่ถูกต้อง",
    "USAGE_ERROR": "เรียกใช้คำสั่ง Ledger ไม่ถูกต้อง",
    "BLOCK_NOT_FOUND": "ไม่พบ Block นี้",
    "TRANSACTION_NOT_FOUND": "ไม่พบรายการนี้ใน Ledger",
}

_PROBLEM_TH = {
    "EMPTY_CHAIN": "ยังไม่มี Block ใดเลย (ยังไม่ได้เริ่มต้น Ledger)",
    "BAD_GENESIS": "Genesis Block ไม่ตรงกับค่ามาตรฐาน",
    "HEIGHT_GAP": "ลำดับ Block ขาดหาย",
    "BROKEN_LINK": "previous_hash ไม่ต่อกับ Block ก่อนหน้า",
    "INVALID_BLOCK_HASH": "Hash ของ Block ไม่ตรงกับข้อมูลใน Block",
    "MERKLE_MISMATCH": "Merkle Root ไม่ตรงกับรายการใน Block",
    "TX_COUNT_MISMATCH": "จำนวนรายการไม่ตรงกับที่ Block ระบุไว้",
    "TAMPERED_TRANSACTION": "รายการถูกแก้ไขหลังบันทึกลง Ledger",
    "DUPLICATE_TRANSACTION": "พบรายการซ้ำใน Ledger",
}

_TX_TYPE_TH = {
    # wallet.py TxType values, verbatim
    "deposit": "ฝากเงิน",
    "withdrawal": "ถอนเงิน",
    "transfer_out": "โอนออก",
    "transfer_in": "โอนเข้า",
    "payment": "ชำระเงิน",
    "refund": "คืนเงิน",
    "debt_payment": "จ่ายหนี้",
    "adjustment": "ปรับยอดโดย Admin",
    # ledger-level types
    "debt_signed": "เซ็นสินค้า (ลงบัญชีหนี้)",
    "debt_paid": "ปิดยอดหนี้",
    "expense_added": "บันทึกรายจ่าย",
    "expense_revised": "แก้ไขรายจ่าย",
    "expense_deleted": "ลบรายจ่าย",
}

_TX_STATUS_TH = {
    "completed": "สำเร็จ",
    "cancelled": "ยกเลิก",
    "pending": "รอดำเนินการ",
}

_SOURCE_TH = {
    "wallet_tx": "กระเป๋าเงิน",
    "debt_entry": "บัญชีหนี้",
    "expense": "รายจ่าย",
}


def deny_text(reason: str) -> str:
    return "❌ " + CHAIN_DENY_TH.get(reason, reason)


# ---------------- small local helpers ----------------
# (Duplicated rather than imported from wallet.py, for the same reason every
# data-layer module in this repo duplicates them: this layer must still work
# when another module is broken or absent.)

def format_baht(satang: Optional[int]) -> str:
    if satang is None:
        return "-"
    baht = Decimal(int(satang)) / 100
    if int(satang) % 100 == 0:
        return f"{int(baht):,} บาท"
    return f"{baht:,.2f} บาท"


def _when(epoch: Optional[int]) -> str:
    if not epoch:
        return "-"
    try:
        return datetime.fromtimestamp(int(epoch), BANGKOK_TZ).strftime("%d/%m/%Y %H:%M")
    except (ValueError, OverflowError, OSError):
        return "-"


def _short(hash_hex: Optional[str], size: int = 12) -> str:
    if not hash_hex:
        return "-"
    return hash_hex[:size] + "…" if len(hash_hex) > size else hash_hex


def _tx_type_th(tx_type: str) -> str:
    return _TX_TYPE_TH.get(tx_type, tx_type)


def _direction(tx: dict) -> str:
    """'+' when the balance rose, '−' when it fell, '' when the record is
    not a balance movement at all (debt and expense anchors).

    wallet.py stores `amount_satang` as an unsigned magnitude for EVERY
    transaction type -- including a negative /wallet_admin adjust, which is
    written through _debit() as a positive number. The direction survives
    only in balance_before_satang vs balance_after_satang, which the ledger
    captures in each wallet anchor's metadata. Reading it back here is what
    stops an audit view from showing a 500-baht admin deduction and a
    500-baht admin credit as the same line."""
    metadata = tx.get("metadata")
    if not isinstance(metadata, dict):
        return ""
    before = metadata.get("balance_before_satang")
    after = metadata.get("balance_after_satang")
    if before is None or after is None:
        return ""
    if after > before:
        return "+"
    if after < before:
        return "−"
    return ""


def _signed_amount(tx: dict) -> str:
    return _direction(tx) + format_baht(tx.get("amount_satang"))


def _status_th(tx: dict) -> str:
    metadata = tx.get("metadata")
    if not isinstance(metadata, dict):
        return ""
    return _TX_STATUS_TH.get(metadata.get("status"), "")


# ---------------- formatters ----------------

def format_status(data: dict) -> str:
    if not data.get("initialized"):
        return (
            "🔗 Ledger: ยังไม่ได้เริ่มต้น\n"
            "จะสร้าง Genesis Block อัตโนมัติเมื่อรันคำสั่งบันทึกครั้งแรก"
        )
    pending = data.get("pending_transactions", 0)
    capped = data.get("pending_capped_at")
    pending_text = f"{pending:,}"
    if capped and pending >= capped:
        pending_text = f"{pending:,}+"
    lines = [
        "🔗 สถานะ Ledger (Append-Only Verifiable Ledger)",
        f"ความสูงล่าสุด (height): {data.get('height', 0):,}",
        f"จำนวน Block ทั้งหมด: {data.get('block_count', 0):,}",
        f"จำนวนรายการที่บันทึกแล้ว: {data.get('transaction_count', 0):,}",
        f"รอบันทึกเข้า Ledger: {pending_text} รายการ",
        f"Hash ล่าสุด: {_short(data.get('tip_hash'), 16)}",
        f"บันทึกล่าสุดเมื่อ: {_when(data.get('last_anchor_at'))}",
    ]
    return "\n".join(lines)


def format_anchor_result(data: dict) -> str:
    anchored = data.get("anchored", 0)
    if not anchored:
        return "🔗 ไม่มีรายการใหม่ที่ต้องบันทึกลง Ledger"
    return (
        "🔗 บันทึกลง Ledger แล้ว\n"
        f"Block ใหม่: #{data.get('height')}\n"
        f"จำนวนรายการในบล็อก: {anchored:,}"
    )


def format_verify(data: dict) -> str:
    blocks = data.get("blocks_checked", 0)
    txs = data.get("transactions_checked", 0)
    if data.get("ok"):
        return (
            "✅ Ledger สมบูรณ์ ไม่พบการแก้ไขย้อนหลัง\n"
            f"ตรวจสอบแล้ว: {blocks:,} Block / {txs:,} รายการ\n"
            f"Hash ล่าสุด: {_short(data.get('tip_hash'), 16)}"
        )
    lines = [
        "🚨 Ledger ไม่ผ่านการตรวจสอบ",
        f"ตรวจสอบแล้ว: {blocks:,} Block / {txs:,} รายการ",
        f"พบปัญหา: {data.get('problem_count', 0):,} รายการ",
        "",
    ]
    for problem in (data.get("problems") or [])[:10]:
        kind = problem.get("kind", "")
        lines.append(
            f"• Block #{problem.get('height')}: "
            f"{_PROBLEM_TH.get(kind, kind)}"
        )
    remaining = int(data.get("problem_count", 0)) - min(10, len(data.get("problems") or []))
    if remaining > 0:
        lines.append(f"… และอีก {remaining:,} รายการ")
    lines.append("")
    lines.append("⚠️ Block ที่บันทึกแล้วห้ามแก้ไข การแก้ไขย้อนหลังทำให้ Ledger เสียหายถาวร")
    return "\n".join(lines)


def format_reconcile(data: dict) -> str:
    checked = data.get("checked", 0)
    if data.get("ok"):
        return (
            "✅ ข้อมูลในฐานข้อมูลตรงกับ Ledger ทุกรายการ\n"
            f"ตรวจสอบแล้ว: {checked:,} รายการ"
        )
    lines = [
        "🚨 พบข้อมูลในฐานข้อมูลไม่ตรงกับที่บันทึกไว้ใน Ledger",
        f"ตรวจสอบแล้ว: {checked:,} รายการ | ไม่ตรงกัน: {data.get('mismatches', 0):,} รายการ",
        "",
    ]
    for problem in (data.get("problems") or [])[:10]:
        lines.append(f"• {problem.get('tx_ref')}")
    lines.append("")
    lines.append("หมายเหตุ: หมายถึงแถวต้นทางถูกแก้ไขหลังบันทึกลง Ledger แล้ว")
    return "\n".join(lines)


def format_block(data: dict) -> str:
    block = data.get("block") or {}
    lines = [
        f"🧱 Block #{block.get('height')}",
        f"เวลา: {_when(block.get('timestamp'))}",
        f"Hash: {_short(block.get('hash'), 24)}",
        f"Previous Hash: {_short(block.get('previous_hash'), 24)}",
        f"Merkle Root: {_short(block.get('merkle_root'), 24)}",
        f"จำนวนรายการ: {block.get('tx_count', 0):,}",
    ]
    transactions = block.get("transactions") or []
    if transactions:
        lines.append("")
        lines.append("รายการในบล็อก:")
        for tx in transactions[:20]:
            lines.append(
                f"• {_tx_type_th(tx.get('tx_type', ''))} "
                f"{_signed_amount(tx)} "
                f"[{tx.get('tx_ref')}]"
            )
        if len(transactions) > 20:
            lines.append(f"… และอีก {len(transactions) - 20:,} รายการ")
    return "\n".join(lines)


def format_transaction_matches(matches: List[dict]) -> str:
    if not matches:
        return deny_text("TRANSACTION_NOT_FOUND")
    lines = [f"🔎 พบ {len(matches):,} รายการใน Ledger"]
    for tx in matches:
        lines.append("")
        lines.append(f"• {_tx_type_th(tx.get('tx_type', ''))} — {tx.get('tx_ref')}")
        lines.append(f"  ที่มา: {_SOURCE_TH.get(tx.get('source'), tx.get('source'))} "
                     f"#{tx.get('source_row_id')}")
        lines.append(f"  จำนวน: {_signed_amount(tx)}")
        status = _status_th(tx)
        if status:
            lines.append(f"  สถานะ: {status}")
        lines.append(f"  เวลา: {_when(tx.get('occurred_at'))}")
        lines.append(f"  อยู่ใน Block #{tx.get('block_height')}")
        lines.append(f"  Payload Hash: {_short(tx.get('payload_hash'), 16)}")
        if tx.get("hash_consistent") is False:
            lines.append("  🚨 Hash ไม่ตรงกับข้อมูล — รายการนี้ถูกแก้ไข")
    return "\n".join(lines)


def usage_text() -> str:
    return (
        "ใช้งาน:\n"
        "/chain status — ดูสถานะ Ledger\n"
        "/chain verify — ตรวจสอบความสมบูรณ์ของ Ledger (Admin)\n"
        "/chain reconcile — เทียบฐานข้อมูลกับ Ledger (Admin)\n"
        "/chain block <height> — ดู Block (Admin)\n"
        "/chain tx <ref> — ค้นหารายการ เช่น 12 หรือ wallet_tx:12 (Admin)\n"
        "/chain anchor — บันทึกรายการค้างเข้า Ledger ทันที (Admin)"
    )