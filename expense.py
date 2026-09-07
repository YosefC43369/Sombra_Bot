"""
expense.py — Expense Tracker / Expense Management (data layer)

Per-chat, per-user personal spending log: record an expense, list/filter
it by date range or category, edit it, delete it, and summarize it by
category over a period.

CORE INVARIANT (matches wallet.py's and debt_ledger.py's own): every
baht figure this module produces comes from plain Python integer
arithmetic over `amount_satang` (1 บาท = 100 สตางค์, INTEGER — never
float).

DELIBERATELY NOT WIRED INTO THE WALLET BALANCE. An expense record is a
*bookkeeping note about money the user spent somewhere else*, not a
movement of the internal wallet balance. Recording one therefore never
credits or debits `wallets.balance_satang` and never writes a
`wallet_transactions` row — doing so would double-count against the
real internal ledger (a user who both /transfer'd money and logged the
same spend as an /expense must not have their balance moved twice).
The two systems are joined only by an optional, purely informational
`wallet_transaction_id` reference (see add_expense()), which records
"this note corresponds to that already-existing ledger row" without
creating a second transaction. The same reasoning applies to
debt_ledger.py: `debt_entry_id` is an optional reference only, and
recording an expense NEVER marks a debt entry paid — settling a debt
stays exactly one operation, /debt_pay (wallet.pay_debt_with_wallet).

OWNERSHIP: every row is keyed by (chat_id, user_id) and every read,
update and delete in this module takes the acting user_id and filters
on it, so a member can only ever see/edit/delete their own expenses.
There is no function here that lets one ordinary member reach another
member's rows; the only cross-member read is
summarize_all_users_admin(), which app.py gates behind the existing
is_admin() check.

Design constraints (matches security.py / wallet.py / debt_ledger.py /
scope_policy.py / findings.py):
- Standard library only (sqlite3, time, re, logging, dataclasses,
  datetime, decimal, typing, zoneinfo).
- Imports `security` and NOTHING else from this repo. Every data-layer
  module here only ever imports security, never each other, so each one
  still loads and tests in complete isolation if another is broken —
  which is why the small money/date helpers below are duplicated from
  debt_ledger.py rather than imported from it (wallet.py duplicates the
  money helpers for exactly this stated reason; the date helpers are
  duplicated on the same grounds and are kept byte-identical in
  behaviour to debt_ledger.py's originals).
- No network/API calls, no LLM calls, no background threads.
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and
  audit_log table (via write_audit_log) — never a second database file.
- Deletion is a SOFT delete (`deleted_at` timestamp). debt_ledger.py
  already keeps settled entries "ไม่ถูกลบ เพื่อการตรวจสอบย้อนหลัง";
  the same audit-trail reasoning applies here, so every read below
  filters `deleted_at IS NULL` and nothing is ever physically removed.
"""

import re
import time
import sqlite3
import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from security import DB_PATH, write_audit_log

logger = logging.getLogger("modbot.expense")

BANGKOK_TZ_NAME = "Asia/Bangkok"
try:
    BANGKOK_TZ = ZoneInfo(BANGKOK_TZ_NAME)
except ZoneInfoNotFoundError:  # pragma: no cover - only if tzdata truly missing
    logger.exception(
        "EXPENSE: Asia/Bangkok tzdata not found on this system — "
        "install the 'tzdata' package (see requirements.txt)."
    )
    raise

MAX_DESCRIPTION_LEN = 500
MAX_RAW_AMOUNT_LEN = 32              # sanity cap before we even try Decimal()
MAX_EXPENSE_AMOUNT = Decimal("1000000")  # 1,000,000 บาท per single expense
DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 100
SUMMARY_ROW_LIMIT = 100000           # effectively "no cap" for one summary query
CONN_TIMEOUT_SECONDS = 30


# ---------------- Categories ----------------
# Canonical key -> (emoji, Thai label, accepted aliases). The canonical
# key is what gets stored in the `category` column; aliases exist only
# so a user can type either English or Thai. Unknown categories are
# REJECTED rather than silently coerced to "other" — a typo'd category
# that quietly lands in the wrong bucket would corrupt every later
# summary, and the user gets a reply listing the valid ones instead.

CATEGORIES: Dict[str, dict] = {
    "food":          {"emoji": "🍜", "th": "อาหาร",       "aliases": ("อาหาร", "กิน", "ข้าว", "อาหารการกิน")},
    "transport":     {"emoji": "🚗", "th": "เดินทาง",      "aliases": ("เดินทาง", "ขนส่ง", "รถ", "ค่ารถ")},
    "housing":       {"emoji": "🏠", "th": "ที่พัก",        "aliases": ("ที่พัก", "บ้าน", "ค่าเช่า", "เช่าบ้าน")},
    "shopping":      {"emoji": "🛒", "th": "ช้อปปิ้ง",      "aliases": ("ช้อปปิ้ง", "ซื้อของ", "ช้อป")},
    "health":        {"emoji": "💊", "th": "สุขภาพ",       "aliases": ("สุขภาพ", "ยา", "หมอ", "โรงพยาบาล")},
    "entertainment": {"emoji": "🎮", "th": "บันเทิง",       "aliases": ("บันเทิง", "เที่ยว", "เกม", "หนัง")},
    "bills":         {"emoji": "📱", "th": "บิล/ค่าบริการ",  "aliases": ("บิล", "ค่าบริการ", "ค่าน้ำ", "ค่าไฟ", "เน็ต")},
    "education":     {"emoji": "📚", "th": "การศึกษา",     "aliases": ("การศึกษา", "เรียน", "หนังสือ", "คอร์ส")},
    "work":          {"emoji": "💼", "th": "งาน",          "aliases": ("งาน", "ทำงาน", "ออฟฟิศ")},
    "other":         {"emoji": "📦", "th": "อื่นๆ",         "aliases": ("อื่นๆ", "อื่น ๆ", "อื่น", "เบ็ดเตล็ด")},
}

VALID_CATEGORIES = tuple(CATEGORIES.keys())

# Reverse lookup built once at import: every canonical key and every
# alias, casefolded, -> canonical key.
_CATEGORY_LOOKUP: Dict[str, str] = {}
for _key, _meta in CATEGORIES.items():
    _CATEGORY_LOOKUP[_key.casefold()] = _key
    _CATEGORY_LOOKUP[_meta["th"].casefold()] = _key
    for _alias in _meta["aliases"]:
        _CATEGORY_LOOKUP[_alias.casefold()] = _key


def normalize_category(raw: Optional[str]) -> Optional[str]:
    """'Food' / 'food' / 'อาหาร' -> 'food'. Returns None (never raises)
    for a missing or unrecognized category — callers turn None into a
    Thai validation-error reply listing the valid categories."""
    if raw is None:
        return None
    text = raw.strip().casefold()
    if not text:
        return None
    return _CATEGORY_LOOKUP.get(text)


def category_label(key: str) -> str:
    """'food' -> '🍜 อาหาร'. Unknown keys (only possible for a row written
    by an older/newer schema) degrade to the raw key rather than raising."""
    meta = CATEGORIES.get(key)
    if not meta:
        return key
    return f"{meta['emoji']} {meta['th']}"


# ---------------- Result types (same shape as wallet.py's) ----------------

@dataclass
class OpResult:
    ok: bool
    reason: str = ""
    detail: str = ""
    data: dict = field(default_factory=dict)


class _Abort(Exception):
    """Internal control-flow only: raised inside a `with _tx() as conn:`
    block to trigger a rollback, caught immediately outside it and
    turned into an OpResult. Never escapes a public function."""
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH, timeout=CONN_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    conn.isolation_level = None  # manual transaction control (BEGIN IMMEDIATE below)
    return conn


class _Tx:
    """Opens one connection, BEGIN IMMEDIATE (acquire the write lock up
    front), commit on clean exit, rollback on any exception — identical
    to wallet.py's _Tx, so a read-modify-write (e.g. update_expense's
    ownership check followed by its UPDATE) can never interleave with
    another writer."""

    def __enter__(self):
        self.conn = _conn()
        self.conn.execute("BEGIN IMMEDIATE")
        return self.conn

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.conn.commit()
        else:
            try:
                self.conn.rollback()
            except sqlite3.Error:
                pass
        self.conn.close()
        return False  # never suppress the exception


def _tx():
    return _Tx()


def expense_db_init() -> None:
    """Creates the Expense table only. Idempotent: safe on every process
    start, never resets or drops data. Never touches app.py's,
    security.py's, wallet.py's or debt_ledger.py's tables."""
    conn = _conn()
    conn.execute("BEGIN")
    conn.execute("""CREATE TABLE IF NOT EXISTS expenses (
        expense_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        amount_satang INTEGER NOT NULL CHECK (amount_satang > 0),
        category TEXT NOT NULL,
        description TEXT,
        expense_date TEXT NOT NULL,
        wallet_transaction_id INTEGER,
        debt_entry_id INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        deleted_at INTEGER
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_expenses_chat_user_date "
        "ON expenses (chat_id, user_id, expense_date)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_expenses_chat_user_category "
        "ON expenses (chat_id, user_id, category)"
    )
    conn.commit()
    conn.close()
    logger.info("EXPENSE DATABASE: OK")


# ---------------- Money helpers ----------------
# (Duplicated from debt_ledger.py/wallet.py rather than imported — see
# the module docstring for why every data-layer module here imports
# only `security`.)

def parse_amount_to_satang(raw: Optional[str]) -> Optional[int]:
    """Parses user-supplied text into a positive integer number of
    satang. Returns None (never raises) for missing/non-numeric/zero/
    negative/absurdly-large input — callers turn None into a Thai
    validation-error reply. Decimal, never float."""
    if raw is None:
        return None
    text = raw.strip().replace(",", "")
    if not text or len(text) > MAX_RAW_AMOUNT_LEN:
        return None
    try:
        amount = Decimal(text)
    except (InvalidOperation, ValueError):
        return None
    if amount.is_nan() or amount.is_infinite():
        return None
    if amount <= 0 or amount > MAX_EXPENSE_AMOUNT:
        return None
    satang = int((amount * 100).to_integral_exact(rounding=ROUND_HALF_UP))
    if satang <= 0:
        return None
    return satang


def format_baht(satang: int) -> str:
    """Integer satang -> Thai baht display text with thousands
    separators. Whole-baht amounts render without decimals."""
    baht = Decimal(satang) / 100
    if satang % 100 == 0:
        return f"{int(baht):,} บาท"
    return f"{baht:,.2f} บาท"


# ---------------- Time / timezone helpers ----------------

def _now_utc_epoch() -> int:
    return int(time.time())


def bangkok_date_from_epoch(epoch_seconds: int) -> str:
    """UTC epoch -> Asia/Bangkok calendar date (YYYY-MM-DD). Single
    source of truth for 'which day did this happen on' — never derive a
    user-facing date from UTC."""
    return datetime.fromtimestamp(epoch_seconds, tz=BANGKOK_TZ).strftime("%Y-%m-%d")


def today_bangkok_date() -> str:
    return bangkok_date_from_epoch(_now_utc_epoch())


def _today_bangkok_date_obj() -> date:
    return datetime.now(tz=BANGKOK_TZ).date()


def month_range(year: int, month: int) -> Tuple[str, str]:
    """(first_day, last_day) inclusive ISO dates for one calendar month."""
    first = date(year, month, 1)
    next_first = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
    last = next_first - timedelta(days=1)
    return first.isoformat(), last.isoformat()


def current_month_range(today: Optional[date] = None) -> Tuple[str, str]:
    if today is None:
        today = _today_bangkok_date_obj()
    return month_range(today.year, today.month)


def current_week_range(today: Optional[date] = None) -> Tuple[str, str]:
    """(Monday, Sunday) inclusive ISO dates for the week containing
    `today` (default: today in Asia/Bangkok). Monday-start matches Thai
    calendar convention."""
    if today is None:
        today = _today_bangkok_date_obj()
    monday = today - timedelta(days=today.weekday())
    sunday = monday + timedelta(days=6)
    return monday.isoformat(), sunday.isoformat()


_MONTH_ARG_RE = re.compile(r"^(\d{4})-(\d{2})$")
_DATE_ARG_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")


def parse_month_arg(raw: str) -> Optional[Tuple[str, str]]:
    """'YYYY-MM' -> (first_day, last_day) inclusive, or None."""
    if not raw:
        return None
    m = _MONTH_ARG_RE.match(raw.strip())
    if not m:
        return None
    year, month = int(m.group(1)), int(m.group(2))
    if not (1 <= month <= 12):
        return None
    try:
        return month_range(year, month)
    except ValueError:
        return None


def parse_date_arg(raw: str) -> Optional[str]:
    """'YYYY-MM-DD' -> the same string if it is a real calendar date,
    else None. Rejects e.g. 2026-02-31 rather than letting a
    nonexistent date through into a range query."""
    if not raw:
        return None
    m = _DATE_ARG_RE.match(raw.strip())
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat()
    except ValueError:
        return None


def parse_period(args: Optional[List[str]]) -> Optional[dict]:
    """Turns the trailing period words of a command into a concrete
    inclusive date range. Accepts:

        (nothing)              -> this month
        today                  -> today
        week                   -> this week (Mon-Sun)
        month                  -> this calendar month
        YYYY-MM                -> that calendar month
        YYYY-MM-DD             -> that single day
        YYYY-MM-DD YYYY-MM-DD  -> custom inclusive range

    Returns {"date_from", "date_to", "label"} or None if the words
    aren't a period this understands — callers turn None into a Thai
    usage-error reply rather than guessing a range. An inverted custom
    range (from > to) is rejected as invalid rather than silently
    swapped."""
    words = [w for w in (args or []) if w.strip()]

    if not words:
        date_from, date_to = current_month_range()
        return {"date_from": date_from, "date_to": date_to, "label": "เดือนนี้"}

    first = words[0].strip().casefold()

    if len(words) == 1:
        if first in ("today", "วันนี้"):
            today = today_bangkok_date()
            return {"date_from": today, "date_to": today, "label": "วันนี้"}
        if first in ("week", "สัปดาห์", "สัปดาห์นี้"):
            date_from, date_to = current_week_range()
            return {"date_from": date_from, "date_to": date_to, "label": "สัปดาห์นี้"}
        if first in ("month", "เดือน", "เดือนนี้"):
            date_from, date_to = current_month_range()
            return {"date_from": date_from, "date_to": date_to, "label": "เดือนนี้"}
        month = parse_month_arg(words[0])
        if month:
            return {"date_from": month[0], "date_to": month[1], "label": words[0].strip()}
        single = parse_date_arg(words[0])
        if single:
            return {"date_from": single, "date_to": single, "label": single}
        return None

    if len(words) == 2:
        start, end = parse_date_arg(words[0]), parse_date_arg(words[1])
        if start and end:
            if start > end:
                return None
            return {"date_from": start, "date_to": end, "label": f"{start} - {end}"}
        return None

    return None


# ---------------- Create ----------------

def add_expense(chat_id: int, user_id: int, amount_satang: int, category: str,
                description: str = "", expense_date: Optional[str] = None,
                wallet_transaction_id: Optional[int] = None,
                debt_entry_id: Optional[int] = None) -> OpResult:
    """Records one expense for (chat_id, user_id).

    `amount_satang` must already be a validated positive int (see
    parse_amount_to_satang()) — this function does not parse free-text
    money, so a caller can never skip validation by calling it directly
    with a string. `category` must already be a canonical key from
    normalize_category().

    `wallet_transaction_id` / `debt_entry_id` are OPTIONAL, purely
    informational back-references. Setting either records a link to an
    already-existing row; it never creates, modifies or settles
    anything in wallet.py or debt_ledger.py, and no wallet balance is
    touched here (see module docstring).

    `expense_date` defaults to today in Asia/Bangkok; the parameter
    exists so tests can pin a date without mocking time.time()."""
    if amount_satang is None or not isinstance(amount_satang, int) or isinstance(amount_satang, bool):
        return OpResult(False, reason="INVALID_AMOUNT")
    if amount_satang <= 0:
        return OpResult(False, reason="INVALID_AMOUNT")
    if amount_satang > int(MAX_EXPENSE_AMOUNT * 100):
        return OpResult(False, reason="INVALID_AMOUNT")
    if category not in CATEGORIES:
        return OpResult(False, reason="INVALID_CATEGORY")

    desc = (description or "").strip()
    if len(desc) > MAX_DESCRIPTION_LEN:
        return OpResult(False, reason="DESCRIPTION_TOO_LONG")

    if expense_date is None:
        expense_date = today_bangkok_date()
    elif parse_date_arg(expense_date) is None:
        return OpResult(False, reason="INVALID_DATE")

    now = _now_utc_epoch()
    try:
        with _tx() as conn:
            cur = conn.execute(
                "INSERT INTO expenses "
                "(chat_id, user_id, amount_satang, category, description, expense_date, "
                " wallet_transaction_id, debt_entry_id, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (chat_id, user_id, amount_satang, category, (desc or None), expense_date,
                 wallet_transaction_id, debt_entry_id, now, now),
            )
            expense_id = cur.lastrowid
    except sqlite3.Error:
        logger.exception("EXPENSE DB ERROR on add_expense")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, user_id, actor="user", action="EXPENSE_ADDED",
                    detail=f"expense_id={expense_id} amount_satang={amount_satang} "
                           f"category={category} date={expense_date}")
    return OpResult(True, data={"expense_id": expense_id, "amount_satang": amount_satang,
                                "category": category, "description": desc,
                                "expense_date": expense_date})


# ---------------- Read ----------------

def get_expense(chat_id: int, expense_id: int, user_id: Optional[int] = None) -> Optional[dict]:
    """One expense, or None. Pass `user_id` to enforce ownership: a row
    belonging to someone else returns None rather than leaking that the
    ID exists — same reasoning as debt_ledger.mark_entry_paid()'s
    chat_id scoping. Soft-deleted rows are never returned."""
    conn = _conn()
    query = ("SELECT * FROM expenses WHERE expense_id=? AND chat_id=? "
             "AND deleted_at IS NULL")
    params: List = [expense_id, chat_id]
    if user_id is not None:
        query += " AND user_id=?"
        params.append(user_id)
    row = conn.execute(query, params).fetchone()
    conn.close()
    return dict(row) if row else None


def list_expenses(chat_id: int, user_id: int, date_from: Optional[str] = None,
                  date_to: Optional[str] = None, category: Optional[str] = None,
                  page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> dict:
    """Paginated, newest-first expenses for ONE user in ONE chat. The
    (chat_id, user_id) filter is not optional — there is no way to call
    this for somebody else's rows."""
    page = max(1, page)
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
    conn = _conn()
    where = "WHERE chat_id=? AND user_id=? AND deleted_at IS NULL"
    params: List = [chat_id, user_id]
    if date_from:
        where += " AND expense_date>=?"
        params.append(date_from)
    if date_to:
        where += " AND expense_date<=?"
        params.append(date_to)
    if category:
        where += " AND category=?"
        params.append(category)

    total_row = conn.execute(
        f"SELECT COUNT(*) AS c, COALESCE(SUM(amount_satang), 0) AS s FROM expenses {where}",
        params,
    ).fetchone()
    total, total_satang = total_row["c"], total_row["s"]

    rows = conn.execute(
        f"SELECT * FROM expenses {where} "
        "ORDER BY expense_date DESC, expense_id DESC LIMIT ? OFFSET ?",
        params + [page_size, (page - 1) * page_size],
    ).fetchall()
    conn.close()

    total_pages = max(1, (total + page_size - 1) // page_size)
    return {
        "items": [dict(r) for r in rows], "page": page, "page_size": page_size,
        "total_count": total, "total_pages": total_pages, "total_satang": total_satang,
        "date_from": date_from, "date_to": date_to, "category": category,
    }


def summarize_by_category(chat_id: int, user_id: int, date_from: Optional[str] = None,
                          date_to: Optional[str] = None) -> dict:
    """Per-category totals for one user over an inclusive date range,
    biggest spender first. All arithmetic is SQLite integer SUM over
    amount_satang — no float anywhere on this path."""
    conn = _conn()
    where = "WHERE chat_id=? AND user_id=? AND deleted_at IS NULL"
    params: List = [chat_id, user_id]
    if date_from:
        where += " AND expense_date>=?"
        params.append(date_from)
    if date_to:
        where += " AND expense_date<=?"
        params.append(date_to)

    rows = conn.execute(
        f"SELECT category, COUNT(*) AS c, SUM(amount_satang) AS s FROM expenses {where} "
        "GROUP BY category ORDER BY s DESC LIMIT ?",
        params + [SUMMARY_ROW_LIMIT],
    ).fetchall()
    conn.close()

    by_category = [
        {"category": r["category"], "count": r["c"], "total_satang": r["s"]}
        for r in rows
    ]
    return {
        "date_from": date_from, "date_to": date_to,
        "by_category": by_category,
        "grand_total_satang": sum(c["total_satang"] for c in by_category),
        "grand_total_count": sum(c["count"] for c in by_category),
    }


def summarize_all_users_admin(chat_id: int, date_from: Optional[str] = None,
                              date_to: Optional[str] = None) -> dict:
    """Chat-wide per-user totals. The ONLY cross-member read in this
    module — app.py gates it behind the existing is_admin() check, the
    same way /dashboard and /wallet_admin are gated. Never called on
    any ordinary-member path."""
    conn = _conn()
    where = "WHERE chat_id=? AND deleted_at IS NULL"
    params: List = [chat_id]
    if date_from:
        where += " AND expense_date>=?"
        params.append(date_from)
    if date_to:
        where += " AND expense_date<=?"
        params.append(date_to)

    rows = conn.execute(
        f"SELECT user_id, COUNT(*) AS c, SUM(amount_satang) AS s FROM expenses {where} "
        "GROUP BY user_id ORDER BY s DESC LIMIT ?",
        params + [SUMMARY_ROW_LIMIT],
    ).fetchall()
    conn.close()

    by_user = [
        {"user_id": r["user_id"], "count": r["c"], "total_satang": r["s"]}
        for r in rows
    ]
    return {
        "date_from": date_from, "date_to": date_to,
        "by_user": by_user,
        "grand_total_satang": sum(u["total_satang"] for u in by_user),
        "grand_total_count": sum(u["count"] for u in by_user),
    }


# ---------------- Update ----------------

def update_expense(chat_id: int, expense_id: int, user_id: int,
                   amount_satang: Optional[int] = None, category: Optional[str] = None,
                   description: Optional[str] = None,
                   expense_date: Optional[str] = None) -> OpResult:
    """Edits one of the CALLING user's own expenses. Ownership is
    re-checked inside the same BEGIN IMMEDIATE transaction as the
    UPDATE (and the UPDATE itself carries the user_id in its WHERE
    clause), so there is no read-then-write window another writer —
    or another user — could slip through.

    Only the fields passed are changed; passing nothing is rejected as
    NO_CHANGES rather than silently touching updated_at."""
    if (amount_satang is None and category is None
            and description is None and expense_date is None):
        return OpResult(False, reason="NO_CHANGES")

    if amount_satang is not None:
        if not isinstance(amount_satang, int) or isinstance(amount_satang, bool):
            return OpResult(False, reason="INVALID_AMOUNT")
        if amount_satang <= 0 or amount_satang > int(MAX_EXPENSE_AMOUNT * 100):
            return OpResult(False, reason="INVALID_AMOUNT")
    if category is not None and category not in CATEGORIES:
        return OpResult(False, reason="INVALID_CATEGORY")
    if description is not None and len(description.strip()) > MAX_DESCRIPTION_LEN:
        return OpResult(False, reason="DESCRIPTION_TOO_LONG")
    if expense_date is not None and parse_date_arg(expense_date) is None:
        return OpResult(False, reason="INVALID_DATE")

    now = _now_utc_epoch()
    try:
        with _tx() as conn:
            row = conn.execute(
                "SELECT * FROM expenses WHERE expense_id=? AND chat_id=? AND deleted_at IS NULL",
                (expense_id, chat_id),
            ).fetchone()
            if not row:
                raise _Abort("NOT_FOUND")
            if row["user_id"] != user_id:
                # Deliberately NOT_FOUND, not FORBIDDEN: a member probing IDs
                # should not learn that someone else's expense #N exists.
                raise _Abort("NOT_FOUND")

            sets, params = [], []
            if amount_satang is not None:
                sets.append("amount_satang=?")
                params.append(amount_satang)
            if category is not None:
                sets.append("category=?")
                params.append(category)
            if description is not None:
                sets.append("description=?")
                params.append(description.strip() or None)
            if expense_date is not None:
                sets.append("expense_date=?")
                params.append(expense_date)
            sets.append("updated_at=?")
            params.append(now)

            conn.execute(
                f"UPDATE expenses SET {', '.join(sets)} "
                "WHERE expense_id=? AND chat_id=? AND user_id=? AND deleted_at IS NULL",
                params + [expense_id, chat_id, user_id],
            )
            updated = dict(conn.execute(
                "SELECT * FROM expenses WHERE expense_id=?", (expense_id,)
            ).fetchone())
    except _Abort as e:
        return OpResult(False, reason=e.reason, detail=e.detail)
    except sqlite3.Error:
        logger.exception("EXPENSE DB ERROR on update_expense")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, user_id, actor="user", action="EXPENSE_UPDATED",
                    detail=f"expense_id={expense_id} amount_satang={updated['amount_satang']} "
                           f"category={updated['category']}")
    return OpResult(True, data={"expense": updated})


# ---------------- Delete (soft) ----------------

def delete_expense(chat_id: int, expense_id: int, user_id: int,
                   is_admin_actor: bool = False) -> OpResult:
    """Soft-deletes one expense (sets `deleted_at`; the row stays in the
    table for audit). Ordinary members can only delete their OWN rows —
    the ownership check and the UPDATE run in one transaction, and the
    UPDATE re-states the ownership condition in its WHERE clause.

    `is_admin_actor` is passed by app.py only after its existing
    is_admin() check; it lets an admin remove a clearly-bogus row in
    their own chat, and is recorded as actor='admin' in the audit
    log."""
    try:
        with _tx() as conn:
            row = conn.execute(
                "SELECT * FROM expenses WHERE expense_id=? AND chat_id=? AND deleted_at IS NULL",
                (expense_id, chat_id),
            ).fetchone()
            if not row:
                raise _Abort("NOT_FOUND")
            if row["user_id"] != user_id and not is_admin_actor:
                raise _Abort("NOT_FOUND")  # see update_expense() for why not FORBIDDEN
            owner_id = row["user_id"]
            amount_satang = row["amount_satang"]

            now = _now_utc_epoch()
            if is_admin_actor and owner_id != user_id:
                conn.execute(
                    "UPDATE expenses SET deleted_at=?, updated_at=? "
                    "WHERE expense_id=? AND chat_id=? AND deleted_at IS NULL",
                    (now, now, expense_id, chat_id),
                )
            else:
                conn.execute(
                    "UPDATE expenses SET deleted_at=?, updated_at=? "
                    "WHERE expense_id=? AND chat_id=? AND user_id=? AND deleted_at IS NULL",
                    (now, now, expense_id, chat_id, user_id),
                )
    except _Abort as e:
        return OpResult(False, reason=e.reason, detail=e.detail)
    except sqlite3.Error:
        logger.exception("EXPENSE DB ERROR on delete_expense")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, owner_id, actor=("admin" if is_admin_actor and owner_id != user_id else "user"),
                    action="EXPENSE_DELETED",
                    detail=f"actor={user_id} expense_id={expense_id} amount_satang={amount_satang}")
    return OpResult(True, data={"expense_id": expense_id, "amount_satang": amount_satang,
                                "user_id": owner_id})
