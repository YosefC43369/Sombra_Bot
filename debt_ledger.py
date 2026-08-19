"""
debt_ledger.py — "เซ็นสินค้า" Outstanding-Balance Ledger (data layer)

Deterministic, offline record-keeping for "who signed for goods/items
and hasn't paid yet" (e.g. staff taking snacks/drinks on credit,
settled at the next payroll cycle). Each signed item is one row;
rows are summed by admin command (never guessed by an LLM) into a
per-person total for a given calendar-month window.

CORE INVARIANT: every baht figure this module ever returns comes from
plain Python integer arithmetic over `amount_satang` (1 บาท = 100
สตางค์, stored as INTEGER — never float, never a string that gets
`eval`'d or fed to an LLM to total up). gemini.py / OpenAI are never
imported here and no function in this file makes a network call —
that keeps this ledger correct and usable even if the AI provider
(gemini.py's GPT-5.6 Luna integration) is down, misconfigured, or
removed entirely (see app.py's /debt_summary handler for the optional,
best-effort AI formatting step, which only ever runs *after* this
module has already produced the final numbers).

Design constraints (matches security.py / quota.py / scope_policy.py /
findings.py):
- Standard library only (sqlite3, time, re, logging, dataclasses, enum,
  decimal, datetime, zoneinfo).
- No network/API calls, no LLM calls, no background threads.
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and
  audit_log table (via write_audit_log) — no second database, never
  touches bot.py's or any other module's tables.
- All money in/out of this module is either a Decimal (input parsing)
  or an int number of satang (everywhere else). format_baht() is the
  only function that turns a satang amount into display text; callers
  that need a Telegram-ready message should go through debt_report.py
  instead of formatting baht themselves.
- Every date bucket ("which day/month does this entry belong to") is
  computed in Asia/Bangkok local time, not server/UTC time, so a
  signature made late at night in Thailand never lands in the wrong
  month just because the server clock is UTC.
"""

import re
import time
import sqlite3
import logging
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from security import DB_PATH, write_audit_log

logger = logging.getLogger("modbot.debt_ledger")

BANGKOK_TZ_NAME = "Asia/Bangkok"
try:
    BANGKOK_TZ = ZoneInfo(BANGKOK_TZ_NAME)
except ZoneInfoNotFoundError: # pragma: no cover - only if tzdata truly missing
    logger.exception(
        "DEBT LEDGER: Asia/Bangkok tzdata not found on this system — "
        "install the 'tzdata' package (see requirements.txt)."
    )
    raise
    
MAX_NAME_LEN = 100
MAX_DESCRIPTION_LEN = 500
MAX_RAW_AMOUNT_LEN = 32    # sanity cap before we even try Decimal()
MAX_ENTRY_AMOUNT = Decimal("1000000") # 1,000,000 บาท per single entry
DEFAULT_LIST_LIMIT = 200
SUMMARY_ROW_LIMIT = 100000 # effectively "no cap" for one summary query


class EntryStatus(str, Enum):
    UNPAID = "unpaid"
    PAID = "paid"
    
VALID_STATUSES = {EntryStatus.UNPAID.value, EntryStatus.PAID.value}

@dataclass
class SignResult:
    ok: bool
    entry_id: Optional[int] = None
    reason: str = ""
    detail: str = ""


@dataclass
class PaidResult:
    ok: bool
    updated_count: int = 0
    total_satang: int = 0
    reason: str = ""
    detail: str = ""
    entries: List[dict] = field(default_factory=list)


# ---------------- Database ----------------

def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
    
    
def debt_ledger_db_init() -> None:
    """Create the debt-ledger table only. Reuses security.py's DB_PATH
    and audit_log table; never touches forbidden_words/warnings/settings
    or any bb_*/github_repo table. Idempotent: safe to call on every
    process start, fresh database or existing one — never resets or
    drops data (Requirement #11: ห้าม reset Database ตอน deploy)."""
    conn = _conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS debt_entries (
        entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        debtor_name TEXT NOT NULL,
        amount_satang INTEGER NOT NULL,
        item_description TEXT,
        status TEXT NOT NULL DEFAULT 'unpaid',
        entry_date TEXT NOT NULL,
        recorded_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        paid_at INTEGER,
        paid_by INTEGER
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_debt_entries_chat_debtor "
        "ON debt_entries (chat_id, debtor_name)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_debt_entries_chat_date "
        "ON debt_entries (chat_id, entry_date)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_debt_entries_chat_status "
        "ON debt_entries (chat_id, status)"
    )
    conn.commit()
    conn.close()
    logger.info("DEBT LEDGER DATABASE: OK")


# ---------------- Time / timezone helpers ----------------

def _now_utc_epoch() -> int:
    return int(time.time())


def bangkok_date_from_epoch(epoch_seconds: int) -> str:
    """Converts a UTC epoch timestamp to its Asia/Bangkok calendar date
    (YYYY-MM-DD). This is the single source of truth for "which day did
    this happen on" — never derive a date from time.gmtime()/UTC for
    anything shown to the user (Requirement #12)."""
    return datetime.fromtimestamp(epoch_seconds, tz=BANGKOK_TZ).strftime("%Y-%m-%d")


def today_bangkok_date() -> str:
    return bangkok_date_from_epoch(_now_utc_epoch())


def _today_bangkok_date_obj() -> date:
    return datetime.now(tz=BANGKOK_TZ).date()


def month_range(year: int, month: int) -> Tuple[str, str]:
    """Returns (first_day, last_day) ISO date strings (inclusive) for
    one calendar month. Raises ValueError for an invalid year/month,
    same as date()."""
    first = date(year, month, 1)
    next_first = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
    last = next_first - timedelta(days=1)
    return first.isoformat(), last.isoformat()


def previous_month_range(today: Optional[date] = None) -> Tuple[str, str]:
    """Returns (first_day, last_day) ISO date strings (inclusive) for
    the calendar month *before* the one containing `today` (default:
    today in Asia/Bangkok). This is the default window for
    /debt_summary — 'รอบเดือนก่อนหน้า' (Requirement #4)."""
    if today is None:
        today = _today_bangkok_date_obj()
    first_of_this_month = today.replace(day=1)
    last_of_prev_month = first_of_this_month - timedelta(days=1)
    return month_range(last_of_prev_month.year, last_of_prev_month.month)


_MONTH_ARG_RE = re.compile(r"^(\d{4})-(\d{2})$")


def parse_month_arg(raw: str) -> Optional[Tuple[str, str]]:
    """Parses a user-supplied 'YYYY-MM' string into a (first_day,
    last_day) inclusive date range. Returns None if `raw` isn't exactly
    that shape or isn't a real calendar month — callers should turn
    that into a Thai usage-error reply rather than guessing."""
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


# ---------------- Money helpers ----------------

def parse_amount_to_satang(raw: Optional[str]) -> Optional[int]:
    """Parses a user-supplied amount string into an integer number of
    satang (1 บาท = 100 สตางค์). Returns None (never raises) if `raw`
    is missing, not a number, not-a-number/infinite, zero, negative, or
    absurdly large — callers are expected to turn None into a Thai
    validation-error reply (Requirement #9). This is the ONLY place in
    the whole feature that turns free-text money into a number; every
    other function in this module only ever moves an already-validated
    int around."""
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
    if amount <= 0 or amount > MAX_ENTRY_AMOUNT:
        return None
    satang = int((amount * 100).to_integral_exact(rounding=ROUND_HALF_UP))
    if satang <= 0:
        return None
    return satang


def format_baht(satang: int) -> str:
    """Formats an integer satang amount as Thai baht display text with
    thousands separators. Whole-baht amounts render without decimals
    (matches the spec's own examples, e.g. '50 บาท' / '1,050 บาท');
    amounts with a fractional satang render with exactly 2 decimals."""
    baht = Decimal(satang) / 100
    if satang % 100 == 0:
        return f"{int(baht):,} บาท"
    return f"{baht:,.2f} บาท"


# ---------------- Validation ----------------

def _validate_name(debtor_name: Optional[str]) -> Optional[str]:
    """Returns a reason string if `debtor_name` is invalid, else None."""
    if not debtor_name or not debtor_name.strip():
        return "NAME_REQUIRED"
    if len(debtor_name.strip()) > MAX_NAME_LEN:
        return "NAME_TOO_LONG"
    return None


# ---------------- Entry: create & read ----------------

def add_entry(
    chat_id: int,
    debtor_name: str,
    amount_satang: int,
    recorded_by: int,
    item_description: str = "",
    entry_date: Optional[str] = None,
) -> SignResult:
    """Records one signed-for-goods entry as 'unpaid'. `amount_satang`
    must already be a validated positive int (see
    parse_amount_to_satang()) — this function does not parse free-text
    money itself, so a caller can never accidentally skip validation by
    calling this directly with a string.

    `entry_date` defaults to today in Asia/Bangkok; the parameter only
    exists so tests can pin a specific date without mocking time.time()
    — app.py's /sign handler never passes it."""
    name = (debtor_name or "").strip()
    name_error = _validate_name(name)
    if name_error:
        return SignResult(False, reason=name_error)

    if amount_satang is None or not isinstance(amount_satang, int) or amount_satang <= 0:
        return SignResult(False, reason="INVALID_AMOUNT")

    description = (item_description or "").strip()
    if len(description) > MAX_DESCRIPTION_LEN:
        return SignResult(False, reason="DESCRIPTION_TOO_LONG")

    if entry_date is None:
        entry_date = today_bangkok_date()

    now = _now_utc_epoch()
    try:
        conn = _conn()
        cur = conn.execute(
            "INSERT INTO debt_entries "
            "(chat_id, debtor_name, amount_satang, item_description, status, "
            " entry_date, recorded_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                chat_id, name, amount_satang, description or None,
                EntryStatus.UNPAID.value, entry_date, recorded_by, now,
            ),
        )
        entry_id = cur.lastrowid
        conn.commit()
        conn.close()
    except sqlite3.Error:
        logger.exception("DEBT LEDGER DB ERROR on add_entry")
        return SignResult(False, reason="DB_ERROR")

    write_audit_log(
        chat_id, recorded_by, actor="admin", action="DEBT_SIGNED",
        detail=f"entry_id={entry_id} debtor={name!r} amount_satang={amount_satang}",
    )
    return SignResult(True, entry_id=entry_id)


def get_entry(entry_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM debt_entries WHERE entry_id=?", (entry_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_entries(
    chat_id: int,
    status: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    debtor_name: Optional[str] = None,
    limit: int = DEFAULT_LIST_LIMIT,
) -> List[dict]:
    """Reads entries for one chat, oldest first, with optional filters.
    `debtor_name` matches case-insensitively (COLLATE NOCASE) so a
    Latin-script name typed with different casing still matches — Thai
    script has no case, so this is a no-op for Thai names."""
    conn = _conn()
    query = "SELECT * FROM debt_entries WHERE chat_id=?"
    params: List = [chat_id]
    if status:
        query += " AND status=?"
        params.append(status)
    if date_from:
        query += " AND entry_date>=?"
        params.append(date_from)
    if date_to:
        query += " AND entry_date<=?"
        params.append(date_to)
    if debtor_name:
        query += " AND debtor_name = ? COLLATE NOCASE"
        params.append(debtor_name)
    query += " ORDER BY entry_date ASC, entry_id ASC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Entry: mark paid ----------------

def mark_entry_paid(entry_id: int, actor_user_id: int, chat_id: Optional[int] = None) -> PaidResult:
    """Marks exactly one entry as paid. If `chat_id` is given and does
    not match the entry's chat, this returns ENTRY_NOT_FOUND rather
    than leaking whether the ID exists in a different chat — a Telegram
    admin in one group has no business marking another group's tab as
    settled."""
    entry = get_entry(entry_id)
    if not entry or (chat_id is not None and entry["chat_id"] != chat_id):
        return PaidResult(False, reason="ENTRY_NOT_FOUND")
    if entry["status"] == EntryStatus.PAID.value:
        return PaidResult(False, reason="ALREADY_PAID")

    now = _now_utc_epoch()
    try:
        conn = _conn()
        conn.execute(
            "UPDATE debt_entries SET status=?, paid_at=?, paid_by=? WHERE entry_id=?",
            (EntryStatus.PAID.value, now, actor_user_id, entry_id),
        )
        conn.commit()
        conn.close()
    except sqlite3.Error:
        logger.exception("DEBT LEDGER DB ERROR on mark_entry_paid")
        return PaidResult(False, reason="DB_ERROR")

    write_audit_log(
        entry["chat_id"], actor_user_id, actor="admin", action="DEBT_PAID",
        detail=f"entry_id={entry_id} debtor={entry['debtor_name']!r} amount_satang={entry['amount_satang']}",
    )
    paid_entry = dict(entry)
    paid_entry["status"] = EntryStatus.PAID.value
    return PaidResult(True, updated_count=1, total_satang=entry["amount_satang"], entries=[paid_entry])


def mark_debtor_paid(
    chat_id: int,
    debtor_name: str,
    actor_user_id: int,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> PaidResult:
    """Marks every currently-unpaid entry for `debtor_name` in this chat
    as paid in a single transaction (all rows update-then-commit
    together, so a crash mid-way never leaves a half-settled tab —
    Requirement #11). If `date_from`/`date_to` are given, only unpaid
    entries whose entry_date falls in that inclusive range are touched
    — this is how /paid <ชื่อ> <YYYY-MM> settles exactly one payroll
    cycle without also closing out a different month's tab."""
    name_error = _validate_name(debtor_name)
    if name_error:
        return PaidResult(False, reason=name_error)
    name = debtor_name.strip()

    entries = list_entries(
        chat_id, status=EntryStatus.UNPAID.value,
        date_from=date_from, date_to=date_to,
        debtor_name=name, limit=SUMMARY_ROW_LIMIT,
    )
    if not entries:
        return PaidResult(False, reason="NO_UNPAID_ENTRIES")

    now = _now_utc_epoch()
    ids = [e["entry_id"] for e in entries]
    total_satang = sum(e["amount_satang"] for e in entries)
    try:
        conn = _conn()
        conn.executemany(
            "UPDATE debt_entries SET status=?, paid_at=?, paid_by=? WHERE entry_id=?",
            [(EntryStatus.PAID.value, now, actor_user_id, eid) for eid in ids],
        )
        conn.commit()
        conn.close()
    except sqlite3.Error:
        logger.exception("DEBT LEDGER DB ERROR on mark_debtor_paid")
        return PaidResult(False, reason="DB_ERROR")

    write_audit_log(
        chat_id, actor_user_id, actor="admin", action="DEBT_PAID_BULK",
        detail=f"debtor={name!r} count={len(ids)} total_satang={total_satang} "
               f"range={date_from or '-'}..{date_to or '-'}",
    )
    paid_entries = [dict(e, status=EntryStatus.PAID.value) for e in entries]
    return PaidResult(True, updated_count=len(ids), total_satang=total_satang, entries=paid_entries)


# ---------------- Summary (deterministic arithmetic) ----------------

def summarize_by_debtor(
    chat_id: int,
    date_from: str,
    date_to: str,
    status: str = EntryStatus.UNPAID.value,
) -> dict:
    """The one function every /debt_summary figure ultimately comes
    from. Pulls entries in [date_from, date_to] (inclusive Asia/Bangkok
    calendar dates) and sums them per debtor using plain Python int
    addition — sum() over already-integer satang values, nothing
    parsed, nothing estimated, nothing sent to an LLM. Returns:

        {
          "date_from": ..., "date_to": ..., "status": ...,
          "by_debtor": [
            {"debtor_name": ..., "count": ..., "total_satang": ...,
             "entries": [...]},
            ...  # sorted by debtor_name
          ],
          "grand_total_satang": ..., "grand_total_count": ...,
        }

    An empty date range (no matching entries) returns an empty
    by_debtor list and zeroed totals rather than raising."""
    entries = list_entries(
        chat_id, status=status, date_from=date_from, date_to=date_to,
        limit=SUMMARY_ROW_LIMIT,
    )
    by_debtor: Dict[str, List[dict]] = {}
    for e in entries:
        by_debtor.setdefault(e["debtor_name"], []).append(e)

    debtor_summaries = []
    grand_total_satang = 0
    grand_total_count = 0
    for name in sorted(by_debtor.keys()):
        rows = by_debtor[name]
        total = sum(r["amount_satang"] for r in rows)
        debtor_summaries.append({
            "debtor_name": name,
            "count": len(rows),
            "total_satang": total,
            "entries": rows,
        })
        grand_total_satang += total
        grand_total_count += len(rows)

    return {
        "date_from": date_from,
        "date_to": date_to,
        "status": status,
        "by_debtor": debtor_summaries,
        "grand_total_satang": grand_total_satang,
        "grand_total_count": grand_total_count,
    }