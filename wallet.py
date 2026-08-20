"""
wallet.py — Wallet / Payment / Transaction Ledger (data layer)

Per-chat internal wallet for each Telegram user: balance, deposits,
withdrawals, member-to-member transfers, payment requests ("bills"),
and a full transaction ledger. Wired into the existing "เซ็นสินค้า"
debt ledger (debt_ledger.py) so an unpaid /debt entry can be settled
straight out of a member's wallet balance.

CORE INVARIANT (matches debt_ledger.py's own): every baht figure this
module produces comes from plain Python integer arithmetic over
`amount_satang` (1 บาท = 100 สตางค์, INTEGER — never float). The wallet
balance is NEVER written directly; every change to `wallets.balance_satang`
happens inside the same DB transaction as a new (or newly-settled)
`wallet_transactions` row, so the ledger can always reconstruct the
balance from scratch — see `recompute_balance()` at the bottom, used
only for auditing/tests, never on any hot path.

Design constraints (matches security.py / debt_ledger.py / scope_policy.py
/ findings.py):
- Standard library only (sqlite3, time, json, logging, dataclasses,
  enum, decimal, typing), with ONE deliberate exception: debt_ledger.py
  is imported, but ONLY inside pay_debt_with_wallet(), so that a debt
  settlement and the matching wallet debit commit as a single atomic
  SQLite transaction (Requirement #8). No other function in this file
  touches debt_ledger.py.
- No network/API calls, no LLM calls, no background threads. A real
  Payment Gateway is NOT guessed here — see payment_provider.py for the
  abstraction seam; today every deposit/payment is settled internally
  and requires an explicit admin confirmation (Requirement: "ห้ามถือว่า
  การกดปุ่มหรือส่งข้อความว่า 'โอนแล้ว' เป็นหลักฐานการชำระเงินจริง").
- CREATE TABLE IF NOT EXISTS only; reuses security.py's DB_PATH and
  audit_log table (via write_audit_log) — never a second database file.
- Wallets are scoped per (chat_id, user_id), NOT globally per user —
  this matches every other feature in this bot (debt_entries, findings,
  scope_policy, security are all chat_id-scoped) and keeps an admin's
  manual-adjustment/withdrawal-approval power (which is itself only
  ever checked per-chat via app.py's is_admin()) from ever reaching a
  balance outside the chat where that admin actually has authority.
  This is a deliberate interpretation of the task spec (which listed
  only "Telegram User ID" as the wallet key) in favor of consistency
  with the rest of the codebase — flagged explicitly for review.
- Every mutating public function opens exactly one connection, runs
  `BEGIN IMMEDIATE` (acquires SQLite's write lock up front rather than
  on first write), and commits or rolls back as a unit — this is what
  makes concurrent /transfer, /withdraw, and "pay with wallet" taps
  safe against double-spending: a balance debit is always an atomic
  conditional UPDATE (`WHERE balance_satang >= ?`), never a
  read-then-write pair a second writer could interleave with.
- `idempotency_key` (optional, usually Telegram's own `update.update_id`)
  lets a duplicate-delivered callback or a double-tapped confirm button
  replay safely: the second call finds the already-recorded transaction
  and returns it instead of creating a second one.
"""

import time
import json
import sqlite3
import logging
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Dict, List, Optional

from security import DB_PATH, write_audit_log

logger = logging.getLogger("modbot.wallet")

MAX_RAW_AMOUNT_LEN = 32      # sanity cap before we even try Decimal()
MAX_TX_AMOUNT = Decimal("1000000")  # 1,000,000 บาท per single operation
DEFAULT_HISTORY_PAGE_SIZE = 10
CONN_TIMEOUT_SECONDS = 30    # let concurrent writers wait out BEGIN IMMEDIATE instead of erroring


class TxType(str, Enum):
    DEPOSIT = "deposit"
    WITHDRAWAL = "withdrawal"
    TRANSFER_OUT = "transfer_out"
    TRANSFER_IN = "transfer_in"
    PAYMENT = "payment"
    REFUND = "refund"
    DEBT_PAYMENT = "debt_payment"
    ADJUSTMENT = "adjustment"
    
    
class TxStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    
    
class WithdrawalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    
    
class PaymentStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"


VALID_WITHDRAWAL_STATUSES = {e.value for e in WithdrawalStatus}
VALID_PAYMENT_STATUSES = {e.value for e in PaymentStatus}


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
    front), commit on clean exit, rollback on any exception. Every
    public mutating function below does its work inside `with _tx() as
    conn:` instead of hand-rolling try/commit/rollback each time."""
    
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
    
    
def wallet_db_init() -> None:
    """Creates the Wallet/Ledger tables only. Idempotent: safe on every
    process start, never resets or drops data. Never touches bot.py's,
    security.py's, or debt_ledger.py's tables."""
    conn = _conn()
    conn.execute("BEGIN")
    conn.execute("""CREATE TABLE IF NOT EXISTS wallets (
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        balance_satang INTEGER NOT NULL DEFAULT 0 CHECK (balance_satang >= 0),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (chat_id, user_id)
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS wallet_transactions (
        transaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        amount_satang INTEGER NOT NULL,
        balance_before_satang INTEGER NOT NULL,
        balance_after_satang INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'completed',
        reference_id TEXT,
        counterparty_user_id INTEGER,
        reason TEXT,
        metadata TEXT,
        idempotency_key TEXT,
        created_by INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_wtx_chat_user "
        "ON wallet_transactions (chat_id, user_id, transaction_id DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_wtx_chat_status "
        "ON wallet_transactions (chat_id, status)"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_wtx_idempotency "
        "ON wallet_transactions (chat_id, idempotency_key) "
        "WHERE idempotency_key IS NOT NULL"
    )
    conn.execute("""CREATE TABLE IF NOT EXISTS withdrawal_requests (
        request_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        amount_satang INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        transaction_id INTEGER,
        requested_at INTEGER NOT NULL,
        decided_by INTEGER,
        decided_at INTEGER,
        reason TEXT
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_wreq_chat_status "
        "ON withdrawal_requests (chat_id, status)"
    )
    conn.execute("""CREATE TABLE IF NOT EXISTS payment_requests (
        payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER NOT NULL,
        requested_by INTEGER NOT NULL,
        payer_user_id INTEGER,
        amount_satang INTEGER NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        provider TEXT NOT NULL DEFAULT 'internal_wallet',
        provider_ref TEXT,
        transaction_id INTEGER,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        paid_at INTEGER
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pay_chat_payer_status "
        "ON payment_requests (chat_id, payer_user_id, status)"
    )
    # Lightweight opportunistic username -> user_id cache, populated by
    # remember_user() (called from app.py's handle_message for every
    # text message, and from every wallet command handler). Telegram's
    # Bot API has no endpoint to resolve an arbitrary @username to a
    # user_id, so /transfer @username and /payment @username only work
    # for members this bot has already seen speak in the same chat --
    # /transfer and /payment also accept Reply-to-message instead (same
    # convention /mute and /unmute already use), which always works.
    conn.execute("""CREATE TABLE IF NOT EXISTS wallet_known_users (
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        username TEXT,
        display_name TEXT,
        last_seen_at INTEGER NOT NULL,
        PRIMARY KEY (chat_id, user_id)
    )""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_wku_chat_username "
        "ON wallet_known_users (chat_id, username COLLATE NOCASE)"
    )
    conn.commit()
    conn.close()
    logger.info("WALLET DATABASE: OK")


# ---------------- Money helpers ----------------
# (Deliberately duplicated from debt_ledger.py rather than imported --
# every data-layer module in this repo (security/quota/scope_policy/
# findings/debt_ledger) only ever imports `security`, never each other;
# keeping that pattern means this module still loads/tests in complete
# isolation from debt_ledger.py, same as debt_ledger.py itself must
# keep working if some *other* module is broken.)

def parse_amount_to_satang(raw: Optional[str]) -> Optional[int]:
    """Parses user-supplied text into a positive integer number of
    satang. Returns None (never raises) for missing/non-numeric/zero/
    negative/absurdly-large input -- callers turn None into a Thai
    validation-error reply. The only place free-text money is parsed;
    every other function in this module only moves an already-validated
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
    if amount <= 0 or amount > MAX_TX_AMOUNT:
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
    
    
def parse_signed_amount_to_satang(raw: Optional[str]) -> Optional[int]:
    """Like parse_amount_to_satang() but allows a leading '-' -- used
    only by /admin adjust, where a negative amount is a deliberate
    balance deduction. Magnitude is still capped by MAX_TX_AMOUNT."""
    if raw is None:
        return None
    text = raw.strip()
    negative = text.startswith("-")
    if negative:
        text = text[1:]
    satang = parse_amount_to_satang(text)
    if satang is None:
        return None
    return -satang if negative else satang
    
# ---------------- Known-users cache (for @username resolution) ----------------

def remember_user(chat_id: int, user_id: int, username: Optional[str] = None,
                   display_name: Optional[str] = None) -> None:
    now = int(time.time())
    conn = _conn()
    conn.execute("BEGIN IMMEDIATE")
    conn.execute(
        "INSERT INTO wallet_known_users (chat_id, user_id, username, display_name, last_seen_at) "
        "VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT(chat_id, user_id) DO UPDATE SET "
        "username=excluded.username, display_name=excluded.display_name, "
        "last_seen_at=excluded.last_seen_at",
        (chat_id, user_id, (username or None), (display_name or None), now),
    )
    conn.commit()
    conn.close()
    
    
def resolve_username(chat_id: int, username: str) -> Optional[int]:
    """'@name' or 'name' -> user_id, only if this bot has seen that
    username speak in this chat before. Returns None otherwise (never
    raises) -- callers should suggest Reply-to-message instead."""
    uname = (username or "").lstrip("@").strip()
    if not uname:
        return None
    conn = _conn()
    row = conn.execute(
        "SELECT user_id FROM wallet_known_users WHERE chat_id=? AND username=? COLLATE NOCASE",
        (chat_id, uname),
    ).fetchone()
    conn.close()
    return row["user_id"] if row else None
    
    
# ---------------- Core ledger primitives (must run inside an open _tx()) ----------------

def _get_or_create_balance(conn, chat_id: int, user_id: int) -> int:
    now = int(time.time())
    conn.execute(
        "INSERT INTO wallets (chat_id, user_id, balance_satang, created_at, updated_at) "
        "VALUES (?, ?, 0, ?, ?) ON CONFLICT(chat_id, user_id) DO NOTHING",
        (chat_id, user_id, now, now),
    )
    row = conn.execute(
        "SELECT balance_satang FROM wallets WHERE chat_id=? AND user_id=?",
        (chat_id, user_id),
    ).fetchone()
    return row["balance_satang"]
    
    
def  _find_by_idempotency_key(conn, chat_id: int, idempotency_key: str) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM wallet_transactions WHERE chat_id=? AND idempotency_key=?",
        (chat_id, idempotency_key),
    ).fetchone()
    return dict(row) if row else None


def _insert_tx(conn, chat_id, user_id, tx_type, amount_satang, balance_before, balance_after,
               status, reference_id, counterparty_user_id, reason, metadata, idempotency_key,
               created_by) -> dict:
    now = int(time.time())
    meta_json = json.dumps(metadata) if isinstance(metadata, (dict, list)) else metadata
    cur = conn.execute(
        "INSERT INTO wallet_transactions "
        "(chat_id, user_id, type, amount_satang, balance_before_satang, balance_after_satang, "
        " status, reference_id, counterparty_user_id, reason, metadata, idempotency_key, "
        " created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (chat_id, user_id, tx_type, amount_satang, balance_before, balance_after,
         status, reference_id, counterparty_user_id, reason, meta_json, idempotency_key,
         created_by, now),
    )
    return {
        "transaction_id": cur.lastrowid, "chat_id": chat_id, "user_id": user_id,
        "type": tx_type, "amount_satang": amount_satang,
        "balance_before_satang": balance_before, "balance_after_satang": balance_after,
        "status": status, "reference_id": reference_id,
        "counterparty_user_id": counterparty_user_id, "reason": reason,
        "metadata": meta_json, "idempotency_key": idempotency_key,
        "created_by": created_by, "created_at": now,
    }
    

def _credit(conn, chat_id, user_id, amount_satang, tx_type, status=TxStatus.COMPLETED.value,
            reference_id=None, counterparty_user_id=None, reason=None, metadata=None,
            idempotency_key=None, created_by=None) -> dict:
    """Increases balance and inserts one ledger row. Always succeeds
    (crediting can never be 'insufficient')."""
    balance_before = _get_or_create_balance(conn, chat_id, user_id)
    balance_after = balance_before + amount_satang
    conn.execute(
        "UPDATE wallets SET balance_satang=?, updated_at=? WHERE chat_id=? AND user_id=?",
        (balance_after, int(time.time()), chat_id, user_id),
    )
    return _insert_tx(conn, chat_id, user_id, tx_type, amount_satang, balance_before,
                       balance_after, status, reference_id, counterparty_user_id, reason,
                       metadata, idempotency_key, created_by or user_id)


def _debit(conn, chat_id, user_id, amount_satang, tx_type, status=TxStatus.COMPLETED.value,
           reference_id=None, counterparty_user_id=None, reason=None, metadata=None,
           idempotency_key=None, created_by=None) -> Optional[dict]:
    """Atomic conditional debit. The `WHERE balance_satang >= ?` clause
    is what actually prevents a negative balance / double-spend under
    concurrency -- there is no separate 'check balance' read the debit
    could race against, because BEGIN IMMEDIATE already means no other
    writer is touching this row at the same time. Returns None (no row
    inserted, caller's transaction should abort) if funds are
    insufficient."""
    _get_or_create_balance(conn, chat_id, user_id)
    row = conn.execute(
        "SELECT balance_satang FROM wallets WHERE chat_id=? AND user_id=?",
        (chat_id, user_id),
    ).fetchone()
    balance_before = row["balance_satang"]
    cur = conn.execute(
        "UPDATE wallets SET balance_satang = balance_satang - ?, updated_at=? "
        "WHERE chat_id=? AND user_id=? AND balance_satang >= ?",
        (amount_satang, int(time.time()), chat_id, user_id, amount_satang),
    )
    if cur.rowcount == 0:
        return None
    balance_after = balance_before - amount_satang
    return _insert_tx(conn, chat_id, user_id, tx_type, amount_satang, balance_before,
                       balance_after, status, reference_id, counterparty_user_id, reason,
                       metadata, idempotency_key, created_by or user_id)
                      
                
# ---------------- Wallet: read ----------------

def get_wallet(chat_id: int, user_id: int) -> dict:
    """Returns {chat_id, user_id, balance_satang}, lazily creating an
    empty wallet on first look (Requirement #1: every user should have
    one)."""
    with _tx() as conn:
        balance = _get_or_create_balance(conn, chat_id, user_id)
    return {"chat_id": chat_id, "user_id": user_id, "balance_satang": balance}


def get_transaction(transaction_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM wallet_transactions WHERE transaction_id=?", (transaction_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def list_transactions(chat_id: int, user_id: int, page: int = 1,
                       page_size: int = DEFAULT_HISTORY_PAGE_SIZE) -> dict:
    """Paginated, newest-first transaction history for one user's
    wallet in one chat (/history)."""
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    conn = _conn()
    total = conn.execute(
        "SELECT COUNT(*) AS c FROM wallet_transactions WHERE chat_id=? AND user_id=?",
        (chat_id, user_id),
    ).fetchone()["c"]
    rows = conn.execute(
        "SELECT * FROM wallet_transactions WHERE chat_id=? AND user_id=? "
        "ORDER BY transaction_id DESC LIMIT ? OFFSET ?",
        (chat_id, user_id, page_size, (page - 1) * page_size),
    ).fetchall()
    conn.close()
    total_pages = max(1, (total + page_size - 1) // page_size)
    return {
        "items": [dict(r) for r in rows], "page": page, "page_size": page_size,
        "total_count": total, "total_pages": total_pages,
    }
    
    
def recompute_balance(chat_id: int, user_id: int) -> int:
    """Rebuilds a balance from the ledger alone (credits minus debits,
    ignoring pending rows) -- for tests/audits only, never used on any
    write path. Any mismatch with wallets.balance_satang would indicate
    a bug, not something this function itself can fix."""
    conn = _conn()
    rows = conn.execute(
        "SELECT type, amount_satang FROM wallet_transactions "
        "WHERE chat_id=? AND user_id=? AND status='completed'",
        (chat_id, user_id),
    ).fetchall()
    conn.close()
    credit_types = {TxType.DEPOSIT.value, TxType.TRANSFER_IN.value, TxType.REFUND.value}
    total = 0
    for r in rows:
        if r["type"] in credit_types or (r["type"] == TxType.ADJUSTMENT.value and r["amount_satang"] >= 0):
            total += r["amount_satang"]
        else:
             total -= abs(r["amount_satang"])
    return total
    
    
# ---------------- Admin manual adjustment ----------------

def admin_adjust(chat_id: int, target_user_id: int, delta_satang: int, admin_id: int,
                  reason: str) -> OpResult:
    """Manual balance correction by an Admin (+ to credit, - to debit).
    `reason` is required and stored on the ledger row -- Requirement
    #10: every Admin Adjustment must record admin_id/target_user_id/
    amount/reason/timestamp/transaction_id, all of which this one
    wallet_transactions row already carries."""
    if not reason or not reason.strip():
        return OpResult(False, reason="REASON_REQUIRED")
    if delta_satang is None or delta_satang == 0:
        return OpResult(False, reason="INVALID_AMOUNT")
    if abs(delta_satang) > int(MAX_TX_AMOUNT * 100):
        return OpResult(False, reason="INVALID_AMOUNT")

    try:
        with _tx() as conn:
            if delta_satang > 0:
                tx = _credit(conn, chat_id, target_user_id, delta_satang, TxType.ADJUSTMENT.value,
                             reason=reason.strip(), created_by=admin_id)
            else:
                tx = _debit(conn, chat_id, target_user_id, -delta_satang, TxType.ADJUSTMENT.value,
                            reason=reason.strip(), created_by=admin_id)
                if tx is None:
                    raise _Abort("INSUFFICIENT_BALANCE")
    except _Abort as e:
        return OpResult(False, reason=e.reason, detail=e.detail)
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on admin_adjust")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, target_user_id, actor="admin", action="WALLET_ADMIN_ADJUST",
                     detail=f"admin={admin_id} delta_satang={delta_satang} reason={reason!r} "
                            f"transaction_id={tx['transaction_id']}")
    return OpResult(True, data={"transaction": tx})


# ---------------- Deposits ----------------

def request_deposit(chat_id: int, user_id: int, amount_satang: int) -> OpResult:
    """Records a PENDING deposit claim -- balance is NOT credited yet.
    An Admin must /admin deposit confirm it after verifying the money
    actually arrived (cash handed over, bank transfer checked, etc.);
    see the module docstring / payment_provider.py for why a user's own
    'โอนแล้ว' message is never enough by itself."""
    if amount_satang is None or amount_satang <= 0:
        return OpResult(False, reason="INVALID_AMOUNT")
    try:
        with _tx() as conn:
            balance_now = _get_or_create_balance(conn, chat_id, user_id)
            tx = _insert_tx(conn, chat_id, user_id, TxType.DEPOSIT.value, amount_satang,
                             balance_now, balance_now, TxStatus.PENDING.value,
                             None, None, None, None, None, user_id)
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on request_deposit")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, user_id, actor="user", action="WALLET_DEPOSIT_REQUESTED",
                     detail=f"amount_satang={amount_satang} transaction_id={tx['transaction_id']}")
    return OpResult(True, data={"transaction": tx})
    

def confirm_deposit(chat_id: int, transaction_id: int, admin_id: int) -> OpResult:
    try:
        with _tx() as conn:
            row = conn.execute(
                "SELECT * FROM wallet_transactions WHERE transaction_id=? AND chat_id=?",
                (transaction_id, chat_id),
            ).fetchone()
            if not row:
                raise _Abort("NOT_FOUND")
            if row["type"] != TxType.DEPOSIT.value:
                raise _Abort("NOT_A_DEPOSIT")
            if row["status"] != TxStatus.PENDING.value:
                raise _Abort("ALREADY_PROCESSED")
            credited = _credit(conn, chat_id, row["user_id"], row["amount_satang"],
                                TxType.DEPOSIT.value, created_by=admin_id)
            conn.execute(
                "UPDATE wallet_transactions SET status=?, balance_before_satang=?, "
                "balance_after_satang=? WHERE transaction_id=?",
                (TxStatus.COMPLETED.value, credited["balance_before_satang"],
                 credited["balance_after_satang"], transaction_id),
            )
    except _Abort as e:
        return OpResult(False, reason=e.reason)
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on confirm_deposit")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, row["user_id"], actor="admin", action="WALLET_DEPOSIT_CONFIRMED",
                     detail=f"admin={admin_id} transaction_id={transaction_id} "
                            f"amount_satang={row['amount_satang']}")
    return OpResult(True, data={"transaction_id": transaction_id, "user_id": row["user_id"],
                                 "amount_satang": row["amount_satang"]})
                                
                                
def reject_deposit(chat_id: int, transaction_id: int, admin_id: int, reason: str = "") -> OpResult:
    try:
        with _tx() as conn:
            row = conn.execute(
                "SELECT * FROM wallet_transactions WHERE transaction_id=? AND chat_id=?",
                (transaction_id, chat_id),
            ).fetchone()
            if not row:
                raise _Abort("NOT_FOUND")
            if row["type"] != TxType.DEPOSIT.value:
                raise _Abort("NOT_A_DEPOSIT")
            if row["status"] != TxStatus.PENDING.value:
                raise _Abort("ALREADY_PROCESSED")
            conn.execute(
                "UPDATE wallet_transactions SET status=?, reason=? WHERE transaction_id=?",
                (TxStatus.CANCELLED.value, (reason or None), transaction_id),
            )
    except _Abort as e:
        return OpResult(False, reason=e.reason)
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on reject_deposit")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, row["user_id"], actor="admin", action="WALLET_DEPOSIT_REJECTED",
                     detail=f"admin={admin_id} transaction_id={transaction_id} reason={reason!r}")
    return OpResult(True, data={"transaction_id": transaction_id})


def list_pending_deposits(chat_id: int, limit: int = 50) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM wallet_transactions WHERE chat_id=? AND type=? AND status=? "
        "ORDER BY transaction_id ASC LIMIT ?",
        (chat_id, TxType.DEPOSIT.value, TxStatus.PENDING.value, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Withdrawals ----------------

def request_withdrawal(chat_id: int, user_id: int, amount_satang: int) -> OpResult:
    """Creates a withdrawal request AND immediately holds the funds
    (debits the spendable balance right away, ledger status='pending')
    -- this is what stops a user from requesting the same money twice
    while an Admin decision is pending (Requirement #3's double-spend
    protection). Rejected/cancelled requests refund the hold."""
    if amount_satang is None or amount_satang <= 0:
        return OpResult(False, reason="INVALID_AMOUNT")
    try:
        with _tx() as conn:
             tx = _debit(conn, chat_id, user_id, amount_satang, TxType.WITHDRAWAL.value,
                        status=TxStatus.PENDING.value, created_by=user_id)
              if tx is None:
                  raise _Abort("INSUFFICIENT_BALANCE")
              now = int(time.time())
              cur = conn.execute(
                "INSERT INTO withdrawal_requests "
                "(chat_id, user_id, amount_satang, status, transaction_id, requested_at) "
                "VALUES (?,?,?,?,?,?)",
                (chat_id, user_id, amount_satang, WithdrawalStatus.PENDING.value,
                 tx["transaction_id"], now),
            )
            request_id = cur.lastrowid
            conn.execute(
                "UPDATE wallet_transactions SET reference_id=? WHERE transaction_id=?",
                (str(request_id), tx["transaction_id"]),
            )
    except _Abort as e:
        return OpResult(False, reason=e.reason)
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on request_withdrawal")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, user_id, actor="user", action="WALLET_WITHDRAWAL_REQUESTED",
                     detail=f"request_id={request_id} amount_satang={amount_satang}")
    return OpResult(True, data={"request_id": request_id, "transaction": tx})
    
    
def _get_withdrawal_in_conn(conn, chat_id: int, request_id: int) -> Optional[dict]:
    row = conn.execute(
        "SELECT * FROM withdrawal_requests WHERE request_id=? AND chat_id=?",
        (request_id, chat_id),
    ).fetchone()
    return dict(row) if row else None


def get_withdrawal_request(chat_id: int, request_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM withdrawal_requests WHERE request_id=? AND chat_id=?",
        (request_id, chat_id),
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def approve_withdrawal(chat_id: int, request_id: int, admin_id: int) -> OpResult:
    """Funds already left the spendable balance at request time; this
    just finalizes the paper trail once the admin has actually handed
    over the cash / sent the transfer outside the bot."""
    try:
        with _tx() as conn:
            req = _get_withdrawal_in_conn(conn, chat_id, request_id)
            if not req:
                raise _Abort("NOT_FOUND")
            if req["status"] != WithdrawalStatus.PENDING.value:
                raise _Abort("ALREADY_PROCESSED")
            now = int(time.time())
            conn.execute(
                "UPDATE withdrawal_requests SET status=?, decided_by=?, decided_at=? "
                "WHERE request_id=?",
                (WithdrawalStatus.COMPLETED.value, admin_id, now, request_id),
            )
            conn.execute(
                "UPDATE wallet_transactions SET status=? WHERE transaction_id=?",
                (TxStatus.COMPLETED.value, req["transaction_id"]),
            )
    except _Abort as e:
        return OpResult(False, reason=e.reason)
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on approve_withdrawal")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, req["user_id"], actor="admin", action="WALLET_WITHDRAWAL_APPROVED",
                     detail=f"admin={admin_id} request_id={request_id} "
                            f"amount_satang={req['amount_satang']}")
    return OpResult(True, data={"request_id": request_id})
    
    
def _reject_or_cancel_withdrawal(chat_id: int, request_id: int, actor_id: int, actor: str,
                                  new_status: str, action_tag: str, reason: str = "") -> OpResult:
    try:
        with _tx() as conn:
            req = _get_withdrawal_in_conn(conn, chat_id, request_id)
            if not req:
                raise _Abort("NOT_FOUND")
            if req["status"] != WithdrawalStatus.PENDING.value:
                raise _Abort("ALREADY_PROCESSED")
            now = int(time.time())
            conn.execute(
                "UPDATE withdrawal_requests SET status=?, decided_by=?, decided_at=?, reason=? "
                "WHERE request_id=?",
                (new_status, actor_id, now, (reason or None), request_id),
            )
            conn.execute(
                "UPDATE wallet_transactions SET status=? WHERE transaction_id=?",
                (TxStatus.CANCELLED.value, req["transaction_id"]),
            )
            refund_tx = _credit(conn, chat_id, req["user_id"], req["amount_satang"],
                                 TxType.REFUND.value, reference_id=str(request_id),
                                 reason=f"withdrawal {new_status}: {reason}".strip(),
                                 created_by=actor_id)
    except _Abort as e:
        return OpResult(False, reason=e.reason)
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on reject/cancel withdrawal")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, req["user_id"], actor=actor, action=action_tag,
                     detail=f"actor={actor_id} request_id={request_id} reason={reason!r} "
                            f"refund_transaction_id={refund_tx['transaction_id']}")
    return OpResult(True, data={"request_id": request_id, "refund_transaction": refund_tx})


def reject_withdrawal(chat_id: int, request_id: int, admin_id: int, reason: str = "") -> OpResult:
    return _reject_or_cancel_withdrawal(chat_id, request_id, admin_id, "admin",
                                         WithdrawalStatus.REJECTED.value,
                                         "WALLET_WITHDRAWAL_REJECTED", reason)


def cancel_withdrawal(chat_id: int, request_id: int, user_id: int) -> OpResult:
    """Self-service cancel by the requester themselves, while still
    pending -- refunds the same way an admin rejection does."""
    req = get_withdrawal_request(chat_id, request_id)
    if req and req["user_id"] != user_id:
        return OpResult(False, reason="FORBIDDEN")
    return _reject_or_cancel_withdrawal(chat_id, request_id, user_id, "user",
                                         WithdrawalStatus.CANCELLED.value,
                                         "WALLET_WITHDRAWAL_CANCELLED", "cancelled by requester")


def list_pending_withdrawals(chat_id: int, limit: int = 50) -> List[dict]:
    conn = _conn()
    rows = conn.execute(
        "SELECT * FROM withdrawal_requests WHERE chat_id=? AND status=? "
        "ORDER BY request_id ASC LIMIT ?",
        (chat_id, WithdrawalStatus.PENDING.value, limit),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Transfers ----------------

def transfer(chat_id: int, sender_id: int, recipient_id: int, amount_satang: int,
             note: str = "", idempotency_key: Optional[str] = None) -> OpResult:
    """Atomically moves money from sender to recipient inside this chat.
    Both legs (transfer_out for the sender, transfer_in for the
    recipient) are written in the same transaction and share a
    `reference_id`, so either both happen or neither does."""
    if sender_id == recipient_id:
        return OpResult(False, reason="SELF_TRANSFER_NOT_ALLOWED")
    if amount_satang is None or amount_satang <= 0:
        return OpResult(False, reason="INVALID_AMOUNT")

    try:
        with _tx() as conn:
            if idempotency_key:
                existing = _find_by_idempotency_key(conn, chat_id, idempotency_key)
                if existing:
                    return OpResult(True, data={"out_tx": existing, "already_processed": True})
            ref = f"tr-{int(time.time() * 1000)}-{sender_id}-{recipient_id}"
            out_tx = _debit(conn, chat_id, sender_id, amount_satang, TxType.TRANSFER_OUT.value,
                             reference_id=ref, counterparty_user_id=recipient_id,
                             reason=(note or None), idempotency_key=idempotency_key,
                             created_by=sender_id)
            if out_tx is None:
                raise _Abort("INSUFFICIENT_BALANCE")
            in_tx = _credit(conn, chat_id, recipient_id, amount_satang, TxType.TRANSFER_IN.value,
                             reference_id=ref, counterparty_user_id=sender_id,
                             reason=(note or None), created_by=sender_id)
    except _Abort as e:
        return OpResult(False, reason=e.reason)
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on transfer")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, sender_id, actor="user", action="WALLET_TRANSFER",
                     detail=f"to={recipient_id} amount_satang={amount_satang} ref={ref}")
    return OpResult(True, data={"out_tx": out_tx, "in_tx": in_tx})


# ---------------- Payment requests ("bills") ----------------

def create_payment_request(chat_id: int, requested_by: int, amount_satang: int,
                            description: str = "", payer_user_id: Optional[int] = None,
                            expires_in_seconds: Optional[int] = None) -> OpResult:
    if amount_satang is None or amount_satang <= 0:
        return OpResult(False, reason="INVALID_AMOUNT")
    if payer_user_id is not None and payer_user_id == requested_by:
        return OpResult(False, reason="SELF_PAYMENT_NOT_ALLOWED")
    now = int(time.time())
    expires_at = now + expires_in_seconds if expires_in_seconds else None
    try:
        with _tx() as conn:
            cur = conn.execute(
                "INSERT INTO payment_requests "
                "(chat_id, requested_by, payer_user_id, amount_satang, description, status, "
                " provider, created_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (chat_id, requested_by, payer_user_id, amount_satang, (description or None),
                 PaymentStatus.PENDING.value, "internal_wallet", now, expires_at),
            )
            payment_id = cur.lastrowid
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on create_payment_request")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, requested_by, actor="user", action="WALLET_PAYMENT_REQUEST_CREATED",
                     detail=f"payment_id={payment_id} amount_satang={amount_satang} "
                            f"payer={payer_user_id}")
    return OpResult(True, data={"payment_id": payment_id})
    
    
def get_payment_request(chat_id: int, payment_id: int) -> Optional[dict]:
    conn = _conn()
    row = conn.execute(
        "SELECT * FROM payment_requests WHERE payment_id=? AND chat_id=?",
        (payment_id, chat_id),
    ).fetchone()
    conn.close()
    if not row:
        return None
    data = dict(row)
    if (data["status"] == PaymentStatus.PENDING.value and data["expires_at"]
            and data["expires_at"] < int(time.time())):
        data["status"] = PaymentStatus.EXPIRED.value  # lazy view-time expiry; see pay_payment_request
    return data
    
    
def pay_payment_request(chat_id: int, payment_id: int, payer_user_id: int,
                         idempotency_key: Optional[str] = None) -> OpResult:
    try:
        with _tx() as conn:
            if idempotency_key:
                existing = _find_by_idempotency_key(conn, chat_id, idempotency_key)
                if existing:
                    return OpResult(True, data={"transaction": existing, "already_processed": True})

            row = conn.execute(
                "SELECT * FROM payment_requests WHERE payment_id=? AND chat_id=?",
                (payment_id, chat_id),
            ).fetchone()
            if not row:
                raise _Abort("NOT_FOUND")
            req = dict(row)
            if req["status"] != PaymentStatus.PENDING.value:
                raise _Abort("ALREADY_PROCESSED")
            if req["expires_at"] and req["expires_at"] < int(time.time()):
                conn.execute(
                    "UPDATE payment_requests SET status=? WHERE payment_id=?",
                    (PaymentStatus.EXPIRED.value, payment_id),
                )
                raise _Abort("EXPIRED")
            if req["payer_user_id"] is not None and req["payer_user_id"] != payer_user_id:
                raise _Abort("FORBIDDEN")
            if req["requested_by"] == payer_user_id:
                raise _Abort("SELF_PAYMENT_NOT_ALLOWED")

            debit_tx = _debit(conn, chat_id, payer_user_id, req["amount_satang"],
                               TxType.PAYMENT.value, reference_id=str(payment_id),
                               counterparty_user_id=req["requested_by"],
                               reason=req["description"], idempotency_key=idempotency_key,
                               created_by=payer_user_id)
            if debit_tx is None:
                raise _Abort("INSUFFICIENT_BALANCE")
            credit_tx = _credit(conn, chat_id, req["requested_by"], req["amount_satang"],
                                 TxType.PAYMENT.value, reference_id=str(payment_id),
                                 counterparty_user_id=payer_user_id,
                                 reason=req["description"], created_by=payer_user_id)
            now = int(time.time())
            conn.execute(
                "UPDATE payment_requests SET status=?, transaction_id=?, paid_at=? "
                "WHERE payment_id=?",
                (PaymentStatus.PAID.value, debit_tx["transaction_id"], now, payment_id),
            )
    except _Abort as e:
        return OpResult(False, reason=e.reason)
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on pay_payment_request")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, payer_user_id, actor="user", action="WALLET_PAYMENT_PAID",
                     detail=f"payment_id={payment_id} amount_satang={req['amount_satang']} "
                            f"to={req['requested_by']}")
    return OpResult(True, data={"debit_tx": debit_tx, "credit_tx": credit_tx})
    
    
def cancel_payment_request(chat_id: int, payment_id: int, actor_id: int,
                            is_admin_actor: bool = False) -> OpResult:
    try:
        with _tx() as conn:
            row = conn.execute(
              "SELECT * FROM payment_requests WHERE payment_id=? AND chat_id=?",
              (payment_id, chat_id),
          ).fetchone()
          if not row:
              raise _Abort("NOT_FOUND")
          req = dict(row)
          if req["status"] != PaymentStatus.PENDING.value:
              raise _Abort("ALREADY_PROCESSED")
          if not is_admin_actor and req["requested_by"] != actor_id:
              raise _Abort("FORBIDDEN")
          conn.execute(
              "UPDATE payment_requests SET status=? WHERE payment_id=?",
              (PaymentStatus.CANCELLED.value, payment_id),
          )
    except _Abort as e:
        return OpResult(False, reason=e.reason)
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on cancel_payment_request")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, req["requested_by"], actor=("admin" if is_admin_actor else "user"),
                     action="WALLET_PAYMENT_CANCELLED",
                     detail=f"actor={actor_id} payment_id={payment_id}")
    return OpResult(True, data={"payment_id": payment_id})


def list_payment_requests(chat_id: int, user_id: int, role: str = "payer",
                           status: Optional[str] = None, limit: int = 50) -> List[dict]:
    """role='payer' -> bills directed at me or open to anyone (payer_user_id
    IS NULL OR = me); role='requester' -> bills I created. Used by /bill."""
    conn = _conn()
    if role == "requester":
        query = "SELECT * FROM payment_requests WHERE chat_id=? AND requested_by=?"
    else:
        query = ("SELECT * FROM payment_requests WHERE chat_id=? AND "
                  "(payer_user_id=? OR payer_user_id IS NULL)")
    params: List = [chat_id, user_id]
    if status:
        query += " AND status=?"
        params.append(status)
    query += " ORDER BY payment_id DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------- Debt integration ----------------

def pay_debt_with_wallet(chat_id: int, entry_id: int, payer_user_id: int,
                          idempotency_key: Optional[str] = None) -> OpResult:
    """Settles one unpaid debt_ledger entry using payer_user_id's OWN
    wallet balance, atomically: the wallet debit and the debt_entries
    update commit together or neither does (spec Requirement #8).

    Deliberately open to ANY chat member, not just the named debtor and
    not Admin-only: paying with your own money never risks anyone
    else's balance, so gating it like /paid (which lets an Admin erase
    *anyone's* tab for free) would block the very normal case of one
    member settling a colleague's tab for them. See app.py's
    cmd_debt_pay() for the same rationale next to the handler."""
    import debt_ledger as dl  # local import: the one deliberate cross-module
                               # dependency in this file, see module docstring
                              
    entry = dl.get_entry(entry_id)
    if not entry or entry["chat_id"] != chat_id:
        return OpResult(False, reason="ENTRY_NOT_FOUND")
    if entry["status"] != dl.EntryStatus.UNPAID.value:
        return OpResult(False, reason="ALREADY_PAID")
    amount_satang = entry["amount_satang"]
    
    try:
        with _tx() as conn:
            if idempotency_key:
                existing = _find_by_idempotency_key(conn, chat_id, idempotency_key)
                if existing:
                    return OpResult(True, data={"transaction": existing, "already_processed": True})

            fresh_entry = dl.get_entry_in_conn(conn, entry_id)
            if not fresh_entry or fresh_entry["chat_id"] != chat_id:
                raise _Abort("ENTRY_NOT_FOUND")
            if fresh_entry["status"] != dl.EntryStatus.UNPAID.value:
                raise _Abort("ALREADY_PAID")

            debit_tx = _debit(conn, chat_id, payer_user_id, amount_satang,
                               TxType.DEBT_PAYMENT.value, reference_id=str(entry_id),
                               reason=f"debt entry #{entry_id}: {fresh_entry.get('item_description') or ''}".strip(),
                               idempotency_key=idempotency_key, created_by=payer_user_id)
            if debit_tx is None:
                raise _Abort("INSUFFICIENT_BALANCE")

            amount_satang = fresh_entry["amount_satang"]
            paid_entry = dl._mark_entry_paid_in_conn(conn, fresh_entry, payer_user_id)
    except _Abort as e:
        return OpResult(False, reason=e.reason)
    except sqlite3.Error:
        logger.exception("WALLET DB ERROR on pay_debt_with_wallet")
        return OpResult(False, reason="DB_ERROR")

    write_audit_log(chat_id, payer_user_id, actor="user", action="DEBT_PAID_VIA_WALLET",
                     detail=f"entry_id={entry_id} amount_satang={amount_satang} "
                            f"transaction_id={debit_tx['transaction_id']}")
    return OpResult(True, data={"transaction": debit_tx, "debt_entry": paid_entry})


# ---------------- Admin views ----------------

def list_all_transactions_admin(chat_id: int, user_id: Optional[int] = None, page: int = 1,
                                 page_size: int = 20) -> dict:
    """/admin transactions [user] -- every wallet transaction in this
    chat, optionally filtered to one member, newest first."""
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    conn = _conn()
    query = "SELECT * FROM wallet_transactions WHERE chat_id=?"
    params: List = [chat_id]
    if user_id is not None:
        query += " AND user_id=?"
        params.append(user_id)
    count_row = conn.execute(query.replace("SELECT *", "SELECT COUNT(*) AS c"), params).fetchone()
    total = count_row["c"]
    query += " ORDER BY transaction_id DESC LIMIT ? OFFSET ?"
    params += [page_size, (page - 1) * page_size]
    rows = conn.execute(query, params).fetchall()
    conn.close()
    total_pages = max(1, (total + page_size - 1) // page_size)
    return {
        "items": [dict(r) for r in rows], "page": page, "page_size": page_size,
        "total_count": total, "total_pages": total_pages,
    }