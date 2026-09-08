"""
chain.py — Python <-> Rust bridge for the append-only verifiable ledger
(blockchain/, crate `sombra-chain`).

WHAT THIS IS. A private, single-node, append-only verifiable ledger. There
is one writer (this bot's host), no peers, no networking, no mining and no
consensus — so it is deliberately NOT described as a decentralized
blockchain anywhere in this codebase or in any user-facing Thai text.

WHAT IT IS NOT. Not a cryptocurrency, not a payment rail, not a second
source of truth for anybody's balance. `bot.db` remains the only place a
balance lives, and nothing in this module or in the Rust crate ever writes
to `wallets`, `wallet_transactions`, `debt_entries` or `expenses`.

HOW IT INTEGRATES — ANCHOR (PULL), NOT DUAL-WRITE. wallet.py,
debt_ledger.py and expense.py are not modified at all. The Rust binary
*reads* rows those modules have already committed and appends them to the
chain. The task brief's three consistency hazards are therefore structurally
impossible rather than merely handled:
  - "balance and ledger disagree": no balance is ever computed here;
  - "chain committed, database failed": the chain can only record rows the
    database already committed;
  - "database committed, chain failed": the chain lags and the next anchor
    run catches up, because every anchor is keyed by a deterministic
    `tx_ref` with a UNIQUE index and is therefore idempotent.
Recovery after a crash, a kill -9, or a week with the binary missing is the
same single action: run `anchor` again.

INTEGRATION STYLE — CLI over subprocess. Chosen over PyO3 bindings (which
would put a Rust toolchain in the critical path of every `pip install`) and
over a local service (a second process to supervise for something that runs
a few times an hour). The binary is also runnable by hand during debugging.

DEGRADED MODE IS A FIRST-CLASS PATH. If the binary is missing, not
executable, times out, crashes, or returns unparseable output, every
function here returns an OpResult-shaped failure and the bot carries on
exactly as before. This module raises nothing; the Telegram bot must never
go down because a ledger component is unhappy. That matters especially on
first deploy, when the Rust binary may not have been built yet.

Design constraints (matches security.py / wallet.py / expense.py):
- Standard library only (asyncio, json, logging, os, shutil, subprocess),
  plus `from security import DB_PATH` -- exactly what every other data-layer
  module here does. Hard-coding a second "bot.db" literal would mean that
  the day someone repoints security.DB_PATH, the ledger would silently keep
  anchoring the old database while the bot wrote to the new one.
- Owns no tables: the Rust crate creates and owns `chain_blocks`,
  `chain_transactions` and `chain_meta` inside the existing `bot.db`.
- No LLM calls, no network.
"""

import os
import json
import shutil
import asyncio
import logging
import subprocess

from security import DB_PATH

logger = logging.getLogger("modbot.chain")

CHAIN_ENABLED = os.getenv("CHAIN_ENABLED", "true").lower() != "false"
CHAIN_BINARY_ENV = os.getenv("CHAIN_BINARY", "").strip()
CHAIN_ANCHOR_INTERVAL = int(os.getenv("CHAIN_ANCHOR_INTERVAL", "300"))
CHAIN_MAX_TX_PER_BLOCK = int(os.getenv("CHAIN_MAX_TX_PER_BLOCK", "500"))
CHAIN_TIMEOUT_SECONDS = float(os.getenv("CHAIN_TIMEOUT", "30"))
CHAIN_STARTUP_DELAY = int(os.getenv("CHAIN_STARTUP_DELAY", "20"))

_HERE = os.path.dirname(os.path.abspath(__file__))
_CANDIDATE_PATHS = (
    os.path.join(_HERE, "blockchain", "target", "release", "sombra-chain"),
    os.path.join(_HERE, "blockchain", "target", "debug", "sombra-chain"),
)


class ChainResult:
    """Same shape as wallet.py's / expense.py's OpResult so app.py handles a
    chain failure with the existing `if not result.ok: deny_text(...)`
    pattern instead of a second convention."""

    __slots__ = ("ok", "reason", "detail", "data")

    def __init__(self, ok, reason="", detail="", data=None):
        self.ok = ok
        self.reason = reason
        self.detail = detail
        self.data = data or {}

    def __repr__(self):
        return f"ChainResult(ok={self.ok!r}, reason={self.reason!r})"


def find_binary():
    """Locates the compiled Rust binary, or returns None. Checked on every
    call rather than cached at import: a deploy that builds the binary after
    the worker has already started then heals on the next anchor tick
    instead of needing a restart."""
    if CHAIN_BINARY_ENV:
        return CHAIN_BINARY_ENV if os.access(CHAIN_BINARY_ENV, os.X_OK) else None
    for path in _CANDIDATE_PATHS:
        if os.access(path, os.X_OK):
            return path
    return shutil.which("sombra-chain")


def is_available():
    return CHAIN_ENABLED and find_binary() is not None


def _decode(stdout, stderr, returncode):
    """The Rust CLI prints exactly one JSON object on stdout for both
    success and failure, so parse first and only fall back to the exit code
    if that fails."""
    text = (stdout or b"").decode("utf-8", errors="replace").strip()
    if not text:
        detail = (stderr or b"").decode("utf-8", errors="replace").strip()
        return ChainResult(False, reason="CHAIN_NO_OUTPUT",
                           detail=detail[:500] or f"exit code {returncode}")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("CHAIN: unparseable output from sombra-chain: %s", text[:300])
        return ChainResult(False, reason="CHAIN_BAD_OUTPUT", detail=text[:500])
    if not isinstance(payload, dict):
        return ChainResult(False, reason="CHAIN_BAD_OUTPUT", detail=text[:500])
    if payload.get("ok") is False and "error" in payload:
        return ChainResult(False, reason=str(payload.get("error")),
                           detail=str(payload.get("detail", ""))[:500], data=payload)
    return ChainResult(True, data=payload)


def _argv(binary, command, extra=None):
    argv = [binary, command, "--db", DB_PATH]
    if extra:
        argv.extend(extra)
    return argv


async def _run(command, extra=None, timeout=None):
    """Runs one CLI subcommand without blocking the event loop.

    Every failure mode -- binary missing, non-zero exit, timeout, OS-level
    spawn error -- comes back as a ChainResult. Nothing raises."""
    if not CHAIN_ENABLED:
        return ChainResult(False, reason="CHAIN_DISABLED")
    binary = find_binary()
    if not binary:
        return ChainResult(False, reason="CHAIN_UNAVAILABLE")

    argv = _argv(binary, command, extra)
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError:
        logger.exception("CHAIN: failed to start %s", binary)
        return ChainResult(False, reason="CHAIN_UNAVAILABLE")

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout or CHAIN_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError:
        # Kill rather than leave an orphan holding SQLite's write lock,
        # which would stall every /transfer and /debt_pay in the group.
        try:
            process.kill()
            await process.wait()
        except (ProcessLookupError, OSError):
            pass
        logger.warning("CHAIN: %s timed out after %.0fs", command, timeout or CHAIN_TIMEOUT_SECONDS)
        return ChainResult(False, reason="CHAIN_TIMEOUT")

    return _decode(stdout, stderr, process.returncode)


def _run_sync(command, extra=None, timeout=None):
    """Blocking variant, used only by chain_db_init() at process start --
    before the event loop is running, exactly like every other *_db_init()
    in this repo."""
    if not CHAIN_ENABLED:
        return ChainResult(False, reason="CHAIN_DISABLED")
    binary = find_binary()
    if not binary:
        return ChainResult(False, reason="CHAIN_UNAVAILABLE")
    try:
        completed = subprocess.run(
            _argv(binary, command, extra),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout or CHAIN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return ChainResult(False, reason="CHAIN_TIMEOUT")
    except OSError:
        logger.exception("CHAIN: failed to start %s", binary)
        return ChainResult(False, reason="CHAIN_UNAVAILABLE")
    return _decode(completed.stdout, completed.stderr, completed.returncode)


# ---------------- Public API ----------------

def chain_db_init():
    """Creates the chain tables and the deterministic genesis block if they
    are absent. Idempotent and non-fatal: a missing or unbuilt binary logs a
    warning and the bot starts normally without the ledger."""
    if not CHAIN_ENABLED:
        logger.info("CHAIN DATABASE: disabled (CHAIN_ENABLED=false)")
        return ChainResult(False, reason="CHAIN_DISABLED")
    result = _run_sync("init")
    if result.ok:
        logger.info("CHAIN DATABASE: OK (genesis_created=%s)",
                    result.data.get("genesis_created"))
    else:
        logger.warning(
            "CHAIN DATABASE: unavailable (%s) -- the bot runs normally, but "
            "nothing is anchored until blockchain/ is built with "
            "`cargo build --release`", result.reason,
        )
    return result


async def anchor_now(max_tx=None):
    """Appends at most one block containing everything committed but not yet
    anchored. Safe to call concurrently with itself: the Rust side takes
    SQLite's write lock with BEGIN IMMEDIATE and the loser finds nothing
    left to do."""
    budget = CHAIN_MAX_TX_PER_BLOCK if max_tx is None else max_tx
    return await _run("anchor", ["--max-tx", str(budget)])


async def get_status():
    return await _run("status")


async def verify_chain(from_height=0):
    """Structural integrity of the chain itself: hashes, links, Merkle
    roots, duplicate transactions."""
    return await _run("verify", ["--from", str(max(0, int(from_height)))])


async def reconcile(limit=0):
    """Compares each anchored payload against the source row as it stands
    today -- catches an edit made straight against the database, which
    verify_chain() cannot see because the chain itself stays well formed.
    Rows still waiting to be anchored are skipped, so a backlog never looks
    like tampering."""
    return await _run("reconcile", ["--limit", str(max(0, int(limit)))])


async def get_block(height):
    return await _run("block", ["--height", str(int(height))])


async def find_transaction(needle):
    """Accepts a chain tx_ref ('wallet_tx:12', 'debt_entry:7:paid'), a
    'source:id' pair, or a bare wallet transaction id as shown by /history."""
    return await _run("tx", ["--ref", str(needle)])


# ---------------- Background anchoring ----------------

async def chain_background_loop():
    """Periodic anchoring, mirroring news.py's news_background_loop():
    sleep, work, swallow every exception, repeat.

    Deliberately a background loop rather than a hook on each wallet write.
    Anchoring inside a command handler would add a subprocess spawn to the
    latency of every /transfer and, worse, would want SQLite's write lock
    while wallet.py is still holding it. Lagging by one interval is the
    correct trade for an audit log."""
    if not CHAIN_ENABLED:
        return
    await asyncio.sleep(CHAIN_STARTUP_DELAY)
    while True:
        try:
            result = await anchor_now()
            if result.ok:
                anchored = result.data.get("anchored", 0)
                if anchored:
                    logger.info("CHAIN ANCHOR: %s transaction(s) into block %s",
                                anchored, result.data.get("height"))
            elif result.reason not in ("CHAIN_UNAVAILABLE", "CHAIN_DISABLED"):
                logger.warning("CHAIN ANCHOR FAILED: %s %s", result.reason, result.detail)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("CHAIN BACKGROUND LOOP ERROR")
        await asyncio.sleep(CHAIN_ANCHOR_INTERVAL)
