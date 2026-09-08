//! Chain operations: bootstrap, anchor, status, lookup, reconcile.

use rusqlite::{params, Connection, TransactionBehavior};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::block::Block;
use crate::storage;
use crate::transaction::{
    self, ChainTransaction, SOURCE_DEBT, SOURCE_EXPENSE, SOURCE_WALLET, TX_DEBT_PAID,
    TX_EXPENSE_ADDED, TX_EXPENSE_DELETED, TX_EXPENSE_REVISED,
};
use crate::{ChainError, Result, DEFAULT_MAX_TX_PER_BLOCK};

pub fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Creates the schema and, if the chain is empty, writes the deterministic
/// genesis block. Idempotent: safe to run on every bot start.
pub fn init(conn: &mut Connection) -> Result<bool> {
    storage::init_schema(conn)?;
    if storage::height(conn)?.is_some() {
        return Ok(false);
    }
    let genesis = Block::genesis();
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Re-check inside the write lock: two processes may have raced here.
    let already: Option<i64> = {
        use rusqlite::OptionalExtension;
        tx.query_row("SELECT MAX(height) FROM chain_blocks", [], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .optional()?
        .flatten()
    };
    if already.is_some() {
        tx.rollback()?;
        return Ok(false);
    }
    storage::insert_block(&tx, &genesis, now_epoch())?;
    tx.execute(
        "INSERT INTO chain_meta (key, value) VALUES ('chain_domain', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![crate::CHAIN_DOMAIN],
    )?;
    tx.commit()?;
    Ok(true)
}

// ---------------- Anchoring ----------------

/// Reads source rows that the chain has not recorded yet.
///
/// Every predicate is a `NOT EXISTS` anti-join against `chain_transactions`,
/// so anchoring is exactly-once per state without a mutable cursor that
/// could drift, be reset, or skip a row that settled out of id order (a
/// pending deposit confirmed after a later transfer already committed).
fn collect_pending(conn: &Connection, budget: usize) -> Result<Vec<ChainTransaction>> {
    let mut out: Vec<ChainTransaction> = Vec::new();

    // --- wallet_transactions ---
    // Only terminal rows. wallet.py moves a row pending -> completed or
    // pending -> cancelled and never out again, so a terminal row's fields
    // are frozen and one anchor per row is correct and final.
    if storage::table_exists(conn, "wallet_transactions")? {
        let remaining = budget.saturating_sub(out.len());
        if remaining > 0 {
            let mut stmt = conn.prepare(
                "SELECT w.transaction_id, w.chat_id, w.user_id, w.type, w.amount_satang,
                        w.balance_before_satang, w.balance_after_satang, w.status,
                        w.reference_id, w.counterparty_user_id, w.created_at
                 FROM wallet_transactions w
                 WHERE w.status IN ('completed', 'cancelled')
                   AND NOT EXISTS (
                       SELECT 1 FROM chain_transactions c
                       WHERE c.source = 'wallet_tx' AND c.source_row_id = w.transaction_id)
                 ORDER BY w.transaction_id ASC
                 LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![remaining as i64], |row| {
                Ok(transaction::from_wallet_row(
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    &row.get::<_, String>(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    &row.get::<_, String>(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                ))
            })?;
            for row in rows {
                out.push(row?);
            }
        }
    }

    // --- debt_entries: signed ---
    if storage::table_exists(conn, "debt_entries")? {
        let remaining = budget.saturating_sub(out.len());
        if remaining > 0 {
            let mut stmt = conn.prepare(
                "SELECT e.entry_id, e.chat_id, e.debtor_name, e.amount_satang,
                        e.item_description, e.entry_date, e.recorded_by, e.created_at
                 FROM debt_entries e
                 WHERE NOT EXISTS (
                       SELECT 1 FROM chain_transactions c
                       WHERE c.source = 'debt_entry' AND c.source_row_id = e.entry_id
                         AND c.tx_type = 'debt_signed')
                 ORDER BY e.entry_id ASC
                 LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![remaining as i64], |row| {
                let description: Option<String> = row.get(4)?;
                Ok(transaction::from_debt_signed(
                    row.get(0)?,
                    row.get(1)?,
                    &row.get::<_, String>(2)?,
                    row.get(3)?,
                    description.as_deref(),
                    &row.get::<_, String>(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })?;
            for row in rows {
                out.push(row?);
            }
        }

        // --- debt_entries: paid ---
        // A second, separate append rather than an edit of the signed
        // anchor. The debt's own business logic stays entirely in
        // debt_ledger.py: nothing here marks anything paid or unpaid.
        let remaining = budget.saturating_sub(out.len());
        if remaining > 0 {
            let mut stmt = conn.prepare(
                "SELECT e.entry_id, e.chat_id, e.debtor_name, e.amount_satang,
                        e.paid_by, e.paid_at
                 FROM debt_entries e
                 WHERE e.status = 'paid' AND e.paid_at IS NOT NULL
                   AND NOT EXISTS (
                       SELECT 1 FROM chain_transactions c
                       WHERE c.source = 'debt_entry' AND c.source_row_id = e.entry_id
                         AND c.tx_type = 'debt_paid')
                 ORDER BY e.entry_id ASC
                 LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![remaining as i64], |row| {
                Ok(transaction::from_debt_paid(
                    row.get(0)?,
                    row.get(1)?,
                    &row.get::<_, String>(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?;
            for row in rows {
                out.push(row?);
            }
        }
    }

    // --- expenses ---
    // Expense rows are editable and soft-deletable, so one anchor per
    // distinct `updated_at`: the first is expense_added, later ones are
    // expense_revised, and the soft delete is expense_deleted. The
    // `c.occurred_at >= e.updated_at` guard is the anti-join.
    //
    // Known, accepted limitation: two edits inside the same clock second
    // share one `updated_at` and therefore collapse into a single anchor.
    // Recording an expense still never touches a wallet balance.
    if storage::table_exists(conn, "expenses")? {
        let remaining = budget.saturating_sub(out.len());
        if remaining > 0 {
            let mut stmt = conn.prepare(
                "SELECT e.expense_id, e.chat_id, e.user_id, e.amount_satang, e.category,
                        e.description, e.expense_date, e.wallet_transaction_id,
                        e.debt_entry_id, e.created_at, e.updated_at, e.deleted_at
                 FROM expenses e
                 WHERE NOT EXISTS (
                       SELECT 1 FROM chain_transactions c
                       WHERE c.source = 'expense' AND c.source_row_id = e.expense_id
                         AND c.occurred_at >= e.updated_at)
                 ORDER BY e.expense_id ASC
                 LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![remaining as i64], |row| {
                let description: Option<String> = row.get(5)?;
                let created_at: i64 = row.get(9)?;
                let updated_at: i64 = row.get(10)?;
                let deleted_at: Option<i64> = row.get(11)?;
                let kind = expense_kind(created_at, updated_at, deleted_at);
                Ok(transaction::from_expense_row(
                    kind,
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    &row.get::<_, String>(4)?,
                    description.as_deref(),
                    &row.get::<_, String>(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    updated_at,
                    updated_at,
                ))
            })?;
            for row in rows {
                out.push(row?);
            }
        }
    }

    Ok(out)
}

/// Which expense anchor a row's current state represents.
pub fn expense_kind(created_at: i64, updated_at: i64, deleted_at: Option<i64>) -> &'static str {
    if deleted_at.is_some() {
        TX_EXPENSE_DELETED
    } else if updated_at > created_at {
        TX_EXPENSE_REVISED
    } else {
        TX_EXPENSE_ADDED
    }
}

/// Appends at most one block containing everything not yet anchored.
///
/// The candidate read and the block insert happen inside the same
/// `BEGIN IMMEDIATE` transaction, so a concurrent anchor run cannot pick up
/// the same rows: the second one blocks on the write lock and then finds the
/// anti-join empty. If the process dies mid-run, nothing is committed and
/// the next run simply re-collects the same rows.
pub fn anchor(conn: &mut Connection, max_tx: usize) -> Result<serde_json::Value> {
    storage::init_schema(conn)?;
    let budget = if max_tx == 0 { DEFAULT_MAX_TX_PER_BLOCK } else { max_tx };

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = {
        let tip_height: i64 = {
            use rusqlite::OptionalExtension;
            tx.query_row("SELECT MAX(height) FROM chain_blocks", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .optional()?
            .flatten()
            .ok_or_else(|| {
                ChainError::Invalid("chain is not initialized; run `init` first".to_string())
            })?
        };
        let previous_hash: String = tx.query_row(
            "SELECT hash FROM chain_blocks WHERE height = ?1",
            params![tip_height],
            |row| row.get(0),
        )?;

        let pending = collect_pending(&tx, budget)?;
        if pending.is_empty() {
            serde_json::json!({
                "ok": true,
                "anchored": 0,
                "height": tip_height,
                "block": serde_json::Value::Null,
            })
        } else {
            let block = Block::new(tip_height + 1, previous_hash, now_epoch(), pending);
            storage::insert_block(&tx, &block, now_epoch())?;
            tx.execute(
                "INSERT INTO chain_meta (key, value) VALUES ('last_anchor_at', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![now_epoch().to_string()],
            )?;
            serde_json::json!({
                "ok": true,
                "anchored": block.tx_count,
                "height": block.height,
                "block": block.to_json(false),
            })
        }
    };
    tx.commit()?;
    Ok(result)
}

// ---------------- Read operations ----------------

pub fn status(conn: &Connection) -> Result<serde_json::Value> {
    storage::init_schema(conn)?;
    let height = storage::height(conn)?;
    let tx_count = storage::transaction_count(conn)?;
    let tip_hash = match height {
        Some(h) => storage::load_block(conn, h)?.map(|b| b.hash),
        None => None,
    };
    let pending = collect_pending(conn, DEFAULT_MAX_TX_PER_BLOCK)?.len() as i64;
    Ok(serde_json::json!({
        "ok": true,
        "initialized": height.is_some(),
        "height": height,
        "block_count": height.map(|h| h + 1),
        "transaction_count": tx_count,
        "tip_hash": tip_hash,
        "pending_transactions": pending,
        "pending_capped_at": DEFAULT_MAX_TX_PER_BLOCK,
        "last_anchor_at": storage::get_meta(conn, "last_anchor_at")?
            .and_then(|v| v.parse::<i64>().ok()),
        "chain_domain": crate::CHAIN_DOMAIN,
    }))
}

pub fn get_block(conn: &Connection, height: i64) -> Result<serde_json::Value> {
    let mut block = match storage::load_block(conn, height)? {
        Some(b) => b,
        None => {
            return Ok(serde_json::json!({"ok": false, "error": "BLOCK_NOT_FOUND",
                                         "height": height}))
        }
    };
    block.transactions = storage::load_block_transactions(conn, height)?;
    Ok(serde_json::json!({"ok": true, "block": block.to_json(true)}))
}

/// Looks up by exact `tx_ref` first, then falls back to every anchor
/// recorded for a `source:row_id` pair.
pub fn find_transaction(conn: &Connection, needle: &str) -> Result<serde_json::Value> {
    if let Some((tx, height)) = storage::find_transaction_by_ref(conn, needle)? {
        let mut value = tx.to_json();
        value["block_height"] = serde_json::json!(height);
        value["hash_consistent"] = serde_json::json!(tx.hash_is_consistent());
        return Ok(serde_json::json!({"ok": true, "matches": [value]}));
    }

    let (source, row_id) = match parse_source_ref(needle) {
        Some(pair) => pair,
        None => {
            return Ok(serde_json::json!({"ok": false, "error": "TRANSACTION_NOT_FOUND",
                                         "query": needle}))
        }
    };
    let found = storage::find_transactions_by_source(conn, source, row_id)?;
    if found.is_empty() {
        return Ok(serde_json::json!({"ok": false, "error": "TRANSACTION_NOT_FOUND",
                                     "query": needle}));
    }
    let matches: Vec<serde_json::Value> = found
        .into_iter()
        .map(|(tx, height)| {
            let mut value = tx.to_json();
            value["block_height"] = serde_json::json!(height);
            value["hash_consistent"] = serde_json::json!(tx.hash_is_consistent());
            value
        })
        .collect();
    Ok(serde_json::json!({"ok": true, "matches": matches}))
}

/// Accepts `wallet_tx:12`, `debt_entry:7`, `expense:3`, or a bare number
/// (treated as a wallet transaction id, since that is the id users see in
/// /history and /wallet_admin transactions).
fn parse_source_ref(needle: &str) -> Option<(&'static str, i64)> {
    if let Ok(id) = needle.trim().parse::<i64>() {
        return Some((SOURCE_WALLET, id));
    }
    let (prefix, rest) = needle.split_once(':')?;
    let id = rest.split(':').next()?.parse::<i64>().ok()?;
    match prefix {
        SOURCE_WALLET | "wallet" => Some((SOURCE_WALLET, id)),
        SOURCE_DEBT | "debt" => Some((SOURCE_DEBT, id)),
        SOURCE_EXPENSE => Some((SOURCE_EXPENSE, id)),
        _ => None,
    }
}

// ---------------- Reconciliation against the live source rows ----------------

/// Recomputes each anchored payload from the source row as it stands today
/// and reports any divergence.
///
/// `verify` proves the chain has not been rewritten. This proves the
/// *database* has not been edited behind the chain's back — an UPDATE
/// straight against `wallet_transactions` shows up here even though the
/// chain itself is perfectly well formed.
///
/// Rows with anchoring still pending are excluded rather than reported, so
/// a normal backlog never looks like tampering.
fn push_mismatch(
    problems: &mut Vec<serde_json::Value>,
    tx_ref: &str,
    stored: &str,
    recomputed: &str,
) {
    if stored != recomputed {
        problems.push(serde_json::json!({
            "tx_ref": tx_ref,
            "stored_payload_hash": stored,
            "recomputed_payload_hash": recomputed,
        }));
    }
}

pub fn reconcile(conn: &Connection, limit: usize) -> Result<serde_json::Value> {
    let cap = if limit == 0 { 5000 } else { limit } as i64;
    let mut checked: i64 = 0;
    let mut problems: Vec<serde_json::Value> = Vec::new();


    if storage::table_exists(conn, "wallet_transactions")? {
        let mut stmt = conn.prepare(
            "SELECT c.payload_hash, w.transaction_id, w.chat_id, w.user_id, w.type,
                    w.amount_satang, w.balance_before_satang, w.balance_after_satang,
                    w.status, w.reference_id, w.counterparty_user_id, w.created_at
             FROM chain_transactions c
             JOIN wallet_transactions w ON w.transaction_id = c.source_row_id
             WHERE c.source = 'wallet_tx'
             ORDER BY c.tx_id ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![cap], |row| {
            let stored: String = row.get(0)?;
            let rebuilt = transaction::from_wallet_row(
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                &row.get::<_, String>(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                &row.get::<_, String>(8)?,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
            );
            Ok((stored, rebuilt))
        })?;
        for row in rows {
            let (stored, rebuilt) = row?;
            checked += 1;
            push_mismatch(&mut problems, &rebuilt.tx_ref, &stored, &rebuilt.payload_hash);
        }
    }

    if storage::table_exists(conn, "debt_entries")? {
        let mut stmt = conn.prepare(
            "SELECT c.payload_hash, c.tx_type, e.entry_id, e.chat_id, e.debtor_name,
                    e.amount_satang, e.item_description, e.entry_date, e.recorded_by,
                    e.created_at, e.paid_by, e.paid_at
             FROM chain_transactions c
             JOIN debt_entries e ON e.entry_id = c.source_row_id
             WHERE c.source = 'debt_entry'
             ORDER BY c.tx_id ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![cap], |row| {
            let stored: String = row.get(0)?;
            let tx_type: String = row.get(1)?;
            let description: Option<String> = row.get(6)?;
            let paid_at: Option<i64> = row.get(11)?;
            let rebuilt = if tx_type == TX_DEBT_PAID {
                transaction::from_debt_paid(
                    row.get(2)?,
                    row.get(3)?,
                    &row.get::<_, String>(4)?,
                    row.get(5)?,
                    row.get(10)?,
                    paid_at.unwrap_or(0),
                )
            } else {
                transaction::from_debt_signed(
                    row.get(2)?,
                    row.get(3)?,
                    &row.get::<_, String>(4)?,
                    row.get(5)?,
                    description.as_deref(),
                    &row.get::<_, String>(7)?,
                    row.get(8)?,
                    row.get(9)?,
                )
            };
            Ok((stored, rebuilt))
        })?;
        for row in rows {
            let (stored, rebuilt) = row?;
            checked += 1;
            push_mismatch(&mut problems, &rebuilt.tx_ref, &stored, &rebuilt.payload_hash);
        }
    }

    if storage::table_exists(conn, "expenses")? {
        let mut stmt = conn.prepare(
            "SELECT c.payload_hash, e.expense_id, e.chat_id, e.user_id, e.amount_satang,
                    e.category, e.description, e.expense_date, e.wallet_transaction_id,
                    e.debt_entry_id, e.created_at, e.updated_at, e.deleted_at
             FROM chain_transactions c
             JOIN expenses e ON e.expense_id = c.source_row_id
             WHERE c.source = 'expense' AND c.occurred_at >= e.updated_at
             ORDER BY c.tx_id ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![cap], |row| {
            let stored: String = row.get(0)?;
            let description: Option<String> = row.get(6)?;
            let created_at: i64 = row.get(10)?;
            let updated_at: i64 = row.get(11)?;
            let deleted_at: Option<i64> = row.get(12)?;
            let kind = expense_kind(created_at, updated_at, deleted_at);
            let rebuilt = transaction::from_expense_row(
                kind,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                &row.get::<_, String>(5)?,
                description.as_deref(),
                &row.get::<_, String>(7)?,
                row.get(8)?,
                row.get(9)?,
                updated_at,
                updated_at,
            );
            Ok((stored, rebuilt))
        })?;
        for row in rows {
            let (stored, rebuilt) = row?;
            checked += 1;
            push_mismatch(&mut problems, &rebuilt.tx_ref, &stored, &rebuilt.payload_hash);
        }
    }

    let mismatches = problems.len();
    let clean = problems.is_empty();
    let shown: Vec<serde_json::Value> = problems.into_iter().take(50).collect();
    Ok(serde_json::json!({
        "ok": clean,
        "checked": checked,
        "mismatches": mismatches,
        "problems": shown,
    }))
}

/// Convenience wrapper used by the CLI and by the integration tests.
pub fn verify(conn: &Connection, from: i64) -> Result<serde_json::Value> {
    let report = crate::validation::validate_chain(conn, from)?;
    Ok(report.to_json())
}

/// Guard used by the CLI: a genesis-only chain is valid but has nothing to
/// anchor, and callers should be able to tell the two apart.
pub fn is_initialized(conn: &Connection) -> Result<bool> {
    Ok(storage::height(conn)?.is_some())
}
