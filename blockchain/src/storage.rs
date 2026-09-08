//! Persistence.
//!
//! Reuses the bot's existing SQLite file (`bot.db`) rather than introducing
//! a second database — same choice every Python data-layer module in this
//! repo already makes via `security.DB_PATH`. Only `CREATE TABLE IF NOT
//! EXISTS` is used; no existing table is read-modified, and nothing outside
//! the three `chain_*` tables is ever written.
//!
//! Journal mode is left exactly as the Python side set it. Switching the
//! file to WAL from here would silently change behaviour for every other
//! module in the bot, which is not this component's call to make.

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::time::Duration;

use crate::block::Block;
use crate::transaction::ChainTransaction;
use crate::{Result, BUSY_TIMEOUT_MS};

pub fn open(db_path: &str) -> Result<Connection> {
    let conn = Connection::open(db_path)?;
    conn.busy_timeout(Duration::from_millis(BUSY_TIMEOUT_MS as u64))?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")?;
    Ok(conn)
}

pub fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS chain_blocks (
            height INTEGER PRIMARY KEY,
            previous_hash TEXT NOT NULL,
            merkle_root TEXT NOT NULL,
            timestamp INTEGER NOT NULL,
            tx_count INTEGER NOT NULL,
            hash TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chain_transactions (
            tx_id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_height INTEGER NOT NULL REFERENCES chain_blocks(height),
            position INTEGER NOT NULL,
            tx_ref TEXT NOT NULL UNIQUE,
            tx_type TEXT NOT NULL,
            source TEXT NOT NULL,
            source_row_id INTEGER NOT NULL,
            chat_id INTEGER NOT NULL,
            user_id INTEGER,
            amount_satang INTEGER NOT NULL DEFAULT 0,
            reference_id TEXT,
            occurred_at INTEGER NOT NULL,
            metadata TEXT,
            payload_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_chain_tx_block
            ON chain_transactions (block_height, position);
        CREATE INDEX IF NOT EXISTS idx_chain_tx_source
            ON chain_transactions (source, source_row_id, tx_type);
        CREATE INDEX IF NOT EXISTS idx_chain_tx_chat
            ON chain_transactions (chat_id, tx_id DESC);
        CREATE TABLE IF NOT EXISTS chain_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );",
    )?;
    Ok(())
}

pub fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO chain_meta (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn get_meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    let value = conn
        .query_row(
            "SELECT value FROM chain_meta WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    Ok(value)
}

pub fn height(conn: &Connection) -> Result<Option<i64>> {
    let h = conn
        .query_row("SELECT MAX(height) FROM chain_blocks", [], |row| {
            row.get::<_, Option<i64>>(0)
        })
        .optional()?
        .flatten();
    Ok(h)
}

pub fn transaction_count(conn: &Connection) -> Result<i64> {
    let n = conn.query_row("SELECT COUNT(*) FROM chain_transactions", [], |row| {
        row.get::<_, i64>(0)
    })?;
    Ok(n)
}

/// Reads one block header (without its transactions).
pub fn load_block(conn: &Connection, height: i64) -> Result<Option<Block>> {
    let block = conn
        .query_row(
            "SELECT height, previous_hash, merkle_root, timestamp, tx_count, hash
             FROM chain_blocks WHERE height = ?1",
            params![height],
            |row| {
                Ok(Block {
                    height: row.get(0)?,
                    previous_hash: row.get(1)?,
                    merkle_root: row.get(2)?,
                    timestamp: row.get(3)?,
                    tx_count: row.get(4)?,
                    hash: row.get(5)?,
                    transactions: Vec::new(),
                })
            },
        )
        .optional()?;
    Ok(block)
}

/// Reads block headers in ascending height order, starting at `from`.
pub fn load_blocks(conn: &Connection, from: i64) -> Result<Vec<Block>> {
    let mut stmt = conn.prepare(
        "SELECT height, previous_hash, merkle_root, timestamp, tx_count, hash
         FROM chain_blocks WHERE height >= ?1 ORDER BY height ASC",
    )?;
    let rows = stmt.query_map(params![from], |row| {
        Ok(Block {
            height: row.get(0)?,
            previous_hash: row.get(1)?,
            merkle_root: row.get(2)?,
            timestamp: row.get(3)?,
            tx_count: row.get(4)?,
            hash: row.get(5)?,
            transactions: Vec::new(),
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn map_tx(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChainTransaction> {
    Ok(ChainTransaction {
        tx_ref: row.get(0)?,
        tx_type: row.get(1)?,
        source: row.get(2)?,
        source_row_id: row.get(3)?,
        chat_id: row.get(4)?,
        user_id: row.get(5)?,
        amount_satang: row.get(6)?,
        reference_id: row.get(7)?,
        occurred_at: row.get(8)?,
        metadata: row.get(9)?,
        payload_hash: row.get(10)?,
    })
}

const TX_COLUMNS: &str = "tx_ref, tx_type, source, source_row_id, chat_id, user_id, \
                          amount_satang, reference_id, occurred_at, metadata, payload_hash";

pub fn load_block_transactions(conn: &Connection, height: i64) -> Result<Vec<ChainTransaction>> {
    let sql = format!(
        "SELECT {} FROM chain_transactions WHERE block_height = ?1 ORDER BY position ASC",
        TX_COLUMNS
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![height], map_tx)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Looks a transaction up by its `tx_ref`, returning it with the height of
/// the block that contains it.
pub fn find_transaction_by_ref(
    conn: &Connection,
    tx_ref: &str,
) -> Result<Option<(ChainTransaction, i64)>> {
    let sql = format!(
        "SELECT {}, block_height FROM chain_transactions WHERE tx_ref = ?1",
        TX_COLUMNS
    );
    let found = conn
        .query_row(&sql, params![tx_ref], |row| {
            let tx = map_tx(row)?;
            let height: i64 = row.get(11)?;
            Ok((tx, height))
        })
        .optional()?;
    Ok(found)
}

/// Every anchor recorded for one source row, oldest first. A row legitimately
/// has several (a debt entry that was signed and later paid; an expense that
/// was edited), which is the append-only history for that row.
pub fn find_transactions_by_source(
    conn: &Connection,
    source: &str,
    source_row_id: i64,
) -> Result<Vec<(ChainTransaction, i64)>> {
    let sql = format!(
        "SELECT {}, block_height FROM chain_transactions
         WHERE source = ?1 AND source_row_id = ?2 ORDER BY tx_id ASC",
        TX_COLUMNS
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(params![source, source_row_id], |row| {
        let tx = map_tx(row)?;
        let height: i64 = row.get(11)?;
        Ok((tx, height))
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// Appends a sealed block and its transactions. Must be called inside the
/// caller's own IMMEDIATE transaction so the block and every transaction in
/// it commit as one unit.
pub fn insert_block(tx: &Transaction<'_>, block: &Block, now: i64) -> Result<()> {
    tx.execute(
        "INSERT INTO chain_blocks
            (height, previous_hash, merkle_root, timestamp, tx_count, hash, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            block.height,
            block.previous_hash,
            block.merkle_root,
            block.timestamp,
            block.tx_count,
            block.hash,
            now
        ],
    )?;
    for (position, ctx) in block.transactions.iter().enumerate() {
        tx.execute(
            "INSERT INTO chain_transactions
                (block_height, position, tx_ref, tx_type, source, source_row_id, chat_id,
                 user_id, amount_satang, reference_id, occurred_at, metadata, payload_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                block.height,
                position as i64,
                ctx.tx_ref,
                ctx.tx_type,
                ctx.source,
                ctx.source_row_id,
                ctx.chat_id,
                ctx.user_id,
                ctx.amount_satang,
                ctx.reference_id,
                ctx.occurred_at,
                ctx.metadata,
                ctx.payload_hash
            ],
        )?;
    }
    Ok(())
}

/// True when the named table exists. The anchor step skips a source whose
/// table has not been created yet, so this component works on a database
/// where, say, expense.py has never run.
pub fn table_exists(conn: &Connection, name: &str) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?1",
            params![name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}
