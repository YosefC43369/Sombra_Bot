//! Integration tests for the append-only verifiable ledger.
//!
//! Each test gets its own throwaway SQLite file seeded with the same source
//! tables the Python side creates (wallet.py's `wallet_transactions`,
//! debt_ledger.py's `debt_entries`, expense.py's `expenses`), so anchoring
//! is exercised against the real column layout rather than a mock.
//!
//! No `tempfile` dev-dependency: a counter plus the process id is enough
//! isolation here and keeps the build graph minimal.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::{params, Connection};
use sombra_chain::block::{merkle_root, Block};
use sombra_chain::validation::validate_chain;
use sombra_chain::{chain, storage, ZERO_HASH};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDb {
    path: PathBuf,
}

impl TempDb {
    fn new() -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!("sombra_chain_test_{}_{}.db", std::process::id(), n));
        let _ = std::fs::remove_file(&path);
        let db = TempDb { path };
        db.seed();
        db
    }

    fn path(&self) -> &str {
        self.path.to_str().expect("temp path is valid utf-8")
    }

    fn conn(&self) -> Connection {
        storage::open(self.path()).expect("open temp db")
    }

    /// Mirrors the columns the anchor queries read from each Python module.
    fn seed(&self) {
        let conn = Connection::open(&self.path).expect("create temp db");
        conn.execute_batch(
            "CREATE TABLE wallet_transactions (
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
            );
            CREATE TABLE debt_entries (
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
            );
            CREATE TABLE expenses (
                expense_id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                amount_satang INTEGER NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                expense_date TEXT NOT NULL,
                wallet_transaction_id INTEGER,
                debt_entry_id INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                deleted_at INTEGER
            );",
        )
        .expect("seed source tables");
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn add_wallet_tx(conn: &Connection, user_id: i64, tx_type: &str, satang: i64, status: &str) -> i64 {
    conn.execute(
        "INSERT INTO wallet_transactions
            (chat_id, user_id, type, amount_satang, balance_before_satang,
             balance_after_satang, status, created_by, created_at)
         VALUES (1, ?1, ?2, ?3, 0, ?3, ?4, ?1, 1700000000)",
        params![user_id, tx_type, satang, status],
    )
    .expect("insert wallet tx");
    conn.last_insert_rowid()
}

fn add_debt_entry(conn: &Connection, name: &str, satang: i64) -> i64 {
    conn.execute(
        "INSERT INTO debt_entries
            (chat_id, debtor_name, amount_satang, item_description, status,
             entry_date, recorded_by, created_at)
         VALUES (1, ?1, ?2, 'กาแฟ', 'unpaid', '2026-01-05', 42, 1700000000)",
        params![name, satang],
    )
    .expect("insert debt entry");
    conn.last_insert_rowid()
}

fn add_expense(conn: &Connection, satang: i64) -> i64 {
    conn.execute(
        "INSERT INTO expenses
            (chat_id, user_id, amount_satang, category, description, expense_date,
             created_at, updated_at)
         VALUES (1, 7, ?1, 'food', 'ข้าวมันไก่', '2026-01-05', 1700000000, 1700000000)",
        params![satang],
    )
    .expect("insert expense");
    conn.last_insert_rowid()
}

// ---------------- Genesis ----------------

#[test]
fn genesis_is_deterministic_across_databases() {
    let a = TempDb::new();
    let b = TempDb::new();
    let mut ca = a.conn();
    let mut cb = b.conn();
    assert!(chain::init(&mut ca).unwrap());
    assert!(chain::init(&mut cb).unwrap());

    let ga = storage::load_block(&ca, 0).unwrap().unwrap();
    let gb = storage::load_block(&cb, 0).unwrap().unwrap();
    assert_eq!(ga.hash, gb.hash);
    assert_eq!(ga.hash, Block::genesis().hash);
    assert_eq!(ga.previous_hash, ZERO_HASH);
    assert_eq!(ga.merkle_root, ZERO_HASH);
    assert_eq!(ga.timestamp, 0);
    assert_eq!(ga.tx_count, 0);
}

#[test]
fn init_is_idempotent() {
    let db = TempDb::new();
    let mut conn = db.conn();
    assert!(chain::init(&mut conn).unwrap());
    assert!(!chain::init(&mut conn).unwrap());
    assert_eq!(storage::height(&conn).unwrap(), Some(0));
}

// ---------------- Block creation and hashing ----------------

#[test]
fn hashing_is_stable_and_sensitive() {
    let tx = sombra_chain::transaction::from_wallet_row(
        1, 1, 7, "deposit", 5000, 0, 5000, "completed", None, None, 1700000000,
    );
    assert_eq!(tx.payload_hash, tx.compute_payload_hash());
    assert!(tx.hash_is_consistent());

    let other = sombra_chain::transaction::from_wallet_row(
        1, 1, 7, "deposit", 5001, 0, 5001, "completed", None, None, 1700000000,
    );
    assert_ne!(tx.payload_hash, other.payload_hash);

    let block = Block::new(1, ZERO_HASH.to_string(), 1700000100, vec![tx.clone()]);
    assert_eq!(block.hash, block.recompute_hash());
    assert_eq!(block.merkle_root, merkle_root(&[tx.payload_hash.clone()]));
    assert_eq!(block.tx_count, 1);
}

#[test]
fn merkle_root_handles_empty_and_odd_sets() {
    assert_eq!(merkle_root(&[]), ZERO_HASH);
    let one = merkle_root(&["aa".to_string()]);
    assert_eq!(one, "aa");
    let three = merkle_root(&["aa".to_string(), "bb".to_string(), "cc".to_string()]);
    let four = merkle_root(&[
        "aa".to_string(),
        "bb".to_string(),
        "cc".to_string(),
        "cc".to_string(),
    ]);
    assert_eq!(three, four, "an odd trailing node is paired with itself");
}

// ---------------- Anchoring ----------------

#[test]
fn anchor_records_terminal_wallet_rows_only() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();

    add_wallet_tx(&conn, 7, "deposit", 5000, "completed");
    let pending_id = add_wallet_tx(&conn, 7, "withdrawal", 1000, "pending");

    let result = chain::anchor(&mut conn, 0).unwrap();
    assert_eq!(result["anchored"], 1);
    assert_eq!(result["height"], 1);

    // The pending row is picked up only once it settles.
    conn.execute(
        "UPDATE wallet_transactions SET status='completed' WHERE transaction_id=?1",
        params![pending_id],
    )
    .unwrap();
    let result = chain::anchor(&mut conn, 0).unwrap();
    assert_eq!(result["anchored"], 1);
    assert_eq!(result["height"], 2);
}

#[test]
fn anchoring_is_idempotent_and_rejects_duplicates() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    add_wallet_tx(&conn, 7, "deposit", 5000, "completed");

    assert_eq!(chain::anchor(&mut conn, 0).unwrap()["anchored"], 1);
    // Nothing left to do: no empty block is appended either.
    let second = chain::anchor(&mut conn, 0).unwrap();
    assert_eq!(second["anchored"], 0);
    assert_eq!(storage::height(&conn).unwrap(), Some(1));
    assert_eq!(storage::transaction_count(&conn).unwrap(), 1);

    // The UNIQUE tx_ref index is the backstop against a duplicate anchor.
    let duplicate = conn.execute(
        "INSERT INTO chain_transactions
            (block_height, position, tx_ref, tx_type, source, source_row_id, chat_id,
             user_id, amount_satang, occurred_at, payload_hash)
         VALUES (1, 99, 'wallet_tx:1', 'deposit', 'wallet_tx', 1, 1, 7, 5000, 1, 'x')",
        [],
    );
    assert!(duplicate.is_err(), "duplicate tx_ref must be rejected");
}

#[test]
fn debt_signing_and_payment_anchor_separately() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    let entry_id = add_debt_entry(&conn, "สมชาย", 25000);

    assert_eq!(chain::anchor(&mut conn, 0).unwrap()["anchored"], 1);

    conn.execute(
        "UPDATE debt_entries SET status='paid', paid_at=1700000500, paid_by=7 WHERE entry_id=?1",
        params![entry_id],
    )
    .unwrap();
    assert_eq!(chain::anchor(&mut conn, 0).unwrap()["anchored"], 1);

    let history = storage::find_transactions_by_source(&conn, "debt_entry", entry_id).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].0.tx_type, "debt_signed");
    assert_eq!(history[1].0.tx_type, "debt_paid");
    // The signed anchor is untouched by the payment — append, never edit.
    assert!(history[0].0.hash_is_consistent());
}

#[test]
fn expense_edits_and_deletes_append_new_anchors() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    let expense_id = add_expense(&conn, 15000);

    assert_eq!(chain::anchor(&mut conn, 0).unwrap()["anchored"], 1);

    conn.execute(
        "UPDATE expenses SET amount_satang=17000, updated_at=1700000600 WHERE expense_id=?1",
        params![expense_id],
    )
    .unwrap();
    assert_eq!(chain::anchor(&mut conn, 0).unwrap()["anchored"], 1);

    conn.execute(
        "UPDATE expenses SET deleted_at=1700000900, updated_at=1700000900 WHERE expense_id=?1",
        params![expense_id],
    )
    .unwrap();
    assert_eq!(chain::anchor(&mut conn, 0).unwrap()["anchored"], 1);

    let history = storage::find_transactions_by_source(&conn, "expense", expense_id).unwrap();
    let kinds: Vec<&str> = history.iter().map(|(t, _)| t.tx_type.as_str()).collect();
    assert_eq!(
        kinds,
        vec!["expense_added", "expense_revised", "expense_deleted"]
    );
    assert_eq!(chain::anchor(&mut conn, 0).unwrap()["anchored"], 0);
}

#[test]
fn anchor_respects_the_per_block_budget() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    for _ in 0..5 {
        add_wallet_tx(&conn, 7, "deposit", 100, "completed");
    }
    assert_eq!(chain::anchor(&mut conn, 2).unwrap()["anchored"], 2);
    assert_eq!(chain::anchor(&mut conn, 2).unwrap()["anchored"], 2);
    assert_eq!(chain::anchor(&mut conn, 2).unwrap()["anchored"], 1);
    assert_eq!(chain::anchor(&mut conn, 2).unwrap()["anchored"], 0);
}

// ---------------- Persistence ----------------

#[test]
fn chain_survives_reopening_the_database() {
    let db = TempDb::new();
    let tip_hash;
    {
        let mut conn = db.conn();
        chain::init(&mut conn).unwrap();
        add_wallet_tx(&conn, 7, "deposit", 5000, "completed");
        chain::anchor(&mut conn, 0).unwrap();
        tip_hash = storage::load_block(&conn, 1).unwrap().unwrap().hash;
    }
    let conn = db.conn();
    let reopened = storage::load_block(&conn, 1).unwrap().unwrap();
    assert_eq!(reopened.hash, tip_hash);
    assert_eq!(storage::load_block_transactions(&conn, 1).unwrap().len(), 1);
    assert!(validate_chain(&conn, 0).unwrap().ok);
}

// ---------------- Validation ----------------

#[test]
fn a_healthy_chain_validates() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    add_wallet_tx(&conn, 7, "deposit", 5000, "completed");
    add_debt_entry(&conn, "สมหญิง", 12000);
    add_expense(&conn, 8000);
    chain::anchor(&mut conn, 0).unwrap();

    let report = validate_chain(&conn, 0).unwrap();
    assert!(report.ok, "unexpected problems: {:?}", report.problems);
    assert_eq!(report.blocks_checked, 2);
    assert_eq!(report.transactions_checked, 3);
}

#[test]
fn empty_chain_is_reported_rather_than_silently_accepted() {
    let db = TempDb::new();
    let conn = db.conn();
    let report = validate_chain(&conn, 0).unwrap();
    assert!(!report.ok);
    assert!(report.problems.iter().any(|p| p.kind == "EMPTY_CHAIN"));
}

#[test]
fn editing_a_committed_transaction_is_detected() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    add_wallet_tx(&conn, 7, "deposit", 5000, "completed");
    chain::anchor(&mut conn, 0).unwrap();
    assert!(validate_chain(&conn, 0).unwrap().ok);

    conn.execute(
        "UPDATE chain_transactions SET amount_satang = 999999 WHERE tx_ref = 'wallet_tx:1'",
        [],
    )
    .unwrap();

    let report = validate_chain(&conn, 0).unwrap();
    assert!(!report.ok);
    assert!(report
        .problems
        .iter()
        .any(|p| p.kind == "TAMPERED_TRANSACTION"));
    assert!(report.problems.iter().any(|p| p.kind == "MERKLE_MISMATCH"));
}

#[test]
fn editing_a_committed_block_header_is_detected() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    add_wallet_tx(&conn, 7, "deposit", 5000, "completed");
    chain::anchor(&mut conn, 0).unwrap();

    conn.execute("UPDATE chain_blocks SET timestamp = 1 WHERE height = 1", [])
        .unwrap();

    let report = validate_chain(&conn, 0).unwrap();
    assert!(!report.ok);
    assert!(report
        .problems
        .iter()
        .any(|p| p.kind == "INVALID_BLOCK_HASH"));
}

#[test]
fn a_broken_previous_hash_link_is_detected() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    add_wallet_tx(&conn, 7, "deposit", 100, "completed");
    chain::anchor(&mut conn, 0).unwrap();
    add_wallet_tx(&conn, 8, "deposit", 200, "completed");
    chain::anchor(&mut conn, 0).unwrap();

    conn.execute(
        "UPDATE chain_blocks SET previous_hash = ?1 WHERE height = 2",
        params![ZERO_HASH],
    )
    .unwrap();

    let report = validate_chain(&conn, 0).unwrap();
    assert!(!report.ok);
    assert!(report.problems.iter().any(|p| p.kind == "BROKEN_LINK"));
}

#[test]
fn a_replaced_genesis_block_is_detected() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    conn.execute("UPDATE chain_blocks SET timestamp = 42 WHERE height = 0", [])
        .unwrap();

    let report = validate_chain(&conn, 0).unwrap();
    assert!(!report.ok);
    assert!(report.problems.iter().any(|p| p.kind == "BAD_GENESIS"));
}

#[test]
fn a_missing_block_leaves_a_detectable_gap() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    add_wallet_tx(&conn, 7, "deposit", 100, "completed");
    chain::anchor(&mut conn, 0).unwrap();
    add_wallet_tx(&conn, 8, "deposit", 200, "completed");
    chain::anchor(&mut conn, 0).unwrap();

    conn.execute("DELETE FROM chain_transactions WHERE block_height = 1", [])
        .unwrap();
    conn.execute("DELETE FROM chain_blocks WHERE height = 1", [])
        .unwrap();

    let report = validate_chain(&conn, 0).unwrap();
    assert!(!report.ok);
    assert!(report.problems.iter().any(|p| p.kind == "HEIGHT_GAP"));
}

// ---------------- Reconciliation against live source rows ----------------

#[test]
fn editing_a_source_row_after_anchoring_is_detected() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    add_wallet_tx(&conn, 7, "deposit", 5000, "completed");
    chain::anchor(&mut conn, 0).unwrap();

    let clean = chain::reconcile(&conn, 0).unwrap();
    assert_eq!(clean["ok"], true);
    assert_eq!(clean["checked"], 1);

    // A hand-edit straight against the wallet ledger — the chain itself is
    // still perfectly well formed, which is exactly why reconcile exists.
    conn.execute(
        "UPDATE wallet_transactions SET amount_satang = 1 WHERE transaction_id = 1",
        [],
    )
    .unwrap();
    assert!(validate_chain(&conn, 0).unwrap().ok);

    let dirty = chain::reconcile(&conn, 0).unwrap();
    assert_eq!(dirty["ok"], false);
    assert_eq!(dirty["mismatches"], 1);
}

#[test]
fn a_pending_expense_edit_is_not_reported_as_tampering() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    let expense_id = add_expense(&conn, 15000);
    chain::anchor(&mut conn, 0).unwrap();

    conn.execute(
        "UPDATE expenses SET amount_satang=17000, updated_at=1700000600 WHERE expense_id=?1",
        params![expense_id],
    )
    .unwrap();

    let report = chain::reconcile(&conn, 0).unwrap();
    assert_eq!(report["ok"], true, "a backlog is not a mismatch");
    assert_eq!(report["checked"], 0);
}

// ---------------- Lookup ----------------

#[test]
fn transactions_can_be_looked_up_by_ref_and_by_source_row() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    add_wallet_tx(&conn, 7, "deposit", 5000, "completed");
    chain::anchor(&mut conn, 0).unwrap();

    let by_ref = chain::find_transaction(&conn, "wallet_tx:1").unwrap();
    assert_eq!(by_ref["ok"], true);
    assert_eq!(by_ref["matches"][0]["block_height"], 1);

    let by_number = chain::find_transaction(&conn, "1").unwrap();
    assert_eq!(by_number["ok"], true);
    assert_eq!(by_number["matches"][0]["tx_ref"], "wallet_tx:1");

    let missing = chain::find_transaction(&conn, "wallet_tx:404").unwrap();
    assert_eq!(missing["ok"], false);
    assert_eq!(missing["error"], "TRANSACTION_NOT_FOUND");
}

#[test]
fn status_reports_height_and_backlog() {
    let db = TempDb::new();
    let mut conn = db.conn();
    chain::init(&mut conn).unwrap();
    add_wallet_tx(&conn, 7, "deposit", 5000, "completed");

    let before = chain::status(&conn).unwrap();
    assert_eq!(before["height"], 0);
    assert_eq!(before["pending_transactions"], 1);

    chain::anchor(&mut conn, 0).unwrap();
    let after = chain::status(&conn).unwrap();
    assert_eq!(after["height"], 1);
    assert_eq!(after["transaction_count"], 1);
    assert_eq!(after["pending_transactions"], 0);
}
