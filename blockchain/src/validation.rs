//! Chain integrity validation.
//!
//! Answers one question exactly: has anything in `chain_blocks` /
//! `chain_transactions` been altered since it was written? It reads only
//! the chain's own tables — comparing against the live wallet/debt/expense
//! rows is `chain::reconcile`'s job, deliberately kept separate so a
//! well-formed chain never reports a problem just because the anchor
//! backlog is not empty.

use rusqlite::Connection;
use std::collections::HashSet;

use crate::block::{compute_block_hash, merkle_root};
use crate::storage;
use crate::{Result, ZERO_HASH};

/// Cap on how many problems are reported. A broken chain usually breaks in
/// every subsequent block, and a Telegram reply cannot carry thousands of
/// lines anyway.
pub const MAX_REPORTED_PROBLEMS: usize = 50;

#[derive(Debug)]
pub struct Problem {
    pub height: i64,
    pub kind: &'static str,
    pub detail: String,
}

#[derive(Debug)]
pub struct ValidationReport {
    pub ok: bool,
    pub blocks_checked: i64,
    pub transactions_checked: i64,
    pub problems: Vec<Problem>,
    pub tip_height: Option<i64>,
    pub tip_hash: Option<String>,
}

impl ValidationReport {
    pub fn to_json(&self) -> serde_json::Value {
        let problems: Vec<serde_json::Value> = self
            .problems
            .iter()
            .take(MAX_REPORTED_PROBLEMS)
            .map(|p| {
                serde_json::json!({
                    "height": p.height,
                    "kind": p.kind,
                    "detail": p.detail,
                })
            })
            .collect();
        serde_json::json!({
            "ok": self.ok,
            "blocks_checked": self.blocks_checked,
            "transactions_checked": self.transactions_checked,
            "problem_count": self.problems.len(),
            "problems": problems,
            "tip_height": self.tip_height,
            "tip_hash": self.tip_hash,
        })
    }
}

/// Walks the chain from `from` upward, checking every invariant:
///
/// * heights are contiguous with no gap and no duplicate;
/// * block 0 is the deterministic genesis block;
/// * each block's `previous_hash` equals the real hash of its predecessor;
/// * each block's stored hash matches a fresh recomputation of its header;
/// * each block's `tx_count` matches the transactions actually stored;
/// * each block's `merkle_root` matches a fresh Merkle root over them;
/// * each transaction's `payload_hash` matches its own fields;
/// * no `tx_ref` appears twice anywhere in the chain.
///
/// Editing a committed block therefore cannot go unnoticed: changing an
/// amount breaks that transaction's payload hash, which breaks the block's
/// Merkle root, which breaks the block hash, which breaks every later
/// block's `previous_hash`.
pub fn validate_chain(conn: &Connection, from: i64) -> Result<ValidationReport> {
    storage::init_schema(conn)?;
    let start = if from < 0 { 0 } else { from };
    let blocks = storage::load_blocks(conn, start)?;

    let mut report = ValidationReport {
        ok: true,
        blocks_checked: 0,
        transactions_checked: 0,
        problems: Vec::new(),
        tip_height: None,
        tip_hash: None,
    };

    if blocks.is_empty() {
        if start == 0 {
            report.ok = false;
            report.problems.push(Problem {
                height: 0,
                kind: "EMPTY_CHAIN",
                detail: "no blocks found; the chain has never been initialized".to_string(),
            });
        }
        return Ok(report);
    }

    // When validating a suffix, the predecessor's hash still has to be read
    // so continuity is checked at the boundary too.
    let mut expected_previous: Option<String> = if start > 0 {
        storage::load_block(conn, start - 1)?.map(|b| b.hash)
    } else {
        None
    };
    let mut expected_height = start;
    let mut seen_refs: HashSet<String> = HashSet::new();

    for block in &blocks {
        report.blocks_checked += 1;

        if block.height != expected_height {
            report.problems.push(Problem {
                height: block.height,
                kind: "HEIGHT_GAP",
                detail: format!("expected height {}, found {}", expected_height, block.height),
            });
            expected_height = block.height;
        }

        if block.height == 0 {
            let genesis = crate::block::Block::genesis();
            if block.hash != genesis.hash
                || block.previous_hash != ZERO_HASH
                || block.merkle_root != ZERO_HASH
                || block.timestamp != 0
                || block.tx_count != 0
            {
                report.problems.push(Problem {
                    height: 0,
                    kind: "BAD_GENESIS",
                    detail: format!(
                        "genesis block does not match the deterministic genesis (expected hash {})",
                        genesis.hash
                    ),
                });
            }
        } else if let Some(previous) = &expected_previous {
            if &block.previous_hash != previous {
                report.problems.push(Problem {
                    height: block.height,
                    kind: "BROKEN_LINK",
                    detail: format!(
                        "previous_hash {} does not match block {}'s hash {}",
                        block.previous_hash,
                        block.height - 1,
                        previous
                    ),
                });
            }
        }

        let transactions = storage::load_block_transactions(conn, block.height)?;
        report.transactions_checked += transactions.len() as i64;

        if transactions.len() as i64 != block.tx_count {
            report.problems.push(Problem {
                height: block.height,
                kind: "TX_COUNT_MISMATCH",
                detail: format!(
                    "header claims {} transactions, {} stored",
                    block.tx_count,
                    transactions.len()
                ),
            });
        }

        for tx in &transactions {
            if !tx.hash_is_consistent() {
                report.problems.push(Problem {
                    height: block.height,
                    kind: "TAMPERED_TRANSACTION",
                    detail: format!(
                        "{}: stored payload_hash does not match its own fields",
                        tx.tx_ref
                    ),
                });
            }
            if !seen_refs.insert(tx.tx_ref.clone()) {
                report.problems.push(Problem {
                    height: block.height,
                    kind: "DUPLICATE_TRANSACTION",
                    detail: format!("{} appears more than once in the chain", tx.tx_ref),
                });
            }
        }

        let leaves: Vec<String> = transactions.iter().map(|t| t.payload_hash.clone()).collect();
        let root = merkle_root(&leaves);
        if root != block.merkle_root {
            report.problems.push(Problem {
                height: block.height,
                kind: "MERKLE_MISMATCH",
                detail: format!(
                    "stored merkle_root {} does not match the {} transaction(s) in this block",
                    block.merkle_root,
                    transactions.len()
                ),
            });
        }

        let recomputed = compute_block_hash(
            block.height,
            &block.previous_hash,
            &block.merkle_root,
            block.timestamp,
            block.tx_count,
        );
        if recomputed != block.hash {
            report.problems.push(Problem {
                height: block.height,
                kind: "INVALID_BLOCK_HASH",
                detail: format!("stored hash {} recomputes to {}", block.hash, recomputed),
            });
        }

        // Chain forward from the hash actually stored, so one broken block
        // does not cascade a second, misleading BROKEN_LINK onto its
        // successor.
        expected_previous = Some(block.hash.clone());
        expected_height = block.height + 1;
    }

    if let Some(last) = blocks.last() {
        report.tip_height = Some(last.height);
        report.tip_hash = Some(last.hash.clone());
    }
    report.ok = report.problems.is_empty();
    Ok(report)
}
