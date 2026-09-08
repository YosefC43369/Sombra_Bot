//! Blocks and their hashing.
//!
//! No nonce and no proof-of-work: there is one writer and no fork to
//! resolve, so mining would burn CPU to buy nothing. A block's integrity
//! comes from the hash link plus the Merkle root over its transactions.

use crate::transaction::ChainTransaction;
use crate::{canonical, sha256_hex, CHAIN_DOMAIN, ZERO_HASH};

#[derive(Debug, Clone)]
pub struct Block {
    pub height: i64,
    pub previous_hash: String,
    pub merkle_root: String,
    pub timestamp: i64,
    pub tx_count: i64,
    pub hash: String,
    pub transactions: Vec<ChainTransaction>,
}

/// Merkle root over transaction payload hashes.
///
/// Leaves are the hex payload hashes; a parent is the SHA-256 of its two
/// children's hex strings concatenated. An odd node is paired with itself.
/// The empty set hashes to ZERO_HASH.
///
/// The duplicated-last-node scheme has a known ambiguity in permissionless
/// systems (an attacker can craft two different tx lists with one root).
/// It cannot be exploited here: the transaction set of a block is fixed at
/// write time by a UNIQUE `tx_ref` index, and there is no second party
/// submitting candidate blocks.
pub fn merkle_root(leaves: &[String]) -> String {
    if leaves.is_empty() {
        return ZERO_HASH.to_string();
    }
    let mut level: Vec<String> = leaves.to_vec();
    while level.len() > 1 {
        let mut next: Vec<String> = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let left = &level[i];
            let right = if i + 1 < level.len() { &level[i + 1] } else { left };
            next.push(sha256_hex(&canonical(&[left.as_str(), right.as_str()])));
            i += 2;
        }
        level = next;
    }
    level.remove(0)
}

/// Fixed field order — part of the on-disk format, must not be reordered.
pub fn compute_block_hash(
    height: i64,
    previous_hash: &str,
    merkle_root: &str,
    timestamp: i64,
    tx_count: i64,
) -> String {
    let height_s = height.to_string();
    let timestamp_s = timestamp.to_string();
    let tx_count_s = tx_count.to_string();
    sha256_hex(&canonical(&[
        CHAIN_DOMAIN,
        height_s.as_str(),
        previous_hash,
        merkle_root,
        timestamp_s.as_str(),
        tx_count_s.as_str(),
    ]))
}

impl Block {
    /// Builds block N+1 over `transactions`, sealing its hash immediately.
    pub fn new(
        height: i64,
        previous_hash: String,
        timestamp: i64,
        transactions: Vec<ChainTransaction>,
    ) -> Self {
        let leaves: Vec<String> = transactions.iter().map(|t| t.payload_hash.clone()).collect();
        let root = merkle_root(&leaves);
        let tx_count = transactions.len() as i64;
        let hash = compute_block_hash(height, &previous_hash, &root, timestamp, tx_count);
        Block {
            height,
            previous_hash,
            merkle_root: root,
            timestamp,
            tx_count,
            hash,
            transactions,
        }
    }

    /// The genesis block, built from constants only.
    ///
    /// Deterministic by construction: height 0, an all-zero previous hash,
    /// an all-zero Merkle root, no transactions and — importantly —
    /// timestamp 0 rather than "now". Two fresh installs therefore produce
    /// byte-identical genesis blocks, so a chain can be re-initialized or
    /// compared across environments without ambiguity.
    pub fn genesis() -> Self {
        let hash = compute_block_hash(0, ZERO_HASH, ZERO_HASH, 0, 0);
        Block {
            height: 0,
            previous_hash: ZERO_HASH.to_string(),
            merkle_root: ZERO_HASH.to_string(),
            timestamp: 0,
            tx_count: 0,
            hash,
            transactions: Vec::new(),
        }
    }

    /// Recomputes this block's hash from its own stored header fields.
    pub fn recompute_hash(&self) -> String {
        compute_block_hash(
            self.height,
            &self.previous_hash,
            &self.merkle_root,
            self.timestamp,
            self.tx_count,
        )
    }

    pub fn to_json(&self, include_transactions: bool) -> serde_json::Value {
        let mut value = serde_json::json!({
            "height": self.height,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "timestamp": self.timestamp,
            "tx_count": self.tx_count,
            "hash": self.hash,
        });
        if include_transactions {
            let txs: Vec<serde_json::Value> =
                self.transactions.iter().map(|t| t.to_json()).collect();
            value["transactions"] = serde_json::Value::Array(txs);
        }
        value
    }
}
