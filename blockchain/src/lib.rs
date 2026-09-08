//! sombra_chain — Private single-node, append-only verifiable ledger for
//! Sombra_Bot.
//!
//! This is NOT a decentralized blockchain and NOT a cryptocurrency. There
//! is exactly one writer (the bot's own host), no networking, no peers, no
//! mining and no consensus. What it does provide is a hash-linked,
//! tamper-evident append-only log over transactions that the existing
//! SQLite database has ALREADY committed.
//!
//! DESIGN DECISION — ANCHOR (PULL), NEVER DUAL-WRITE.
//! The Python money paths (wallet.py / debt_ledger.py / expense.py) are not
//! touched at all. Instead this component *reads* rows those modules have
//! already committed and appends them to the chain. That is deliberate: a
//! dual-write ("write the DB, then write the chain") has two failure modes
//! the task brief explicitly forbids — DB ok / chain failed, and chain ok /
//! DB failed. With a pull model neither can happen:
//!   * the DB is always the single source of truth for balances;
//!   * the chain can only ever lag, never lead or diverge;
//!   * catching up is idempotent (every anchor is keyed by a deterministic
//!     `tx_ref` with a UNIQUE index), so a crashed or killed anchor run is
//!     recovered simply by running it again.
//! No wallet balance is ever computed, changed or second-guessed here.

pub mod block;
pub mod chain;
pub mod storage;
pub mod transaction;
pub mod validation;

use std::fmt;

/// Domain-separation tag folded into every block header hash. Bumping this
/// invalidates every existing chain, so it is versioned deliberately.
pub const CHAIN_DOMAIN: &str = "sombra-chain-v1";

/// 32 zero bytes in hex — used for the genesis `previous_hash` and for the
/// Merkle root of an empty transaction set.
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Upper bound on how many source rows one `anchor` run folds into a single
/// block. Keeps the write transaction short so the Python side never waits
/// long on SQLite's write lock.
pub const DEFAULT_MAX_TX_PER_BLOCK: usize = 500;

/// How long to wait for SQLite's write lock before giving up. The Python bot
/// holds the lock only for very short `BEGIN IMMEDIATE` blocks, so this is
/// generous on purpose: an anchor run should queue behind a live /transfer,
/// not fail because of one.
pub const BUSY_TIMEOUT_MS: u32 = 15_000;

#[derive(Debug)]
pub enum ChainError {
    Db(rusqlite::Error),
    /// The chain (or a caller argument) is structurally invalid.
    Invalid(String),
    /// Bad CLI invocation.
    Usage(String),
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::Db(e) => write!(f, "database error: {}", e),
            ChainError::Invalid(m) => write!(f, "invalid: {}", m),
            ChainError::Usage(m) => write!(f, "usage: {}", m),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<rusqlite::Error> for ChainError {
    fn from(e: rusqlite::Error) -> Self {
        ChainError::Db(e)
    }
}

pub type Result<T> = std::result::Result<T, ChainError>;

/// Length-prefixed, unambiguous concatenation used for every hash preimage
/// in this crate. Prefixing each field with its byte length means no field
/// value can ever be crafted to look like a field boundary, so two different
/// field tuples can never produce the same preimage.
pub fn canonical(fields: &[&str]) -> String {
    let mut out = String::new();
    for f in fields {
        out.push_str(&f.len().to_string());
        out.push(':');
        out.push_str(f);
        out.push('|');
    }
    out
}

/// SHA-256 over a canonical preimage, hex encoded. Uses the `sha2` crate —
/// no hand-rolled hashing anywhere in this component.
pub fn sha256_hex(preimage: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(preimage.as_bytes());
    hex::encode(hasher.finalize())
}
