//! Chain transaction records.
//!
//! A `ChainTransaction` is an immutable notarization of one state a source
//! row reached in the existing database — never a second copy of the money
//! movement itself. `tx_type` values for wallet rows are copied verbatim
//! from wallet.py's `TxType` enum (deposit / withdrawal / transfer_out /
//! transfer_in / payment / refund / debt_payment / adjustment) rather than
//! inventing a parallel vocabulary.

use crate::{canonical, sha256_hex};

/// Which existing table a chain transaction was anchored from.
pub const SOURCE_WALLET: &str = "wallet_tx";
pub const SOURCE_DEBT: &str = "debt_entry";
pub const SOURCE_EXPENSE: &str = "expense";

/// Chain-level tx_type values that do not come from wallet.py's TxType.
pub const TX_DEBT_SIGNED: &str = "debt_signed";
pub const TX_DEBT_PAID: &str = "debt_paid";
pub const TX_EXPENSE_ADDED: &str = "expense_added";
pub const TX_EXPENSE_REVISED: &str = "expense_revised";
pub const TX_EXPENSE_DELETED: &str = "expense_deleted";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTransaction {
    /// Deterministic, globally unique identity of this anchor. UNIQUE in the
    /// database, which is what makes anchoring idempotent and gives
    /// duplicate-transaction detection for free.
    pub tx_ref: String,
    pub tx_type: String,
    pub source: String,
    pub source_row_id: i64,
    pub chat_id: i64,
    pub user_id: Option<i64>,
    pub amount_satang: i64,
    /// Free-form back-reference already carried by the source row
    /// (withdrawal request id, payment id, debt entry id, transfer ref).
    pub reference_id: Option<String>,
    /// When the anchored event happened, per the source row — NOT when it
    /// was anchored. Anchoring time lives on the block.
    pub occurred_at: i64,
    /// Compact JSON. Keys are emitted in sorted order (serde_json's default
    /// BTreeMap-backed Map), so this string is reproducible byte-for-byte.
    pub metadata: Option<String>,
    /// SHA-256 over every field above. Recomputed on `verify`.
    pub payload_hash: String,
}

impl ChainTransaction {
    pub fn new(
        tx_ref: String,
        tx_type: &str,
        source: &str,
        source_row_id: i64,
        chat_id: i64,
        user_id: Option<i64>,
        amount_satang: i64,
        reference_id: Option<String>,
        occurred_at: i64,
        metadata: Option<String>,
    ) -> Self {
        let mut tx = ChainTransaction {
            tx_ref,
            tx_type: tx_type.to_string(),
            source: source.to_string(),
            source_row_id,
            chat_id,
            user_id,
            amount_satang,
            reference_id,
            occurred_at,
            metadata,
            payload_hash: String::new(),
        };
        tx.payload_hash = tx.compute_payload_hash();
        tx
    }

    /// Fixed field order — changing it invalidates every stored hash, so it
    /// is part of the on-disk format and must not be reordered.
    pub fn compute_payload_hash(&self) -> String {
        let source_row_id = self.source_row_id.to_string();
        let chat_id = self.chat_id.to_string();
        let user_id = self.user_id.map(|v| v.to_string()).unwrap_or_default();
        let amount = self.amount_satang.to_string();
        let reference_id = self.reference_id.clone().unwrap_or_default();
        let occurred_at = self.occurred_at.to_string();
        let metadata = self.metadata.clone().unwrap_or_default();
        sha256_hex(&canonical(&[
            self.tx_ref.as_str(),
            self.tx_type.as_str(),
            self.source.as_str(),
            source_row_id.as_str(),
            chat_id.as_str(),
            user_id.as_str(),
            amount.as_str(),
            reference_id.as_str(),
            occurred_at.as_str(),
            metadata.as_str(),
        ]))
    }

    /// True when the stored hash still matches the stored fields.
    pub fn hash_is_consistent(&self) -> bool {
        self.compute_payload_hash() == self.payload_hash
    }

    pub fn to_json(&self) -> serde_json::Value {
        let metadata = self
            .metadata
            .as_deref()
            .and_then(|m| serde_json::from_str::<serde_json::Value>(m).ok())
            .unwrap_or(serde_json::Value::Null);
        serde_json::json!({
            "tx_ref": self.tx_ref,
            "tx_type": self.tx_type,
            "source": self.source,
            "source_row_id": self.source_row_id,
            "chat_id": self.chat_id,
            "user_id": self.user_id,
            "amount_satang": self.amount_satang,
            "reference_id": self.reference_id,
            "occurred_at": self.occurred_at,
            "payload_hash": self.payload_hash,
            "metadata": metadata,
        })
    }
}

// ---------------- Source-row -> ChainTransaction builders ----------------
// One builder per anchor rule. Each is a pure function of the source row, so
// `verify --deep` can recompute the same payload from the live row and prove
// the row has not been edited behind the ledger's back.

/// One already-terminal `wallet_transactions` row (status completed or
/// cancelled — wallet.py never moves a row out of either state again).
#[allow(clippy::too_many_arguments)]
pub fn from_wallet_row(
    transaction_id: i64,
    chat_id: i64,
    user_id: i64,
    tx_type: &str,
    amount_satang: i64,
    balance_before: i64,
    balance_after: i64,
    status: &str,
    reference_id: Option<String>,
    counterparty_user_id: Option<i64>,
    created_at: i64,
) -> ChainTransaction {
    let metadata = serde_json::json!({
        "balance_after_satang": balance_after,
        "balance_before_satang": balance_before,
        "counterparty_user_id": counterparty_user_id,
        "status": status,
    })
    .to_string();
    ChainTransaction::new(
        format!("{}:{}", SOURCE_WALLET, transaction_id),
        tx_type,
        SOURCE_WALLET,
        transaction_id,
        chat_id,
        Some(user_id),
        amount_satang,
        reference_id,
        created_at,
        Some(metadata),
    )
}

/// A debt entry being signed. Covers creation-time fields only, none of
/// which debt_ledger.py ever mutates, so this anchor stays valid for the
/// entry's whole life.
pub fn from_debt_signed(
    entry_id: i64,
    chat_id: i64,
    debtor_name: &str,
    amount_satang: i64,
    item_description: Option<&str>,
    entry_date: &str,
    recorded_by: i64,
    created_at: i64,
) -> ChainTransaction {
    let metadata = serde_json::json!({
        "debtor_name": debtor_name,
        "entry_date": entry_date,
        "item_description": item_description,
    })
    .to_string();
    ChainTransaction::new(
        format!("{}:{}:signed", SOURCE_DEBT, entry_id),
        TX_DEBT_SIGNED,
        SOURCE_DEBT,
        entry_id,
        chat_id,
        Some(recorded_by),
        amount_satang,
        None,
        created_at,
        Some(metadata),
    )
}

/// A debt entry reaching `paid`. A separate append rather than an edit of
/// the `signed` anchor — settling is a new fact, not a correction.
pub fn from_debt_paid(
    entry_id: i64,
    chat_id: i64,
    debtor_name: &str,
    amount_satang: i64,
    paid_by: Option<i64>,
    paid_at: i64,
) -> ChainTransaction {
    let metadata = serde_json::json!({
        "debtor_name": debtor_name,
    })
    .to_string();
    ChainTransaction::new(
        format!("{}:{}:paid", SOURCE_DEBT, entry_id),
        TX_DEBT_PAID,
        SOURCE_DEBT,
        entry_id,
        chat_id,
        paid_by,
        amount_satang,
        Some(entry_id.to_string()),
        paid_at,
        Some(metadata),
    )
}

/// An expense note. `kind` selects added / revised / deleted; `tx_ref`
/// carries `revision_at` for revisions so each edit anchors exactly once.
/// Recording an expense NEVER moves a wallet balance — expense.py keeps
/// `wallet_transaction_id` as a reference only, and so does this anchor.
#[allow(clippy::too_many_arguments)]
pub fn from_expense_row(
    kind: &str,
    expense_id: i64,
    chat_id: i64,
    user_id: i64,
    amount_satang: i64,
    category: &str,
    description: Option<&str>,
    expense_date: &str,
    wallet_transaction_id: Option<i64>,
    debt_entry_id: Option<i64>,
    revision_at: i64,
    occurred_at: i64,
) -> ChainTransaction {
    let tx_ref = match kind {
        TX_EXPENSE_ADDED => format!("{}:{}:added", SOURCE_EXPENSE, expense_id),
        TX_EXPENSE_DELETED => format!("{}:{}:deleted", SOURCE_EXPENSE, expense_id),
        _ => format!("{}:{}:rev:{}", SOURCE_EXPENSE, expense_id, revision_at),
    };
    let metadata = serde_json::json!({
        "category": category,
        "debt_entry_id": debt_entry_id,
        "description": description,
        "expense_date": expense_date,
        "wallet_transaction_id": wallet_transaction_id,
    })
    .to_string();
    ChainTransaction::new(
        tx_ref,
        kind,
        SOURCE_EXPENSE,
        expense_id,
        chat_id,
        Some(user_id),
        amount_satang,
        None,
        occurred_at,
        Some(metadata),
    )
}
