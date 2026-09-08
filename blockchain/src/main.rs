//! `sombra-chain` — CLI front end.
//!
//! Integration choice: a plain CLI invoked with `subprocess`, not PyO3
//! bindings and not a long-running service. The bot deploys as a single
//! Python worker with `pip install -r requirements.txt`; bindings would put
//! a Rust toolchain in the critical path of every pip install and every
//! developer machine, and a service would add a process to supervise, a
//! port to secure and a health check to write for a component that runs a
//! handful of times an hour. A binary the Python side can also run by hand
//! while debugging is the smallest thing that works.
//!
//! Contract with the Python caller: exactly one JSON object on stdout, on
//! success and on failure alike, so `chain.py` can always `json.loads()`
//! the result. Failures additionally exit non-zero and write a human line
//! to stderr.

use std::collections::HashMap;

use sombra_chain::{chain, storage, ChainError, Result};

struct Args {
    command: String,
    flags: HashMap<String, String>,
}

fn parse_args() -> Result<Args> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        return Err(ChainError::Usage(usage()));
    }
    let command = raw[0].clone();
    if command.starts_with('-') {
        return Err(ChainError::Usage(usage()));
    }
    let mut flags = HashMap::new();
    let mut i = 1;
    while i < raw.len() {
        let token = &raw[i];
        if let Some(name) = token.strip_prefix("--") {
            // Supports both `--db path` and `--db=path`.
            if let Some((key, value)) = name.split_once('=') {
                flags.insert(key.to_string(), value.to_string());
                i += 1;
            } else {
                let value = raw
                    .get(i + 1)
                    .ok_or_else(|| ChainError::Usage(format!("--{} needs a value", name)))?;
                flags.insert(name.to_string(), value.clone());
                i += 2;
            }
        } else {
            return Err(ChainError::Usage(format!("unexpected argument: {}", token)));
        }
    }
    Ok(Args { command, flags })
}

fn usage() -> String {
    "sombra-chain <init|anchor|status|verify|reconcile|block|tx> --db <path> \
     [--max-tx N] [--from N] [--limit N] [--height N] [--ref REF]"
        .to_string()
}

fn required<'a>(args: &'a Args, key: &str) -> Result<&'a str> {
    args.flags
        .get(key)
        .map(|s| s.as_str())
        .ok_or_else(|| ChainError::Usage(format!("--{} is required", key)))
}

fn number(args: &Args, key: &str, default: i64) -> Result<i64> {
    match args.flags.get(key) {
        None => Ok(default),
        Some(raw) => raw
            .parse::<i64>()
            .map_err(|_| ChainError::Usage(format!("--{} must be an integer", key))),
    }
}

fn run() -> Result<serde_json::Value> {
    let args = parse_args()?;
    let db_path = required(&args, "db")?.to_string();

    match args.command.as_str() {
        "init" => {
            let mut conn = storage::open(&db_path)?;
            let created = chain::init(&mut conn)?;
            let status = chain::status(&conn)?;
            Ok(serde_json::json!({
                "ok": true,
                "genesis_created": created,
                "status": status,
            }))
        }
        "anchor" => {
            let mut conn = storage::open(&db_path)?;
            if !chain::is_initialized(&conn)? {
                chain::init(&mut conn)?;
            }
            let max_tx = number(&args, "max-tx", 0)?;
            chain::anchor(&mut conn, max_tx.max(0) as usize)
        }
        "status" => {
            let conn = storage::open(&db_path)?;
            chain::status(&conn)
        }
        "verify" => {
            let conn = storage::open(&db_path)?;
            let from = number(&args, "from", 0)?;
            chain::verify(&conn, from)
        }
        "reconcile" => {
            let conn = storage::open(&db_path)?;
            let limit = number(&args, "limit", 0)?;
            chain::reconcile(&conn, limit.max(0) as usize)
        }
        "block" => {
            let conn = storage::open(&db_path)?;
            let height = args
                .flags
                .get("height")
                .ok_or_else(|| ChainError::Usage("--height is required".to_string()))?
                .parse::<i64>()
                .map_err(|_| ChainError::Usage("--height must be an integer".to_string()))?;
            chain::get_block(&conn, height)
        }
        "tx" => {
            let conn = storage::open(&db_path)?;
            let needle = required(&args, "ref")?;
            chain::find_transaction(&conn, needle)
        }
        other => Err(ChainError::Usage(format!(
            "unknown command '{}'. {}",
            other,
            usage()
        ))),
    }
}

fn error_code(err: &ChainError) -> &'static str {
    match err {
        ChainError::Db(_) => "DB_ERROR",
        ChainError::Invalid(_) => "INVALID_CHAIN",
        ChainError::Usage(_) => "USAGE_ERROR",
    }
}

fn main() {
    match run() {
        Ok(value) => println!("{}", value),
        Err(err) => {
            let payload = serde_json::json!({
                "ok": false,
                "error": error_code(&err),
                "detail": err.to_string(),
            });
            println!("{}", payload);
            eprintln!("sombra-chain: {}", err);
            std::process::exit(1);
        }
    }
}
