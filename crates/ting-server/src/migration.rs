//! Preserve pre-Accounts records without granting a new account access by a mutable handle.
use rusqlite::{Connection, OptionalExtension};

const TABLES: &[&str] = &[
    "types",
    "grants",
    "preferences",
    "tings",
    "keys",
    "hooks",
    "deliveries",
    "cursors",
    "lifecycle_environments",
    "login_attempts",
    "lifecycle_operations",
    "receiver_sessions",
    "receiver_operations",
    "public_identifier_migration",
];

pub fn ensure_current(db: &Connection) -> anyhow::Result<()> {
    let sql: Option<String> = db
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='tings'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if !sql.is_some_and(|s| s.contains("org TEXT")) {
        return Ok(());
    }
    // Renaming in one transaction preserves exact bodies, idempotency receipts and foreign keys.
    // There is no trusted IAM-to-Accounts UUID map; never transfer private history by handle.
    let tx = db.unchecked_transaction()?;
    for table in TABLES {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
            [table],
            |r| r.get(0),
        )?;
        if exists {
            tx.execute_batch(&format!("ALTER TABLE {table} RENAME TO legacy_{table};"))?;
        }
    }
    tx.commit()?;
    Ok(())
}

pub fn copy_types(db: &Connection) -> anyhow::Result<()> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='legacy_types')",
        [],
        |r| r.get(0),
    )?;
    if exists {
        // Types are public app metadata. Current app authors govern all future edits.
        db.execute("INSERT OR IGNORE INTO types(ctx,app,name,description) SELECT 'accounts',app,name,description FROM legacy_types WHERE ctx='production' ORDER BY name", [])?;
    }
    Ok(())
}
