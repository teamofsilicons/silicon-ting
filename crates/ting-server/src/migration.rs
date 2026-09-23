//! Offline, explicit IAM-map cutover. Historical payloads and AEAD contexts never change.
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use anyhow::{Context, Result, bail, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    worlds: Vec<String>,
    identities: Vec<Identity>,
    memberships: Vec<Membership>,
    organizations: Vec<Organization>,
    #[serde(default)]
    authentication_invalidation: Option<AuthenticationInvalidation>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthenticationInvalidation {
    auth_state_sha256: String,
    iam_evidence_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    scope_key: String,
    actor_type: String,
    old_id: String,
    new_id: String,
    org_id: Option<String>,
    #[serde(default)]
    imported: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Organization {
    scope_key: String,
    org_id: String,
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Membership {
    scope_key: String,
    actor_type: String,
    id: String,
    org_id: String,
}
fn world(scope: &str) -> &str {
    if scope.is_empty() {
        "production"
    } else {
        scope
    }
}
fn handle(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
fn canonical(kind: &str, id: &str) -> bool {
    if kind == "application" {
        crate::validation::app_id(id)
    } else {
        crate::validation::actor_kind(id) == Some(kind)
    }
}

impl Manifest {
    fn validate(&self) -> Result<()> {
        let worlds: HashSet<_> = self.worlds.iter().collect();
        ensure!(
            !worlds.is_empty() && worlds.len() == self.worlds.len(),
            "worlds must explicitly list each database context once"
        );
        for w in &self.worlds {
            ensure!(
                w == "production" || uuid::Uuid::parse_str(w).is_ok(),
                "invalid testing world: {w}"
            );
        }
        let mut org_ids = HashSet::new();
        let mut org_handles = HashSet::new();
        for o in &self.organizations {
            ensure!(
                worlds.contains(&world(&o.scope_key).to_owned())
                    && !o.org_id.is_empty()
                    && !o.id.is_empty(),
                "invalid organization authority"
            );
            ensure!(
                org_ids.insert((&o.scope_key, &o.id))
                    && org_handles.insert((&o.scope_key, &o.org_id)),
                "conflicting organization aliases"
            );
        }
        let mut old = HashSet::new();
        let mut new = HashSet::new();
        for i in &self.identities {
            ensure!(
                worlds.contains(&world(&i.scope_key).to_owned()),
                "mapping has an undeclared world"
            );
            ensure!(
                canonical(&i.actor_type, &i.new_id),
                "noncanonical mapped {} ID: {}",
                i.actor_type,
                i.new_id
            );
            ensure!(
                old.insert((&i.scope_key, &i.actor_type, &i.old_id)),
                "duplicate old identity mapping"
            );
            ensure!(
                new.insert((&i.scope_key, &i.actor_type, &i.new_id)),
                "identity collision: {}",
                i.new_id
            );
            let expected = match i.actor_type.as_str() {
                "carbon" => {
                    ensure!(
                        i.org_id.is_none(),
                        "Carbon ownership comes from memberships, not an owning org"
                    );
                    format!("c:{}", i.old_id)
                }
                "silicon" => {
                    let org = i
                        .org_id
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .context("Silicon owner is required")?;
                    let h = i.old_id.strip_suffix(&format!(":{org}"));
                    ensure!(
                        i.old_id == i.new_id || h.is_some_and(|s| handle(s, 3, 50)),
                        "Silicon old ID disagrees with authoritative owner"
                    );
                    format!("si:{}", h.unwrap_or_default())
                }
                "application" => {
                    let org = i
                        .org_id
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .context("application owner is required")?;
                    let h = i.old_id.strip_prefix(&format!("{org}>"));
                    ensure!(
                        i.old_id == i.new_id || h.is_some_and(|s| canonical("application", s)),
                        "application old ID disagrees with authoritative owner"
                    );
                    h.unwrap_or_default().to_owned()
                }
                _ => unreachable!(),
            };
            ensure!(
                i.old_id == i.new_id || expected == i.new_id,
                "mapping changes an unverified handle: {}",
                i.old_id
            );
            if i.actor_type == "application" && !i.scope_key.is_empty() {
                let production = self.identities.iter().find(|p| {
                    p.scope_key.is_empty() && p.actor_type == "application" && p.new_id == i.new_id
                });
                match production {
                    Some(p) => ensure!(
                        i.imported && p.org_id == i.org_id && p.old_id == i.old_id,
                        "testing app impersonates production app: {}",
                        i.new_id
                    ),
                    None => ensure!(
                        !i.imported,
                        "imported app has no production mapping: {}",
                        i.new_id
                    ),
                }
            } else {
                ensure!(!i.imported, "only testing applications can be imported");
            }
        }
        for m in &self.memberships {
            ensure!(
                matches!(m.actor_type.as_str(), "carbon" | "silicon") && !m.org_id.is_empty(),
                "invalid membership authority"
            );
            self.identity(world(&m.scope_key), Some(&m.actor_type), &m.id)?;
            self.organization(world(&m.scope_key), &m.org_id)?;
        }
        Ok(())
    }
    fn identity(&self, ctx: &str, kind: Option<&str>, id: &str) -> Result<&Identity> {
        ensure!(
            self.worlds.iter().any(|w| w == ctx),
            "database world absent from export: {ctx}"
        );
        let mut found = self.identities.iter().filter(|i| {
            world(&i.scope_key) == ctx
                && kind.map_or(i.actor_type != "application", |k| i.actor_type == k)
                && (i.old_id == id || i.new_id == id)
        });
        let i = found
            .next()
            .with_context(|| format!("unmapped identity in world {ctx}: {id}"))?;
        ensure!(
            found.next().is_none(),
            "ambiguous actor kind or old/canonical binding: {id}"
        );
        Ok(i)
    }
    fn organization<'a>(&'a self, ctx: &str, org: &str) -> Result<&'a str> {
        let mut found = self
            .organizations
            .iter()
            .filter(|o| world(&o.scope_key) == ctx && (o.id == org || o.org_id == org));
        let o = found.next().context("unmapped organization selector")?;
        ensure!(found.next().is_none(), "ambiguous organization selector");
        Ok(&o.org_id)
    }
    fn actor(&self, ctx: &str, org: &str, id: &str) -> Result<String> {
        let org = self.organization(ctx, org)?;
        let i = self.identity(ctx, None, id)?;
        ensure!(
            self.memberships.iter().any(|m| world(&m.scope_key) == ctx
                && m.actor_type == i.actor_type
                && m.org_id == org
                && (m.id == i.old_id || m.id == i.new_id)),
            "missing authoritative membership for {id} in {ctx}/{org}"
        );
        Ok(i.new_id.clone())
    }
}
fn table(db: &Connection, schema: &str, name: &str) -> Result<bool> {
    Ok(db.query_row(
        &format!(
            "SELECT EXISTS(SELECT 1 FROM {schema}.sqlite_master WHERE type='table' AND name=?)"
        ),
        [name],
        |r| r.get(0),
    )?)
}

/// Run before startup resets receivers or prunes receipts.
pub fn ensure_current(db: &Connection) -> Result<()> {
    for (t, col, kind) in [
        ("types", "app", "application"),
        ("grants", "app", "application"),
        ("grants", "recipient", "actor"),
        ("preferences", "app", "application"),
        ("preferences", "recipient", "actor"),
        ("tings", "app", "application"),
        ("tings", "recipient", "actor"),
        ("hooks", "recipient", "actor"),
    ] {
        if !table(db, "main", t)? {
            continue;
        }
        let mut q = db.prepare(&format!("SELECT DISTINCT {col} FROM {t}"))?;
        for id in q.query_map([], |r| r.get::<_, String>(0))? {
            let id = id?;
            ensure!(
                if kind == "actor" {
                    canonical("carbon", &id) || canonical("silicon", &id)
                } else {
                    canonical(kind, &id)
                },
                "legacy identity in {t}.{col}; stop all writers and run --migrate-public-identifiers with the IAM world-scoped export before starting Ting"
            );
        }
    }
    if table(db, "main", "keys")? {
        let mut q = db.prepare("SELECT DISTINCT kind,owner FROM keys")?;
        for row in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (kind, owner) = row?;
            ensure!(
                match kind.as_str() {
                    "send" | "sent-read" => crate::validation::app_id(&owner),
                    "hook" => crate::validation::actor_kind(&owner).is_some(),
                    _ => false,
                },
                "legacy or unknown replay owner; run --migrate-public-identifiers before starting Ting"
            );
        }
    }
    Ok(())
}

fn decrypt(cipher: &Aes256Gcm, id: &str, bytes: &[u8]) -> Result<Value> {
    ensure!(
        bytes.len() >= 28,
        "invalid credential ciphertext; restore matching snapshot and encryption key"
    );
    let plain = cipher
        .decrypt(
            Nonce::from_slice(&bytes[..12]),
            Payload {
                msg: &bytes[12..],
                aad: id.as_bytes(),
            },
        )
        .map_err(|_| {
            anyhow::anyhow!(
                "credential authentication failed; restore matching snapshot and encryption key"
            )
        })?;
    serde_json::from_slice(&plain).context("invalid encrypted credential JSON")
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("credential is missing {key}"))
}
fn preserved(db: &Connection) -> Result<String> {
    let mut digest = Sha256::new();
    let mut queries = vec![
        "SELECT id,created,body,silent,read FROM tings ORDER BY id",
        "SELECT id,active FROM grants ORDER BY id",
        "SELECT hook,message,offered,offer_receiver,delivery,read,last_offer FROM deliveries ORDER BY hook,message",
        "SELECT ctx,org,kind,key,fingerprint,response,expires FROM keys ORDER BY ctx,org,kind,key,fingerprint,response",
        "SELECT id,payload FROM auth.sessions ORDER BY id",
        "SELECT id,slt_hash,created,payload,response FROM auth.logins ORDER BY id",
        "SELECT id,revision,generation,key_version,key_hash,state FROM lifecycle_environments ORDER BY id",
    ];
    for (table_name, query) in [
        (
            "lifecycle_operations",
            "SELECT id,environment,fingerprint,state,receipt FROM lifecycle_operations ORDER BY id",
        ),
        (
            "receiver_sessions",
            "SELECT id,token_hash,payload FROM receiver_sessions ORDER BY id",
        ),
        (
            "receiver_operations",
            "SELECT id,ctx,fingerprint,response FROM receiver_operations ORDER BY id",
        ),
    ] {
        if table(db, "main", table_name)? {
            queries.push(query);
        }
    }
    for query in queries {
        let mut q = db.prepare(query)?;
        let count = q.column_count();
        let rows = q.query_map([], |r| {
            (0..count)
                .map(|i| r.get::<_, rusqlite::types::Value>(i))
                .collect::<rusqlite::Result<Vec<_>>>()
        })?;
        digest.update(query.as_bytes());
        for row in rows {
            digest.update(format!("{:?}", row?).as_bytes());
        }
    }
    Ok(hex::encode(digest.finalize()))
}

// Bind operator reconciliation to the exact credential/replay state, including pending flags.
fn authentication_state(db: &Connection) -> Result<String> {
    let mut digest = Sha256::new();
    for query in [
        "SELECT json_group_array(json_array(id,hex(payload),revoked,revoke_pending)) FROM (SELECT * FROM auth.sessions ORDER BY id)",
        "SELECT json_group_array(json_array(id,slt_hash,created,CASE WHEN payload IS NULL THEN NULL ELSE hex(payload) END,CASE WHEN response IS NULL THEN NULL ELSE hex(response) END)) FROM (SELECT * FROM auth.logins ORDER BY id)",
        "SELECT json_group_array(json_array(id,state,key_hash)) FROM (SELECT * FROM auth.testing_contexts ORDER BY id)",
    ] {
        let rows: String = db.query_row(query, [], |r| r.get(0))?;
        digest.update(rows.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

pub fn run(
    database_path: &str,
    encryption_key: &str,
    mapping_path: &str,
    apply: bool,
) -> Result<Value> {
    let raw = std::fs::read(mapping_path)?;
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    manifest.validate()?;
    let checksum = hex::encode(Sha256::digest(&raw));
    let key = hex::decode(encryption_key).context("TING_ENCRYPTION_KEY must be hexadecimal")?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("TING_ENCRYPTION_KEY must encode 32 bytes"))?;
    let auth_path = format!("{database_path}.auth");
    ensure!(
        std::path::Path::new(&auth_path).is_file(),
        "matching .auth database is required"
    );
    let mut db = Connection::open_with_flags(database_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    db.execute("ATTACH DATABASE ? AS auth", [&auth_path])?;
    // SQLite's super-journal makes the two databases crash-atomic; WAL cannot do this.
    if apply {
        db.execute_batch("PRAGMA main.journal_mode=DELETE; PRAGMA auth.journal_mode=DELETE;")?;
    }
    db.execute_batch(
        "PRAGMA main.synchronous=FULL; PRAGMA auth.synchronous=FULL; PRAGMA foreign_keys=ON;",
    )?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if table(&tx, "main", "public_identifier_migration")? {
        let previous: String = tx.query_row(
            "SELECT checksum FROM public_identifier_migration WHERE version=1",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            previous == checksum,
            "database was already migrated with a different export; do not remap it"
        );
        ensure_current(&tx)?;
        return Ok(json!({"status":"already_applied","mapping_sha256":checksum}));
    }
    let now = crate::store::now();
    let reconciled = if let Some(evidence) = &manifest.authentication_invalidation {
        ensure!(
            evidence.iam_evidence_sha256.len() == 64
                && evidence
                    .iam_evidence_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit()),
            "reconciliation requires the SHA-256 of the authoritative IAM invalidation evidence"
        );
        ensure!(
            evidence.auth_state_sha256 == authentication_state(&tx)?,
            "authentication state changed since IAM reconciliation; repeat the audit with writers stopped"
        );
        true
    } else {
        false
    };
    if table(&tx, "main", "lifecycle_operations")? {
        let pending: i64 = tx.query_row(
            "SELECT COUNT(*) FROM lifecycle_operations WHERE state!='completed'",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            pending == 0,
            "unfinished Honeycomb lifecycle operations must be reconciled first"
        );
    }
    let pending: i64 = tx.query_row(
        "SELECT COUNT(*) FROM auth.logins WHERE response IS NULL",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        pending == 0 || reconciled,
        "unfinished IAM login exchanges must be reconciled with their original keys first"
    );
    let pending: i64 = tx.query_row(
        "SELECT COUNT(*) FROM auth.sessions WHERE revoke_pending!=0",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        pending == 0 || reconciled,
        "pending IAM revocations must finish before cutover"
    );
    let mut sessions = 0;
    {
        let mut q = tx.prepare("SELECT id,payload,revoked FROM auth.sessions")?;
        for row in q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, bool>(2)?,
            ))
        })? {
            let (id, bytes, revoked) = row?;
            let s = decrypt(&cipher, &id, &bytes)?;
            ensure!(
                reconciled || (s["refresh_key"].is_null() && s["refresh_started"].is_null()),
                "pending IAM refresh must be reconciled with its original key first"
            );
            let ctx = field(&s, "context")?;
            let kind = field(&s, "kind")?;
            ensure!(
                matches!(kind, "carbon" | "silicon"),
                "invalid encrypted actor kind"
            );
            ensure!(
                manifest.worlds.iter().any(|w| w == ctx),
                "encrypted credential references an unexported world"
            );
            // Already-revoked ciphertext is historical evidence, never a new authority binding.
            // IAM can have purged its testing principal; keep the exact old payload and AAD.
            if !revoked {
                manifest.identity(ctx, Some(kind), field(&s, "id")?)?;
            }
            ensure!(
                if ctx == "production" {
                    s["test"].is_null()
                } else {
                    s["test"]["id"].as_str() == Some(ctx)
                },
                "encrypted credential world mismatch"
            );
            sessions += 1;
        }
        let mut q = tx.prepare("SELECT id,payload,response FROM auth.logins")?;
        for row in q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<Vec<u8>>>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })? {
            let (id, payload, response) = row?;
            for bytes in [payload, response].into_iter().flatten() {
                decrypt(&cipher, &id, &bytes)?;
            }
        }
    }
    for (schema, name) in [
        ("main", "lifecycle_environments"),
        ("auth", "testing_contexts"),
    ] {
        let mut q = tx.prepare(&format!("SELECT id FROM {schema}.{name}"))?;
        for ctx in q.query_map([], |r| r.get::<_, String>(0))? {
            ensure!(
                manifest.worlds.contains(&ctx?),
                "lifecycle/testing fence references an undeclared world"
            );
        }
    }
    let mut receivers = 0;
    if table(&tx, "main", "receiver_sessions")? {
        let mut q = tx.prepare("SELECT id,payload,revoked FROM receiver_sessions")?;
        for row in q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, bool>(2)?,
            ))
        })? {
            let (id, payload, revoked) = row?;
            let r: Value = serde_json::from_str(&payload)?;
            let ctx = field(&r, "context")?;
            ensure!(
                ctx != "production" && manifest.worlds.iter().any(|w| w == ctx),
                "receiver lease has an invalid world"
            );
            ensure!(
                field(&r, "id")? == id && matches!(field(&r, "kind")?, "carbon" | "silicon"),
                "receiver lease identity is inconsistent"
            );
            if !revoked
                && r["expires"]
                    .as_i64()
                    .context("receiver expiry is missing")?
                    > now
            {
                manifest.identity(ctx, Some(field(&r, "kind")?), field(&r, "actor")?)?;
                manifest.actor(ctx, field(&r, "org")?, field(&r, "actor")?)?;
                manifest.identity(ctx, Some("application"), field(&r, "app")?)?;
            }
            receivers += 1;
        }
    }
    if table(&tx, "main", "receiver_operations")? {
        let mut q = tx.prepare("SELECT id,ctx,response FROM receiver_operations")?;
        for row in q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })? {
            let (id, ctx, response) = row?;
            ensure!(
                ctx != "production" && manifest.worlds.contains(&ctx),
                "receiver receipt has an invalid world"
            );
            decrypt(&cipher, &format!("receiver:{id}"), &response)?;
        }
    }
    let before = preserved(&tx)?;
    let mut counts = BTreeMap::new();
    for t in ["types", "grants", "preferences", "tings", "hooks", "keys"] {
        let columns = match t {
            "types" => vec!["app", "name"],
            "grants" => vec!["app", "recipient"],
            "preferences" => vec!["app", "recipient", "scope"],
            "tings" => vec!["app", "recipient", "type"],
            "hooks" => vec!["recipient"],
            "keys" => vec!["owner", "kind"],
            _ => unreachable!(),
        };
        let mut q = tx.prepare(&format!(
            "SELECT rowid,ctx,org,{} FROM {t}",
            columns.join(",")
        ))?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    (3..3 + columns.len())
                        .map(|n| r.get::<_, String>(n))
                        .collect::<rusqlite::Result<Vec<_>>>()?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        counts.insert(t, rows.len());
        for (rowid, ctx, org, values) in rows {
            ensure!(
                manifest.worlds.iter().any(|w| w == &ctx),
                "unexported database world: {ctx}"
            );
            manifest.organization(&ctx, &org)?;
            let mut mapped = values.clone();
            for (n, col) in columns.iter().enumerate() {
                match *col {
                    "app" => {
                        let i = manifest.identity(&ctx, Some("application"), &values[n])?;
                        if t == "types" {
                            ensure!(
                                i.org_id.as_deref() == Some(manifest.organization(&ctx, &org)?),
                                "type catalog application ownership mismatch"
                            );
                        }
                        mapped[n] = i.new_id.clone();
                    }
                    "recipient" => mapped[n] = manifest.actor(&ctx, &org, &values[n])?,
                    "owner" => {
                        mapped[n] = match values[1].as_str() {
                            "send" | "sent-read" => manifest
                                .identity(&ctx, Some("application"), &values[n])?
                                .new_id
                                .clone(),
                            "hook" => manifest.actor(&ctx, &org, &values[n])?,
                            _ => bail!("unknown replay record kind"),
                        }
                    }
                    "name" | "type" => {
                        let suffix = values[n]
                            .strip_prefix(&format!("{}.", values[0]))
                            .context("type does not match owning application")?;
                        ensure!(
                            suffix.split('.').count() == 2,
                            "malformed typed notification name"
                        );
                        mapped[n] = format!("{}.{}", mapped[0], suffix);
                    }
                    "scope" if values[n].starts_with("type:") => {
                        let suffix = values[n]
                            .strip_prefix(&format!("type:{}.", values[0]))
                            .context("preference type disagrees with app")?;
                        mapped[n] = format!("type:{}.{}", mapped[0], suffix);
                    }
                    _ => {}
                }
            }
            let assignments = columns
                .iter()
                .map(|c| format!("{c}=?"))
                .collect::<Vec<_>>()
                .join(",");
            let mut parameters: Vec<rusqlite::types::Value> =
                mapped.into_iter().map(Into::into).collect();
            parameters.push(rowid.into());
            tx.execute(
                &format!("UPDATE {t} SET {assignments} WHERE rowid=?"),
                rusqlite::params_from_iter(parameters),
            )?;
        }
    }
    ensure_current(&tx)?;
    ensure!(
        before == preserved(&tx)?,
        "immutable message, credential or receipt bytes changed; migration rolled back"
    );
    let foreign_error: Option<String> = tx
        .query_row("PRAGMA foreign_key_check", [], |r| r.get(0))
        .optional()?;
    ensure!(foreign_error.is_none(), "foreign key check failed");
    tx.execute("UPDATE auth.sessions SET revoked=1,revoke_pending=0", [])?;
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS auth.invalidated_logins(id TEXT PRIMARY KEY);
        INSERT OR IGNORE INTO auth.invalidated_logins SELECT id FROM auth.logins;",
    )?;
    if table(&tx, "main", "receiver_sessions")? {
        tx.execute("UPDATE receiver_sessions SET revoked=1", [])?;
    }
    tx.execute("DELETE FROM cursors", [])?;
    tx.execute("DELETE FROM login_attempts", [])?;
    tx.execute_batch("CREATE TABLE public_identifier_migration(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,manifest TEXT NOT NULL,completed INTEGER NOT NULL);")?;
    tx.execute(
        "INSERT INTO public_identifier_migration VALUES(1,?,?,?)",
        params![checksum, String::from_utf8(raw)?, now],
    )?;
    let evidence = json!({"status":if apply {"applied"} else {"preview"},"mapping_sha256":checksum,"worlds":manifest.worlds,"rows":counts,"authenticated_sessions":sessions,"immutable_sha256":before,"collisions":0,"unmapped":0,"sessions_invalidated":sessions,"receiver_leases_invalidated":receivers});
    if apply {
        tx.commit()?;
    } else {
        tx.rollback()?;
    }
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{Principal, Proof},
        store::Store,
    };
    const KEY: &str = "abababababababababababababababababababababababababababababababab";
    struct Fixture {
        _dir: tempfile::TempDir,
        db: String,
        map: String,
        worlds: Vec<String>,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir
                .path()
                .join("ting.sqlite")
                .to_string_lossy()
                .into_owned();
            drop(Store::open(&path).unwrap());
            let db = Connection::open(&path).unwrap();
            crate::receiver::initialize(&db).unwrap();
            db.execute("ATTACH DATABASE ? AS auth", [format!("{path}.auth")])
                .unwrap();
            db.execute_batch("CREATE TABLE auth.sessions(id TEXT PRIMARY KEY,payload BLOB NOT NULL,revoked INTEGER DEFAULT 0,revoke_pending INTEGER DEFAULT 0); CREATE TABLE auth.logins(id TEXT PRIMARY KEY,slt_hash TEXT,created INTEGER,payload BLOB,response BLOB); CREATE TABLE auth.testing_contexts(id TEXT PRIMARY KEY,state TEXT,key_hash TEXT); CREATE TABLE lifecycle_operations(id TEXT PRIMARY KEY,environment TEXT,fingerprint TEXT,state TEXT,receipt TEXT);").unwrap();
            let worlds = vec![
                "production".into(),
                uuid::Uuid::new_v4().to_string(),
                uuid::Uuid::new_v4().to_string(),
            ];
            let mut identities = vec![];
            let mut memberships = vec![];
            let mut organizations = vec![];
            let cipher = Aes256Gcm::new_from_slice(&hex::decode(KEY).unwrap()).unwrap();
            for (n, ctx) in worlds.iter().enumerate() {
                let scope = if ctx == "production" { "" } else { ctx };
                organizations.push(json!({"scope_key":scope,"org_id":"tos","id":"org-uuid"}));
                for (kind, old, new, owner) in [
                    ("carbon", "alice", "c:alice", None),
                    ("silicon", "chef:tos", "si:chef", Some("tos")),
                    ("application", "tos>example", "example", Some("tos")),
                ] {
                    identities.push(json!({"scope_key":scope,"actor_type":kind,"old_id":old,"new_id":new,"org_id":owner,"imported":n>0 && kind=="application"}));
                    if kind != "application" {
                        memberships.push(
                            json!({"scope_key":scope,"actor_type":kind,"id":old,"org_id":"tos"}),
                        );
                    }
                }
                let message = format!("msg_{n}");
                let hook = format!("hook_{n}");
                let body = json!({"id":message,"type":"tos>example.msg.received","for":"alice","data":{"keep":"alice tos>example chef:tos"},"metadata":{"url":"https://elsewhere/alice"},"created_at":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros,true),"key":"accepted-key","read":false,"silent":false}).to_string();
                db.execute("INSERT INTO types VALUES(?,'org-uuid','tos>example','tos>example.msg.received','keep tos>example')",[ctx]).unwrap();
                db.execute(
                    "INSERT INTO grants VALUES(?,?,'org-uuid','tos>example','alice',1)",
                    params![format!("sub_{n}"), ctx],
                )
                .unwrap();
                db.execute(
                    "INSERT INTO grants VALUES(?,?,'org-uuid','tos>example','chef:tos',1)",
                    params![format!("silicon-sub_{n}"), ctx],
                )
                .unwrap();
                db.execute("INSERT INTO preferences VALUES(?,'org-uuid','alice','tos>example','type:tos>example.msg.received',1)",[ctx]).unwrap();
                db.execute(
                    "INSERT INTO hooks VALUES(?,?,'org-uuid','alice','disconnected',NULL,NULL)",
                    params![hook, ctx],
                )
                .unwrap();
                db.execute("INSERT INTO tings VALUES(?,?,'org-uuid','tos>example','alice','tos>example.msg.received',?,?,0,0)",params![message,ctx,serde_json::from_str::<Value>(&body).unwrap()["created_at"].as_str(),body]).unwrap();
                db.execute(
                    "INSERT INTO deliveries(hook,message,offered,delivery,read) VALUES(?,?,1,1,0)",
                    params![hook, message],
                )
                .unwrap();
                db.execute("INSERT INTO keys VALUES(?,'org-uuid','tos>example','send','accepted-key','original-request-sha256','{\"id\":\"accepted-receipt\"}',?)",params![ctx,crate::store::now()+86400]).unwrap();
                db.execute("INSERT INTO keys VALUES(?,'org-uuid','alice','hook','hook-key','{}','{\"id\":\"original-hook\",\"for\":\"alice\"}',?)",params![ctx,crate::store::now()+86400]).unwrap();
                let id = format!("session_{n}");
                let session = json!({"context":ctx,"id":"alice","kind":"carbon","access":"retained-access","refresh":"retained-refresh","test":if n == 0 {Value::Null} else {json!({"id":ctx,"secret":"original","key":"original"})},"refresh_key":null,"refresh_started":null});
                let nonce = [n as u8; 12];
                let ciphertext = cipher
                    .encrypt(
                        Nonce::from_slice(&nonce),
                        Payload {
                            msg: session.to_string().as_bytes(),
                            aad: id.as_bytes(),
                        },
                    )
                    .unwrap();
                db.execute(
                    "INSERT INTO auth.sessions(id,payload) VALUES(?,?)",
                    params![id, [nonce.to_vec(), ciphertext].concat()],
                )
                .unwrap();
                if n > 0 {
                    let receiver = format!("receiver_{n}");
                    let operation = format!("receiver_operation_{n}");
                    let payload = json!({"id":receiver,"context":ctx,"generation":3,"key_hash":"original-key-hash","org":"org-uuid","app":"tos>example","actor":"alice","kind":"carbon","expires":crate::store::now()+30});
                    db.execute(
                        "INSERT INTO receiver_sessions VALUES(?,?,?,0)",
                        params![
                            receiver,
                            format!("receiver_token_hash_{n}"),
                            payload.to_string()
                        ],
                    )
                    .unwrap();
                    let aad = format!("receiver:{operation}");
                    let response = cipher
                        .encrypt(
                            Nonce::from_slice(&nonce),
                            Payload {
                                msg: b"{\"receiver_token\":\"retained-test-token\"}",
                                aad: aad.as_bytes(),
                            },
                        )
                        .unwrap();
                    db.execute(
                        "INSERT INTO receiver_operations VALUES(?,?,?,?)",
                        params![
                            operation,
                            ctx,
                            "original-exact-request-fingerprint",
                            [nonce.to_vec(), response].concat()
                        ],
                    )
                    .unwrap();
                    db.execute("INSERT INTO lifecycle_environments VALUES(?,2,3,4,'original-key-hash','active')",[ctx]).unwrap();
                }
            }
            let map = dir
                .path()
                .join("iam-map.json")
                .to_string_lossy()
                .into_owned();
            std::fs::write(&map,json!({"worlds":worlds,"identities":identities,"memberships":memberships,"organizations":organizations}).to_string()).unwrap();
            Self {
                _dir: dir,
                db: path,
                map,
                worlds,
            }
        }
        fn connection(&self) -> Connection {
            Connection::open(&self.db).unwrap()
        }
        fn change_map(&self, change: impl FnOnce(&mut Value)) {
            let mut value: Value =
                serde_json::from_slice(&std::fs::read(&self.map).unwrap()).unwrap();
            change(&mut value);
            std::fs::write(&self.map, value.to_string()).unwrap();
        }
        fn legacy(&self) {
            assert_eq!(
                self.connection()
                    .query_row("SELECT app FROM types WHERE ctx='production'", [], |r| {
                        r.get::<_, String>(0)
                    })
                    .unwrap(),
                "tos>example"
            );
            assert!(Store::open(&self.db).is_err());
        }
    }
    #[test]
    fn populated_worlds_preserve_ciphertext_receipts_and_delivery_identity() {
        let f = Fixture::new();
        assert_eq!(run(&f.db, KEY, &f.map, false).unwrap()["status"], "preview");
        f.legacy();
        let result = run(&f.db, KEY, &f.map, true).unwrap();
        assert_eq!(result["authenticated_sessions"], 3);
        assert_eq!(result["receiver_leases_invalidated"], 2);
        assert_eq!(
            f.connection()
                .query_row(
                    "SELECT COUNT(*) FROM receiver_sessions WHERE revoked=1",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            2
        );
        assert_eq!(
            run(&f.db, KEY, &f.map, true).unwrap()["status"],
            "already_applied"
        );
        let db = f.connection();
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM keys WHERE fingerprint='original-request-sha256'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            3
        );
        assert_eq!(db.query_row("SELECT COUNT(*) FROM tings WHERE body LIKE '%tos>example%' AND app='example' AND recipient='c:alice'",[],|r|r.get::<_,i64>(0)).unwrap(),3);
        let store = Store::open(&f.db).unwrap();
        for ctx in &f.worlds {
            let p = Principal {
                context: ctx.clone(),
                id: "c:alice".into(),
                kind: "carbon".into(),
                session: "fresh-login".into(),
            };
            let items = store
                .tings(ctx, "org-uuid", Some("c:alice"), None, &json!({}))
                .unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0]["type"], "example.msg.received");
            assert_eq!(items[0]["for"], "c:alice");
            assert_eq!(items[0]["data"]["keep"], "alice tos>example chef:tos");
            assert!(
                store
                    .tings(ctx, "other-org", Some("c:alice"), None, &json!({}))
                    .unwrap()
                    .is_empty()
            );
            assert!(
                store
                    .tings(ctx, "org-uuid", Some("si:chef"), None, &json!({}))
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                store
                    .hook_retry(&p, "org-uuid", "hook-key", &json!({}))
                    .unwrap()
                    .unwrap()["id"],
                "original-hook"
            );
            let proof = Proof {
                context: ctx.clone(),
                org_id: "org-uuid".into(),
                app_id: "example".into(),
                actor_id: "c:alice".into(),
                actor_kind: "carbon".into(),
                expires_at: crate::store::now() + 3600,
                test: None,
            };
            let request = json!({"org_id":"org-uuid","type":"example.msg.received","data":{},"for":"c:alice","key":"accepted-key"});
            assert_eq!(
                store.send(&proof, &request).unwrap_err().body["error"]["code"],
                "idempotency_conflict"
            );
            let mut fresh = request.clone();
            fresh["key"] = "new-operation".into();
            let first = store.send(&proof, &fresh).unwrap();
            assert_eq!(store.send(&proof, &fresh).unwrap().1, first.1);
            let index = f.worlds.iter().position(|w| w == ctx).unwrap();
            store
                .bind(
                    &p,
                    "org-uuid",
                    "fresh-receiver",
                    &[format!("hook_{index}")],
                    true,
                    false,
                )
                .unwrap();
            let offer = store
                .offer("fresh-receiver", &format!("hook_{index}"))
                .unwrap()
                .unwrap();
            assert!(
                offer["tings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|t| t["for"] == "c:alice" && t["type"] == "example.msg.received")
            );
        }
    }
    #[test]
    fn collisions_world_ownership_missing_mapping_and_crypto_failure_roll_back() {
        for case in 0..7 {
            let f = Fixture::new();
            match case {
                0 => f.change_map(|m| {
                    let mut i = m["identities"][1].clone();
                    i["old_id"] = "chef:other".into();
                    i["org_id"] = "other".into();
                    m["identities"].as_array_mut().unwrap().push(i);
                }),
                1 => f.change_map(|m| {
                    m["identities"].as_array_mut().unwrap().remove(0);
                }),
                2 => f.change_map(|m| {
                    m["memberships"].as_array_mut().unwrap().remove(0);
                }),
                3 => f.change_map(|m| {
                    m["identities"][5]["imported"] = false.into();
                }),
                4 => {
                    f.connection()
                        .execute(
                            "UPDATE types SET org='wrong-org' WHERE ctx='production'",
                            [],
                        )
                        .unwrap();
                }
                5 => {
                    let auth = Connection::open(format!("{}.auth", f.db)).unwrap();
                    auth.execute(
                        "UPDATE sessions SET payload=zeroblob(64) WHERE id='session_0'",
                        [],
                    )
                    .unwrap();
                }
                6 => {
                    f.connection()
                        .execute(
                            "UPDATE hooks SET ctx=? WHERE ctx='production'",
                            [uuid::Uuid::new_v4().to_string()],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(run(&f.db, KEY, &f.map, true).is_err(), "case {case}");
            f.legacy();
        }
    }
    #[test]
    fn legacy_replay_owner_blocks_startup_without_other_legacy_rows() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(
            "CREATE TABLE keys(kind TEXT,owner TEXT); INSERT INTO keys VALUES('send','tos>hook');",
        )
        .unwrap();
        assert!(ensure_current(&db).is_err());
        db.execute("UPDATE keys SET owner='hook'", []).unwrap();
        ensure_current(&db).unwrap();
    }
    #[test]
    fn uncertain_upstream_operations_block_cutover() {
        for query in [
            "INSERT INTO logins VALUES('pending','hash',1,NULL,NULL)",
            "UPDATE sessions SET revoke_pending=1",
        ] {
            let f = Fixture::new();
            Connection::open(format!("{}.auth", f.db))
                .unwrap()
                .execute(query, [])
                .unwrap();
            assert!(run(&f.db, KEY, &f.map, true).is_err());
            f.legacy();
        }
    }
    #[test]
    fn reconciled_authentication_is_bound_to_exact_state_and_never_replayed() {
        let f = Fixture::new();
        let db = f.connection();
        db.execute("ATTACH DATABASE ? AS auth", [format!("{}.auth", f.db)])
            .unwrap();
        db.execute(
            "INSERT INTO auth.logins VALUES('uncertain','original-slt-hash',1,NULL,NULL)",
            [],
        )
        .unwrap();
        db.execute("UPDATE auth.sessions SET revoke_pending=1", [])
            .unwrap();
        let state = authentication_state(&db).unwrap();
        f.change_map(|m| {
            m["authentication_invalidation"] =
                json!({"auth_state_sha256":state,"iam_evidence_sha256":"ab".repeat(32)})
        });
        db.execute("UPDATE auth.logins SET created=2", []).unwrap();
        drop(db);
        assert!(run(&f.db, KEY, &f.map, true).is_err());
        f.legacy();
        Connection::open(format!("{}.auth", f.db))
            .unwrap()
            .execute("UPDATE logins SET created=1", [])
            .unwrap();
        run(&f.db, KEY, &f.map, true).unwrap();
        let db = f.connection();
        db.execute("ATTACH DATABASE ? AS auth", [format!("{}.auth", f.db)])
            .unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM auth.invalidated_logins WHERE id='uncertain'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM auth.sessions WHERE revoked=0 OR revoke_pending!=0",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(db.query_row("SELECT slt_hash FROM auth.logins WHERE id='uncertain' AND payload IS NULL AND response IS NULL", [], |r|r.get::<_,String>(0)).unwrap(),"original-slt-hash");
    }
}
