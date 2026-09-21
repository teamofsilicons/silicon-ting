//! Honeycomb's authenticated, replay-safe testing lifecycle participant.
use crate::{
    Shared,
    error::{Error, Result},
    validation as v,
};
use axum::{
    Json,
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn conflict(message: &str) -> Error {
    Error::new(
        409,
        "lifecycle_conflict",
        message,
        "Retry the original lifecycle operation and current environment revision.",
    )
}
fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn verify_token(headers: &HeaderMap) -> Result<()> {
    use subtle::ConstantTimeEq;
    let expected = std::env::var("TING_HONEYCOMB_CONTROL_TOKEN")
        .ok()
        .filter(|s| s.len() >= 32)
        .ok_or_else(|| {
            Error::unavailable("Honeycomb lifecycle service authority has not been configured.")
        })?;
    let provided = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");
    if !bool::from(Sha256::digest(provided.as_bytes()).ct_eq(&Sha256::digest(expected.as_bytes())))
    {
        return Err(Error::new(
            401,
            "authentication_required",
            "Dedicated Honeycomb lifecycle service authority is required.",
            "Use the configured service token; an IAM user credential or testing key is not lifecycle authority.",
        ));
    }
    Ok(())
}
pub async fn handle(
    State(app): State<Shared>,
    Path((org, environment, operation)): Path<(String, String, String)>,
    headers: HeaderMap,
    raw: Bytes,
) -> Result<Json<Value>> {
    verify_token(&headers)?;
    let body = v::parse(&raw, 1024 * 1024)?;
    let command = Command::parse(&body, &org, &environment, &operation)?;
    let _gate = app.mutations.lock().await;
    let mut db = Connection::open(&app.config.database_path)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS lifecycle_operations (id TEXT PRIMARY KEY,environment TEXT NOT NULL,fingerprint TEXT NOT NULL,state TEXT NOT NULL,receipt TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS lifecycle_environments (id TEXT PRIMARY KEY,revision INTEGER NOT NULL,generation INTEGER NOT NULL,key_version INTEGER NOT NULL,key_hash TEXT NOT NULL,state TEXT NOT NULL);")?;
    let fingerprint = digest(&serde_json::to_vec(&body)?);
    let old: Option<(String, String, String)> = db
        .query_row(
            "SELECT fingerprint,state,receipt FROM lifecycle_operations WHERE id=?",
            [&operation],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some((fp, state, receipt)) = &old {
        if fp != &fingerprint {
            return Err(conflict("This operation ID was used with different input."));
        }
        if state == "completed" {
            return Ok(Json(serde_json::from_str(receipt)?));
        }
    } else {
        let current:Option<(i64,i64,i64,String)>=db.query_row("SELECT revision,generation,key_version,state FROM lifecycle_environments WHERE id=?",[&environment],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        command.validate_transition(current.as_ref())?;
        let pending:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM lifecycle_operations WHERE environment=? AND state!='completed')",[&environment],|r|r.get(0))?;
        if pending {
            return Err(conflict(
                "An earlier lifecycle operation must finish first.",
            ));
        }
        db.execute(
            "INSERT INTO lifecycle_operations VALUES(?,?,?,'pending',?)",
            params![
                operation,
                environment,
                fingerprint,
                command.receipt().to_string()
            ],
        )?;
    }
    let revoke = matches!(
        command.action.as_str(),
        "clean" | "purge" | "disable" | "rotate" | "retire-applications"
    );
    app.auth
        .fence_context(&environment, "pending", &command.key_hash, revoke)?;
    for (org, recipient) in app.store.context_owners(&environment)? {
        app.hub
            .invalidate(&app, &environment, &org, &recipient, "permission_changed")
            .await?;
    }
    if old.as_ref().is_none_or(|(_, state, _)| state == "pending") {
        let tx = db.transaction()?;
        if matches!(command.action.as_str(), "clean" | "purge") {
            tx.execute("DELETE FROM deliveries WHERE hook IN(SELECT id FROM hooks WHERE ctx=?) OR message IN(SELECT id FROM tings WHERE ctx=?)",params![environment,environment])?;
            for table in ["hooks", "tings", "types", "grants", "preferences", "keys"] {
                tx.execute(&format!("DELETE FROM {table} WHERE ctx=?"), [&environment])?;
            }
            tx.execute(
                "DELETE FROM cursors WHERE substr(binding,1,?)=?",
                params![environment.len() + 1, format!("{environment}:")],
            )?;
        }
        if command.action == "retire-applications" {
            for retired in command.body["retired_apps"].as_array().unwrap() {
                // Retained history remains readable; retired issuers cannot resume pending delivery.
                tx.execute(
                    "UPDATE grants SET active=0 WHERE ctx=? AND app=?",
                    params![environment, retired.as_str().unwrap()],
                )?;
            }
        }
        tx.execute("INSERT INTO lifecycle_environments VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,generation=excluded.generation,key_version=excluded.key_version,key_hash=excluded.key_hash,state=excluded.state",params![environment,command.revision,command.generation,command.key_version,command.key_hash,command.state])?;
        // This marker commits in the same transaction as deletion. An uncertain retry
        // finishes authentication finalization without erasing newly-created records.
        tx.execute(
            "UPDATE lifecycle_operations SET state='applied' WHERE id=?",
            [&operation],
        )?;
        tx.commit()?;
    }
    app.auth
        .fence_context(&environment, &command.state, &command.key_hash, false)?;
    db.execute(
        "UPDATE lifecycle_operations SET state='completed' WHERE id=?",
        [&operation],
    )?;
    app.changed.notify_waiters();
    Ok(Json(command.receipt()))
}

struct Command {
    body: Value,
    action: String,
    revision: i64,
    generation: i64,
    key_version: i64,
    key_hash: String,
    state: String,
}
impl Command {
    fn parse(body: &Value, org: &str, environment: &str, operation: &str) -> Result<Self> {
        v::fields(
            body,
            &[
                "operation_id",
                "environment_id",
                "org_id",
                "app_id",
                "environment_revision",
                "generation",
                "key_version",
                "action",
                "testing_key",
                "snapshot",
                "name",
                "description",
                "reason",
                "retired_apps",
            ],
            &[
                "operation_id",
                "environment_id",
                "org_id",
                "app_id",
                "environment_revision",
                "generation",
                "key_version",
                "action",
                "testing_key",
            ],
        )?;
        for id in [environment, operation] {
            if uuid::Uuid::parse_str(id).is_err() || uuid::Uuid::parse_str(id).unwrap().is_nil() {
                return Err(Error::invalid("Lifecycle IDs must be non-nil UUIDs."));
            }
        }
        if body["org_id"] != org
            || body["environment_id"] != environment
            || body["operation_id"] != operation
            || body["app_id"] != "tos>ting"
        {
            return Err(Error::invalid(
                "Lifecycle path and application must match the body.",
            ));
        }
        let action = v::string(body, "action", 64)?.to_owned();
        if !matches!(
            action.as_str(),
            "prepare"
                | "import"
                | "rotate"
                | "clean"
                | "disable"
                | "restore"
                | "purge"
                | "retire-applications"
        ) {
            return Err(Error::invalid("Unsupported lifecycle action."));
        }
        let version = |key: &str| {
            body[key]
                .as_i64()
                .filter(|v| *v > 0)
                .ok_or_else(|| Error::invalid(format!("{key} must be a positive integer.")))
        };
        let key = v::string(body, "testing_key", 32)?;
        if key.len() != 32 || !key.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(Error::invalid(
                "testing_key must have IAM's 32-character wire format.",
            ));
        }
        let state = match action.as_str() {
            "disable" => "disabled",
            "purge" => "purged",
            "retire-applications" => {
                let retired = body["retired_apps"]
                    .as_array()
                    .ok_or_else(|| Error::invalid("retired_apps must be an array."))?;
                if retired.iter().any(|x| x.as_str().is_none()) {
                    return Err(Error::invalid("retired_apps must contain app IDs."));
                }
                if retired.iter().any(|x| x == "tos>ting") {
                    "retired"
                } else {
                    "active"
                }
            }
            _ => "active",
        }
        .to_owned();
        Ok(Self {
            body: body.clone(),
            action,
            revision: version("environment_revision")?,
            generation: version("generation")?,
            key_version: version("key_version")?,
            key_hash: digest(key.as_bytes()),
            state,
        })
    }
    fn validate_transition(&self, current: Option<&(i64, i64, i64, String)>) -> Result<()> {
        if let Some((revision, generation, key_version, state)) = current {
            if self.revision <= *revision
                || self.generation < *generation
                || self.key_version < *key_version
                || state == "purged"
            {
                return Err(conflict(
                    "Lifecycle operation is stale or the environment was purged.",
                ));
            }
            if self.action == "restore" && state != "disabled" {
                return Err(conflict("Only a disabled environment can be restored."));
            }
            if self.action == "clean" && self.generation <= *generation {
                return Err(conflict(
                    "Cleaning must advance the environment generation.",
                ));
            }
            if self.action == "rotate" && self.key_version <= *key_version {
                return Err(conflict("Rotation must advance the key version."));
            }
        } else if !matches!(self.action.as_str(), "prepare" | "import") {
            return Err(conflict(
                "Prepare or import the testing environment before changing it.",
            ));
        }
        Ok(())
    }
    fn receipt(&self) -> Value {
        let mut receipt = json!({"state":"completed"});
        for field in [
            "operation_id",
            "environment_id",
            "app_id",
            "environment_revision",
            "generation",
            "key_version",
            "retired_apps",
        ] {
            if let Some(value) = self.body.get(field) {
                receipt[field] = value.clone();
            }
        }
        receipt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_rejects_unbound_actions_and_stale_generations() {
        let env = uuid::Uuid::new_v4().to_string();
        let op = uuid::Uuid::new_v4().to_string();
        let mut body = json!({"app_id":"tos>ting","org_id":"tos","environment_id":env,"operation_id":op,"environment_revision":2,"generation":1,"key_version":1,"action":"import","testing_key":"a".repeat(32)});
        let command = Command::parse(&body, "tos", &env, &op).unwrap();
        assert!(command.validate_transition(None).is_ok());
        assert!(command.receipt().get("testing_key").is_none());
        assert!(
            command
                .validate_transition(Some(&(2, 1, 1, "active".into())))
                .is_err()
        );
        body["action"] = json!("clean");
        let command = Command::parse(&body, "tos", &env, &op).unwrap();
        assert!(
            command
                .validate_transition(Some(&(1, 1, 1, "active".into())))
                .is_err()
        );
        body["app_id"] = json!("tos>other");
        assert!(Command::parse(&body, "tos", &env, &op).is_err());
    }
}
