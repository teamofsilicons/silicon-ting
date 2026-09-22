//! Proof-bound, app-scoped testing receivers. These never authorize normal sessions or hooks.
use crate::{
    App, Shared,
    auth::Proof,
    error::{Error, Result},
    store, validation as v,
};
use axum::{
    extract::{
        RawQuery, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, Method},
    response::Response,
};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;

const LIFETIME: i64 = 30;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Serialize, Deserialize)]
struct Receiver {
    id: String,
    context: String,
    generation: i64,
    key_hash: String,
    org: String,
    app: String,
    actor: String,
    kind: String,
    expires: i64,
}
impl Receiver {
    fn description(&self) -> Value {
        json!({"receiver_id":self.id,"environment":{"kind":"testing","id":self.context,"generation":self.generation},
            "org_id":self.org,"app_id":self.app,"for":self.actor,"kind":self.kind,
            "expires_at":chrono::DateTime::from_timestamp(self.expires,0).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Secs,true)})
    }
    fn same_authority(&self, other: &Self) -> bool {
        self.context == other.context
            && self.generation == other.generation
            && self.key_hash == other.key_hash
            && self.org == other.org
            && self.app == other.app
            && self.actor == other.actor
            && self.kind == other.kind
    }
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn expired() -> Error {
    Error::new(
        401,
        "receiver_expired",
        "The receiver capability is expired, replaced, or revoked.",
        "Use a fresh receivers.bootstrap proof to explicitly renew or create a test receiver.",
    )
}
fn denied() -> Error {
    Error::new(
        403,
        "permission_denied",
        "The proof does not authorize this test receiver.",
        "Use the current test environment, actor, issuing app, organization, and active subscription.",
    )
}
fn database(app: &App) -> Result<Connection> {
    let db = Connection::open(&app.config.database_path)?;
    db.busy_timeout(Duration::from_secs(5))?;
    initialize(&db)?;
    Ok(db)
}
pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS receiver_sessions(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,payload TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS receiver_operations(id TEXT PRIMARY KEY,ctx TEXT NOT NULL,fingerprint TEXT NOT NULL,response BLOB NOT NULL);")?;
    Ok(())
}
/// Apply inside the lifecycle transaction so restoring an environment never revives old leases.
pub fn fence(db: &Connection, context: &str, action: &str, retired_apps: &Value) -> Result<()> {
    initialize(db)?;
    match action {
        "clean" | "purge" => {
            db.execute(
                "DELETE FROM receiver_sessions WHERE json_extract(payload,'$.context')=?",
                [context],
            )?;
            db.execute("DELETE FROM receiver_operations WHERE ctx=?", [context])?;
        }
        "disable" | "rotate" | "rotate-key" => {
            db.execute(
                "UPDATE receiver_sessions SET revoked=1 WHERE json_extract(payload,'$.context')=?",
                [context],
            )?;
        }
        "retire-applications" => {
            for app in retired_apps
                .as_array()
                .ok_or_else(|| Error::invalid("retired_apps must be an array."))?
            {
                let app = app
                    .as_str()
                    .ok_or_else(|| Error::invalid("retired_apps must contain app IDs."))?;
                db.execute("UPDATE receiver_sessions SET revoked=1 WHERE json_extract(payload,'$.context')=? AND json_extract(payload,'$.app')=?",params![context,app])?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn check(app: &App, db: &Connection, receiver: &Receiver) -> Result<()> {
    if receiver.expires <= store::now() {
        return Err(expired());
    }
    app.auth
        .check_receiver_context(&receiver.context, receiver.generation, &receiver.key_hash)?;
    let active: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM grants WHERE ctx=? AND org=? AND app=? AND recipient=? AND active=1)",
        params![receiver.context,receiver.org,receiver.app,receiver.actor], |r|r.get(0))?;
    if !active {
        return Err(denied());
    }
    Ok(())
}
fn token_hash(token: &str) -> Result<String> {
    if !token
        .strip_prefix("ting_recv_")
        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err(expired());
    }
    Ok(hash(token.as_bytes()))
}
fn authenticate(app: &App, token: &str) -> Result<Receiver> {
    let db = database(app)?;
    let payload: Option<String> = db
        .query_row(
            "SELECT payload FROM receiver_sessions WHERE token_hash=? AND revoked=0",
            [token_hash(token)?],
            |r| r.get(0),
        )
        .optional()?;
    let receiver: Receiver = serde_json::from_str(&payload.ok_or_else(expired)?)?;
    check(app, &db, &receiver)?;
    Ok(receiver)
}
fn bearer(headers: &HeaderMap) -> Result<&str> {
    if headers.get_all("authorization").iter().count() != 1 {
        return Err(expired());
    }
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(expired)
}

pub async fn bootstrap(
    app: &Shared,
    headers: &HeaderMap,
    raw: &[u8],
    body: &Value,
) -> Result<(u16, Value)> {
    v::fields(
        body,
        &[
            "org_id",
            "app_id",
            "for",
            "key",
            "environment_id",
            "generation",
            "receiver_id",
        ],
        &[
            "org_id",
            "app_id",
            "for",
            "key",
            "environment_id",
            "generation",
        ],
    )?;
    for field in ["org_id", "app_id", "for", "environment_id"] {
        v::string(body, field, 255)?;
    }
    v::string(body, "key", 200)?;
    if body.get("receiver_id").is_some() {
        v::string(body, "receiver_id", 255)?;
    }
    if !body["generation"].as_i64().is_some_and(|n| n > 0) {
        return Err(Error::invalid("generation must be a positive integer."));
    }
    let proof = app
        .auth
        .proof(headers, "/v1/receivers/bootstrap", raw)
        .await?;
    let _gate = app.mutations.lock().await;
    issue(app, &proof, raw, body)
}

// Called only after fresh IAM verification and while holding the mutation gate.
fn issue(app: &App, proof: &Proof, raw: &[u8], body: &Value) -> Result<(u16, Value)> {
    app.auth.check_proof(proof)?;
    let (generation, key_hash) = proof.receiver_context().ok_or_else(denied)?;
    if body["app_id"] != proof.app_id
        || body["for"] != proof.actor_id
        || body["environment_id"] != proof.context
        || body["generation"] != generation
        || !matches!(proof.actor_kind.as_str(), "carbon" | "silicon")
    {
        return Err(denied());
    }
    let mut receiver = Receiver {
        id: body["receiver_id"]
            .as_str()
            .map(String::from)
            .unwrap_or_else(|| store::id("receiver")),
        context: proof.context.clone(),
        generation,
        key_hash,
        org: proof.org_id.clone(),
        app: proof.app_id.clone(),
        actor: proof.actor_id.clone(),
        kind: proof.actor_kind.clone(),
        expires: proof.expires_at.min(store::now() + LIFETIME),
    };
    let mut db = database(app)?;
    check(app, &db, &receiver)?;
    // Generation is in the exact request body, so an old retry cannot create authority after a clean.
    let operation = hash(
        serde_json::to_string(&json!([
            receiver.context,
            receiver.org,
            receiver.app,
            receiver.actor,
            receiver.kind,
            body["key"]
        ]))?
        .as_bytes(),
    );
    let fingerprint = hash(raw);
    let tx = db.transaction()?;
    let previous: Option<(String, Vec<u8>)> = tx
        .query_row(
            "SELECT fingerprint,response FROM receiver_operations WHERE id=?",
            [&operation],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((stored, response)) = previous {
        if stored != fingerprint {
            return Err(Error::new(
                409,
                "idempotency_conflict",
                "This receiver key was already used with different request bytes.",
                "Retry the original bytes with a fresh proof, or use a new key for an explicit renewal.",
            ));
        }
        // Recovery returns the original expiry/token; it never resurrects revoked or renewed authority.
        return Ok((
            200,
            app.auth.open(&format!("receiver:{operation}"), &response)?,
        ));
    }
    if body.get("receiver_id").is_some() {
        let old: Option<(String, bool)> = tx
            .query_row(
                "SELECT payload,revoked FROM receiver_sessions WHERE id=?",
                [&receiver.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (payload, revoked) = old.ok_or_else(expired)?;
        let old: Receiver = serde_json::from_str(&payload)?;
        if revoked {
            return Err(expired());
        }
        if !old.same_authority(&receiver) {
            return Err(denied());
        }
        receiver.id = old.id;
    }
    let mut random = [0u8; 32];
    rand::rng().fill_bytes(&mut random);
    let token = format!("ting_recv_{}", hex::encode(random));
    let mut response = receiver.description();
    response["receiver_token"] = token.clone().into();
    tx.execute("INSERT INTO receiver_sessions(id,token_hash,payload) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash,payload=excluded.payload",
        params![receiver.id,hash(token.as_bytes()),serde_json::to_string(&receiver)?])?;
    tx.execute(
        "INSERT INTO receiver_operations VALUES(?,?,?,?)",
        params![
            operation,
            receiver.context,
            fingerprint,
            app.auth.seal(&format!("receiver:{operation}"), &response)?
        ],
    )?;
    tx.commit()?;
    Ok((201, response))
}

pub async fn http(
    app: &Shared,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    filters: &Value,
) -> Result<Response> {
    let _gate = app.mutations.lock().await;
    let token = bearer(headers)?;
    if method == Method::DELETE && path == "receivers/session" {
        v::fields(filters, &[], &[])?;
        // Cleanup remains available after expiry, grant revocation, or environment disablement.
        let db = database(app)?;
        if db.execute(
            "UPDATE receiver_sessions SET revoked=1 WHERE token_hash=?",
            [token_hash(token)?],
        )? == 0
        {
            return Err(expired());
        }
        return Ok(crate::response(200, json!({"revoked":true})));
    }
    let receiver = authenticate(app, token)?;
    let value = match (method.as_str(), path) {
        ("GET", "receivers/me") => {
            v::fields(filters, &[], &[])?;
            receiver.description()
        }
        ("GET", "receivers/inbox") => {
            v::fields(filters, &["type", "read", "silent", "limit", "cursor"], &[])?;
            let rows = app.store.tings(
                &receiver.context,
                &receiver.org,
                Some(&receiver.actor),
                Some(&receiver.app),
                filters,
            )?;
            app.store.page(
                rows,
                &format!("{}:receiver:{}", receiver.context, receiver.id),
                filters,
                true,
            )?
        }
        ("GET", path)
            if path
                .strip_prefix("receivers/inbox/")
                .is_some_and(|id| !id.is_empty() && !id.contains('/')) =>
        {
            v::fields(filters, &[], &[])?;
            app.store.ting(
                &receiver.context,
                &receiver.org,
                path.strip_prefix("receivers/inbox/").unwrap(),
                Some(&receiver.actor),
                Some(&receiver.app),
            )?
        }
        _ => return Err(Error::not_found()),
    };
    Ok(crate::response(200, value))
}

pub async fn upgrade(
    State(app): State<Shared>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    crate::origin(&app, &headers)?;
    let query = crate::query(raw)?;
    v::fields(&query, &["protocol"], &["protocol"])?;
    if query["protocol"] != "v1" {
        return Err(Error::new(
            400,
            "unsupported_protocol",
            "Unsupported WebSocket protocol.",
            "Use protocol=v1.",
        )
        .details(json!({"supported_protocols":["v1"]})));
    }
    Ok(ws
        .max_message_size(2048)
        .max_frame_size(2048)
        .on_upgrade(move |socket| connection(app, socket)))
}
async fn write(socket: &mut WebSocket, value: Value) -> bool {
    matches!(
        tokio::time::timeout(
            IO_TIMEOUT,
            socket.send(Message::Text(value.to_string().into()))
        )
        .await,
        Ok(Ok(()))
    )
}
fn watch_token(body: &Value) -> Result<&str> {
    v::fields(
        body,
        &["op", "request_id", "receiver_token"],
        &["op", "request_id", "receiver_token"],
    )?;
    if body["op"] != "watch" {
        return Err(Error::invalid("The first frame must be watch."));
    }
    v::string(body, "request_id", 128)?;
    v::string(body, "receiver_token", 128)
}
fn socket_error(error: Error, request: &Value) -> Value {
    let mut body = error.body;
    body["op"] = "error".into();
    if let Some(id) = request["request_id"].as_str().filter(|id| id.len() <= 128) {
        body["request_id"] = id.into();
    }
    body
}
async fn connection(app: Shared, mut socket: WebSocket) {
    let deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    if !write(
        &mut socket,
        json!({"op":"ready","receiver_id":store::id("receiver_connection"),"protocol":"v1"}),
    )
    .await
    {
        return;
    }
    let request = match tokio::time::timeout_at(deadline, socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => v::parse(text.as_bytes(), 2048),
        _ => return,
    };
    let request = match request {
        Ok(request) => request,
        Err(error) => {
            write(&mut socket, socket_error(error, &Value::Null)).await;
            return;
        }
    };
    let token = match watch_token(&request) {
        Ok(token) => token.to_owned(),
        Err(error) => {
            write(&mut socket, socket_error(error, &request)).await;
            return;
        }
    };
    let initial = {
        let _gate = app.mutations.lock().await;
        authenticate(&app, &token)
            .and_then(|receiver| Ok((snapshot(&app, &receiver)?, receiver.description())))
    };
    let mut fingerprint = match initial {
        Ok((fingerprint, mut description)) => {
            description["op"] = "watching_inbox".into();
            description["request_id"] = request["request_id"].clone();
            if !write(&mut socket, description).await {
                return;
            }
            fingerprint
        }
        Err(error) => {
            write(&mut socket, socket_error(error, &request)).await;
            return;
        }
    };
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => {},
            _ = app.changed.notified() => {},
            message = socket.recv() => {
                match message {
                    Some(Ok(Message::Ping(bytes))) => {
                        if !matches!(tokio::time::timeout(IO_TIMEOUT,socket.send(Message::Pong(bytes))).await,Ok(Ok(()))) {return;}
                    }
                    Some(Ok(Message::Pong(_))) => {},
                    Some(Ok(Message::Text(text))) => {
                        let request=v::parse(text.as_bytes(),2048).unwrap_or(Value::Null);
                        write(&mut socket,socket_error(Error::invalid("This receiver socket only watches the scoped inbox; renew with fresh proof and reconnect."),&request)).await;
                        return;
                    }
                    _ => return,
                }
            }
        }
        let current = {
            let _gate = app.mutations.lock().await;
            authenticate(&app, &token)
                .and_then(|receiver| Ok((snapshot(&app, &receiver)?, receiver)))
        };
        match current {
            Ok((next, receiver)) => {
                if next != fingerprint {
                    fingerprint = next;
                    if !write(&mut socket,json!({"op":"inbox_changed","environment":{"kind":"testing","id":receiver.context,"generation":receiver.generation},"org_id":receiver.org,"app_id":receiver.app,"receiver_id":receiver.id})).await {return;}
                }
            }
            Err(error) => {
                write(&mut socket, socket_error(error, &Value::Null)).await;
                return;
            }
        }
    }
}

fn snapshot(app: &App, receiver: &Receiver) -> Result<String> {
    let db = database(app)?;
    // ponytail: hash this test app's retained eligible IDs once per second; add scoped change counters if test inbox volume warrants it.
    let mut query = db.prepare("SELECT t.id,t.read FROM tings t WHERE t.ctx=?1 AND t.org=?2 AND t.app=?3 AND t.recipient=?4
        AND t.created>=?5 AND ((t.read=0 AND t.silent=0) OR t.created>=?6)
        AND ((json_extract(t.body,'$.delivery')='required' AND EXISTS(SELECT 1 FROM preferences p WHERE p.ctx=t.ctx AND p.org=t.org AND p.app=t.app AND p.recipient=t.recipient AND p.scope='delivery:required' AND p.enabled=1))
        OR (COALESCE(json_extract(t.body,'$.delivery'),'')<>'required' AND t.silent=0 AND COALESCE((SELECT p.enabled FROM preferences p WHERE p.ctx=t.ctx AND p.org=t.org AND p.app=t.app AND p.recipient=t.recipient
            AND p.scope IN ('type:'||t.type,'service:'||substr(t.type,length(t.app)+2,instr(substr(t.type,length(t.app)+2),'.')-1),'app')
            ORDER BY CASE WHEN p.scope LIKE 'type:%' THEN 0 WHEN p.scope LIKE 'service:%' THEN 1 ELSE 2 END LIMIT 1),1)=1)) ORDER BY t.id")?;
    let rows = query.query_map(
        params![
            receiver.context,
            receiver.org,
            receiver.app,
            receiver.actor,
            store::retention_cutoff(3),
            store::retention_cutoff(1)
        ],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
    )?;
    let mut digest = Sha256::new();
    for row in rows {
        let (id, read) = row?;
        digest.update(id.as_bytes());
        digest.update([0, read as u8]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{Fixture, fixture};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as ClientMessage;

    fn body(f: &Fixture, key: &str) -> Value {
        json!({"org_id":f.proof.org_id,"app_id":f.proof.app_id,"for":f.proof.actor_id,
            "environment_id":f.proof.context,"generation":1,"key":key})
    }
    fn proof_headers() -> HeaderMap {
        HeaderMap::from_iter([
            (
                axum::http::header::AUTHORIZATION,
                "Bearer fixture-proof".parse().unwrap(),
            ),
            (
                "iam_test_app_secret".parse().unwrap(),
                "fixture-secret".parse().unwrap(),
            ),
            (
                "x-testing-environment-key".parse().unwrap(),
                "k".repeat(32).parse().unwrap(),
            ),
        ])
    }
    fn mint(f: &Fixture, key: &str) -> Value {
        let body = body(f, key);
        issue(&f.app, &f.proof, &serde_json::to_vec(&body).unwrap(), &body)
            .unwrap()
            .1
    }
    fn headers(value: &Value) -> HeaderMap {
        HeaderMap::from_iter([(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {}", value["receiver_token"].as_str().unwrap())
                .parse()
                .unwrap(),
        )])
    }
    async fn value(response: Response) -> Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn bootstrap_requires_fresh_proof_and_recovers_exact_bytes_without_extending_expiry() {
        let f = fixture(true).await;
        let b = body(&f, "lost-response");
        let raw = serde_json::to_vec(&b).unwrap();
        let (status, first) = bootstrap(&f.app, &proof_headers(), &raw, &b).await.unwrap();
        assert_eq!(status, 201);
        let expires = chrono::DateTime::parse_from_rfc3339(first["expires_at"].as_str().unwrap())
            .unwrap()
            .timestamp();
        assert!(expires <= store::now() + 30);
        assert_eq!(
            first["environment"],
            json!({"kind":"testing","id":f.proof.context,"generation":1})
        );
        let (status, replay) = bootstrap(&f.app, &proof_headers(), &raw, &b).await.unwrap();
        assert_eq!((status, replay), (200, first.clone()));
        assert_eq!(
            f.take_calls()
                .iter()
                .filter(|p| p.as_str() == "/api/v1/obo-access/verify")
                .count(),
            2
        );
        let mut whitespace = raw.clone();
        whitespace.push(b' ');
        assert_eq!(
            bootstrap(&f.app, &proof_headers(), &whitespace, &b)
                .await
                .unwrap_err()
                .status,
            409
        );
        let db = database(&f.app).unwrap();
        let receipt: Vec<u8> = db
            .query_row("SELECT response FROM receiver_operations", [], |r| r.get(0))
            .unwrap();
        let token = first["receiver_token"].as_str().unwrap();
        assert!(
            !receipt
                .windows(token.len())
                .any(|bytes| bytes == token.as_bytes())
        );
        assert!(
            f.app
                .auth
                .authenticate(token, &HeaderMap::new())
                .await
                .is_err()
        );
        f.iam.status.store(403, std::sync::atomic::Ordering::SeqCst);
        assert!(
            bootstrap(&f.app, &proof_headers(), &raw, &b).await.is_err(),
            "recovery must not bypass current IAM verification"
        );
    }

    #[tokio::test]
    async fn receiver_renewal_revoke_and_local_authority_fences_are_fail_closed() {
        for kind in ["carbon", "silicon"] {
            let mut f = fixture(true).await;
            f.proof.actor_kind = kind.into();
            f.proof.expires_at = store::now() + 10;
            let first = mint(&f, "first");
            let token = first["receiver_token"].as_str().unwrap();
            let current = authenticate(&f.app, token).unwrap();
            assert_eq!(current.kind, kind);
            assert_eq!(current.expires, f.proof.expires_at);
            let mut renewal = body(&f, "renew");
            renewal["receiver_id"] = first["receiver_id"].clone();
            let (_, renewed) = issue(
                &f.app,
                &f.proof,
                &serde_json::to_vec(&renewal).unwrap(),
                &renewal,
            )
            .unwrap();
            assert_eq!(renewed["receiver_id"], first["receiver_id"]);
            assert_ne!(renewed["receiver_token"], first["receiver_token"]);
            assert!(authenticate(&f.app, token).is_err());
            assert_eq!(
                mint(&f, "first"),
                first,
                "replay never rotates a replaced token back in"
            );
            let token = renewed["receiver_token"].as_str().unwrap();
            let mut expired_receiver = authenticate(&f.app, token).unwrap();
            expired_receiver.expires = store::now() - 1;
            let db = database(&f.app).unwrap();
            db.execute(
                "UPDATE receiver_sessions SET payload=? WHERE id=?",
                params![
                    serde_json::to_string(&expired_receiver).unwrap(),
                    expired_receiver.id
                ],
            )
            .unwrap();
            assert!(authenticate(&f.app, token).is_err());
            // Expired leases can be renewed only through a new, freshly verified proof operation.
            renewal["key"] = "renew-expired".into();
            let renewed = issue(
                &f.app,
                &f.proof,
                &serde_json::to_vec(&renewal).unwrap(),
                &renewal,
            )
            .unwrap()
            .1;
            let token = renewed["receiver_token"].as_str().unwrap();
            assert!(authenticate(&f.app, token).is_ok());
            db.execute("UPDATE grants SET active=0", []).unwrap();
            assert!(authenticate(&f.app, token).is_err());
            assert!(
                issue(
                    &f.app,
                    &f.proof,
                    &serde_json::to_vec(&renewal).unwrap(),
                    &renewal
                )
                .is_err()
            );
            db.execute("UPDATE grants SET active=1", []).unwrap();
            db.execute("UPDATE lifecycle_environments SET generation=2", [])
                .unwrap();
            assert!(authenticate(&f.app, token).is_err());
            db.execute(
                "UPDATE lifecycle_environments SET generation=1,state='disabled'",
                [],
            )
            .unwrap();
            assert!(authenticate(&f.app, token).is_err());
            db.execute(
                "UPDATE lifecycle_environments SET state='active',key_hash='rotated'",
                [],
            )
            .unwrap();
            assert!(authenticate(&f.app, token).is_err());
            // Revoke cleanup works even when the environment is no longer usable, and is idempotent.
            for _ in 0..2 {
                assert_eq!(
                    http(
                        &f.app,
                        &Method::DELETE,
                        "receivers/session",
                        &headers(&renewed),
                        &json!({})
                    )
                    .await
                    .unwrap()
                    .status(),
                    200
                );
            }
            db.execute(
                "UPDATE lifecycle_environments SET key_hash=?",
                [current.key_hash],
            )
            .unwrap();
            renewal["key"] = "after-revoke".into();
            assert_eq!(
                issue(
                    &f.app,
                    &f.proof,
                    &serde_json::to_vec(&renewal).unwrap(),
                    &renewal
                )
                .unwrap_err()
                .status,
                401
            );
        }
        let production = fixture(false).await;
        let b = body(&production, "production");
        assert_eq!(
            issue(
                &production.app,
                &production.proof,
                &serde_json::to_vec(&b).unwrap(),
                &b
            )
            .unwrap_err()
            .status,
            403
        );
    }

    #[tokio::test]
    async fn receiver_binding_and_inbox_cannot_cross_actor_app_environment_or_ack() {
        let mut f = fixture(true).await;
        for (field, value) in [
            ("for", json!("si_other")),
            ("app_id", json!("tos>other")),
            ("environment_id", json!(uuid::Uuid::new_v4())),
            ("generation", json!(2)),
        ] {
            let mut b = body(&f, "mismatch");
            b[field] = value;
            assert_eq!(
                issue(&f.app, &f.proof, &serde_json::to_vec(&b).unwrap(), &b)
                    .unwrap_err()
                    .status,
                403
            );
        }
        let first = mint(&f, "inbox");
        let hook = f.hook("existing-full-receiver");
        let own = f.send("own");
        let other = f.send("other");
        let db = database(&f.app).unwrap();
        db.execute("UPDATE tings SET app='tos>other' WHERE id=?", [&other])
            .unwrap();
        let response = http(
            &f.app,
            &Method::GET,
            "receivers/inbox",
            &headers(&first),
            &json!({}),
        )
        .await
        .unwrap();
        let response = value(response).await;
        assert_eq!(response["items"].as_array().unwrap().len(), 1);
        assert_eq!(response["items"][0]["id"], own);
        assert!(!response["items"][0]["read"].as_bool().unwrap());
        assert_eq!(
            http(
                &f.app,
                &Method::GET,
                &format!("receivers/inbox/{other}"),
                &headers(&first),
                &json!({})
            )
            .await
            .unwrap_err()
            .status,
            404
        );
        assert_eq!(
            http(
                &f.app,
                &Method::GET,
                "receivers/inbox",
                &headers(&first),
                &json!({"for":"si_other"})
            )
            .await
            .unwrap_err()
            .status,
            400
        );
        assert_eq!(
            http(
                &f.app,
                &Method::POST,
                "receivers/ack",
                &headers(&first),
                &json!({})
            )
            .await
            .unwrap_err()
            .status,
            404
        );
        assert_eq!(f.receipt(&hook, &own), (0, 0));
        let b = body(&f, "org");
        f.proof.org_id = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            issue(&f.app, &f.proof, &serde_json::to_vec(&b).unwrap(), &b)
                .unwrap_err()
                .status,
            403
        );
    }

    #[tokio::test]
    async fn lifecycle_fences_survive_restore_and_clean_erases_receiver_state() {
        for action in ["disable", "rotate", "rotate-key", "retire-applications"] {
            let mut f = fixture(true).await;
            let original = mint(&f, "before-lifecycle");
            let original_app = f.proof.app_id.clone();
            let mut db = database(&f.app).unwrap();
            f.proof.app_id = "tos>other".into();
            db.execute(
                "INSERT INTO grants VALUES('other-grant',?,?,?,?,1)",
                params![
                    f.proof.context,
                    f.proof.org_id,
                    f.proof.app_id,
                    f.proof.actor_id
                ],
            )
            .unwrap();
            let other = mint(&f, "other-app");
            let tx = db.transaction().unwrap();
            fence(&tx, &f.proof.context, action, &json!([original_app])).unwrap();
            tx.commit().unwrap();
            // A later restore can reuse the same generation/key, but cannot undo the receiver tombstone.
            db.execute("UPDATE lifecycle_environments SET state='disabled'", [])
                .unwrap();
            db.execute("UPDATE lifecycle_environments SET state='active'", [])
                .unwrap();
            assert!(
                authenticate(&f.app, original["receiver_token"].as_str().unwrap()).is_err(),
                "{action}"
            );
            assert_eq!(
                authenticate(&f.app, other["receiver_token"].as_str().unwrap()).is_ok(),
                action == "retire-applications"
            );
            f.proof.app_id = original_app;
            assert_eq!(
                mint(&f, "before-lifecycle"),
                original,
                "recovery cannot undo revocation"
            );
            assert!(authenticate(&f.app, original["receiver_token"].as_str().unwrap()).is_err());
            assert!(
                authenticate(
                    &f.app,
                    mint(&f, "new-after-restore")["receiver_token"]
                        .as_str()
                        .unwrap()
                )
                .is_ok()
            );
            for cleanup in ["clean", "purge"] {
                let tx = db.transaction().unwrap();
                fence(&tx, &f.proof.context, cleanup, &Value::Null).unwrap();
                tx.commit().unwrap();
                for table in ["receiver_sessions", "receiver_operations"] {
                    assert_eq!(
                        db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                            .get::<_, i64>(0))
                            .unwrap(),
                        0
                    );
                }
            }
        }
    }

    async fn socket_json<S>(socket: &mut tokio_tungstenite::WebSocketStream<S>) -> Value
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let frame = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        serde_json::from_str(frame.to_text().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn watch_has_scoped_hints_and_closes_on_revocation() {
        let f = fixture(true).await;
        let cap = mint(&f, "watch");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/receivers/ws", listener.local_addr().unwrap());
        let app = f.app.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, crate::router(app)).await.unwrap();
        });
        for query in [
            "protocol=v2",
            "protocol=v1&receiver_token=secret",
            "protocol=v1&protocol=v1",
        ] {
            assert!(
                tokio_tungstenite::connect_async(format!("{url}?{query}"))
                    .await
                    .is_err()
            );
        }
        let (mut socket, _) = tokio_tungstenite::connect_async(format!("{url}?protocol=v1"))
            .await
            .unwrap();
        assert_eq!(socket_json(&mut socket).await["op"], "ready");
        socket
            .send(ClientMessage::Text(
                json!({"op":"watch","request_id":"watch-1","receiver_token":cap["receiver_token"]})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        let watching = socket_json(&mut socket).await;
        assert_eq!(watching["op"], "watching_inbox");
        assert_eq!(watching["request_id"], "watch-1");
        let receiver = authenticate(&f.app, cap["receiver_token"].as_str().unwrap()).unwrap();
        let before = snapshot(&f.app, &receiver).unwrap();
        let other = f.send("other-app");
        let db = database(&f.app).unwrap();
        db.execute("UPDATE tings SET app='tos>other' WHERE id=?", [other])
            .unwrap();
        db.execute(
            "INSERT INTO preferences VALUES(?,?,?,?,'app',0)",
            params![
                f.proof.context,
                f.proof.org_id,
                f.proof.actor_id,
                f.proof.app_id
            ],
        )
        .unwrap();
        let silent = f.send("silent");
        db.execute("DELETE FROM preferences WHERE scope='app'", [])
            .unwrap();
        assert_eq!(snapshot(&f.app, &receiver).unwrap(), before);
        f.app.changed.notify_waiters();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), socket.next())
                .await
                .is_err()
        );
        f.send("visible");
        f.app.changed.notify_waiters();
        let hint = socket_json(&mut socket).await;
        assert_eq!(hint["op"], "inbox_changed");
        assert_eq!(hint["app_id"], f.proof.app_id);
        let visible = snapshot(&f.app, &receiver).unwrap();
        db.execute(
            "INSERT INTO preferences VALUES(?,?,?,?,'delivery:required',1)",
            params![
                f.proof.context,
                f.proof.org_id,
                f.proof.actor_id,
                f.proof.app_id
            ],
        )
        .unwrap();
        let mut required = f
            .app
            .store
            .ting(
                &f.proof.context,
                &f.proof.org_id,
                &silent,
                Some(&f.proof.actor_id),
                Some(&f.proof.app_id),
            )
            .unwrap();
        required["delivery"] = "required".into();
        db.execute(
            "UPDATE tings SET body=? WHERE id=?",
            params![required.to_string(), required["id"].as_str()],
        )
        .unwrap();
        assert_ne!(
            snapshot(&f.app, &receiver).unwrap(),
            visible,
            "required silent records are eligible with opt-in"
        );
        db.execute(
            "DELETE FROM preferences WHERE scope='delivery:required'",
            [],
        )
        .unwrap();
        assert_eq!(
            snapshot(&f.app, &receiver).unwrap(),
            visible,
            "removing opt-in suppresses required hints"
        );
        db.execute("UPDATE grants SET active=0", []).unwrap();
        f.app.changed.notify_waiters();
        assert_eq!(socket_json(&mut socket).await["op"], "error");
        let closed = tokio::time::timeout(Duration::from_secs(1), socket.next())
            .await
            .unwrap();
        assert!(
            closed.is_none()
                || closed.is_some_and(|v| v.is_err() || matches!(v, Ok(ClientMessage::Close(_))))
        );
        server.abort();
    }

    #[tokio::test]
    async fn socket_requires_bounded_first_watch_and_rejects_other_operations() {
        let f = fixture(true).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "ws://{}/v1/receivers/ws?protocol=v1",
            listener.local_addr().unwrap()
        );
        let app = f.app.clone();
        let server = tokio::spawn(async move {
            axum::serve(listener, crate::router(app)).await.unwrap();
        });
        let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        socket_json(&mut socket).await;
        socket
            .send(ClientMessage::Text(
                json!({"op":"ack","request_id":"ack","receiver_token":"ting_recv_invalid"})
                    .to_string()
                    .into(),
            ))
            .await
            .unwrap();
        let error = socket_json(&mut socket).await;
        assert_eq!(error["op"], "error");
        assert_eq!(error["request_id"], "ack");
        let (mut oversized, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        socket_json(&mut oversized).await;
        oversized
            .send(ClientMessage::Text("a".repeat(2049).into()))
            .await
            .unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(1), oversized.next())
            .await
            .unwrap();
        assert!(
            closed.is_none()
                || closed.is_some_and(|v| v.is_err() || matches!(v, Ok(ClientMessage::Close(_))))
        );
        let (mut idle, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        socket_json(&mut idle).await;
        let closed = tokio::time::timeout(Duration::from_secs(6), idle.next())
            .await
            .unwrap();
        assert!(
            closed.is_none()
                || closed.is_some_and(|v| v.is_err() || matches!(v, Ok(ClientMessage::Close(_))))
        );
        server.abort();
    }
}
