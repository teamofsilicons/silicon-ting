//! Upstream authority is always checked live; only encrypted credentials are stored locally.
use crate::error::{Error, Result};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axum::http::HeaderMap;
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use silicon_iam_client::{Client, Credential, EnvironmentKey, IdempotencyKey, Mutation, models};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Clone)]
pub struct Principal {
    pub context: String,
    pub id: String,
    pub kind: String,
    pub session: String,
}
pub struct Proof {
    pub context: String,
    pub org_id: String,
    pub app_id: String,
    pub actor_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct TestContext {
    id: String,
    secret: String,
    key: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Session {
    context: String,
    id: String,
    kind: String,
    access: String,
    refresh: String,
    expires: i64,
    test: Option<TestContext>,
    refresh_key: Option<String>,
    revoke_key: String,
}
pub struct Auth {
    db: Mutex<Connection>,
    cipher: Aes256Gcm,
    iam: Client,
    app_id: String,
    honeycomb: String,
    station: String,
    station_key: String,
    station_table: String,
    http: reqwest::Client,
    locks: Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
    telemetry: Option<space_station::SpaceClient>,
    webhook: Option<silicon_iam_client::webhook::WebhookVerifier>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn hash(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
fn unavailable() -> Error {
    Error::unavailable(
        "An authentication dependency could not confirm authority; retry when it is available.",
    )
}
fn expired() -> Error {
    Error::new(
        401,
        "session_expired",
        "The Ting session is expired or revoked.",
        "Log in with a fresh Ting-bound IAM short-lived token.",
    )
}
fn forbidden() -> Error {
    Error::new(
        403,
        "permission_denied",
        "Current authority does not permit this operation.",
        "Check selected IAM organizations and the application's approved permissions.",
    )
}
fn storage(_: impl std::fmt::Display) -> Error {
    Error::new(
        503,
        "storage_unavailable",
        "Credential storage is unavailable.",
        "Retry the same operation and idempotency key.",
    )
}
fn iam_error(error: silicon_iam_client::Error) -> Error {
    match error {
        silicon_iam_client::Error::Api(e) if e.status == 401 => expired(),
        silicon_iam_client::Error::Api(e)
            if e.status == 400 && (e.code.contains("slt") || e.code == "invalid_grant") =>
        {
            expired()
        }
        silicon_iam_client::Error::Api(e) if e.status == 403 => forbidden(),
        silicon_iam_client::Error::Api(e) if e.code == "idempotency_conflict" => Error::new(
            409,
            "idempotency_conflict",
            "IAM rejected a changed idempotent operation.",
            "Repeat the original request with its original key.",
        ),
        _ => unavailable(),
    }
}
fn mutation(key: &str) -> Result<Mutation> {
    Ok(Mutation::with_key(IdempotencyKey::parse(key).map_err(
        |_| Error::invalid("Idempotency-Key must contain 16–255 visible ASCII characters."),
    )?))
}
fn secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn bearer(headers: &HeaderMap) -> Result<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty() && v.len() <= 8192)
        .ok_or_else(|| {
            Error::new(
                401,
                "authentication_required",
                "An IAM App Proof Token is required.",
                "Prepare the exact request and obtain a fresh IAM proof.",
            )
        })
}

impl Auth {
    pub fn new(config: &crate::Config) -> anyhow::Result<Self> {
        let key = hex::decode(&config.encryption_key).map_err(|_| {
            anyhow::anyhow!("TING_ENCRYPTION_KEY must be 64 hexadecimal characters")
        })?;
        anyhow::ensure!(
            key.len() == 32,
            "TING_ENCRYPTION_KEY must encode 32 random bytes"
        );
        let file = format!("{}.auth", config.database_path);
        let db = Connection::open(&file)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
        }
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, payload BLOB NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, revoke_pending INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS logins (id TEXT PRIMARY KEY, slt_hash TEXT NOT NULL, created INTEGER NOT NULL, payload BLOB, response BLOB);
            CREATE TABLE IF NOT EXISTS testing_contexts (id TEXT PRIMARY KEY,state TEXT NOT NULL,key_hash TEXT NOT NULL);")?;
        let iam = Client::new(&config.iam_url)?.with_credential(Credential::application(
            &config.iam_app_id,
            &config.iam_app_secret,
        ));
        let telemetry = if config.spacestation_key.is_empty() {
            None
        } else {
            Some(
                space_station::SpaceClient::builder(&config.spacestation_key)
                    .url(&config.spacestation_url)
                    .home(format!("{}.telemetry", config.database_path))
                    .flush_timeout(Duration::from_millis(100))
                    .on_error(|_| {})
                    .build()?,
            )
        };
        let webhook = std::env::var("TING_IAM_WEBHOOK_SECRET")
            .ok()
            .map(|secret| -> anyhow::Result<_> {
                use silicon_iam_client::webhook::{
                    WebhookSecret, WebhookSecretKeyring, WebhookVerifier,
                };
                let version = std::env::var("TING_IAM_WEBHOOK_SECRET_VERSION")
                    .unwrap_or_else(|_| "1".into())
                    .parse::<i64>()?;
                Ok(WebhookVerifier::new(WebhookSecretKeyring::new(
                    version,
                    WebhookSecret::new(secret)?,
                )?))
            })
            .transpose()?;
        Ok(Self {
            db: Mutex::new(db),
            cipher: Aes256Gcm::new_from_slice(&key)
                .map_err(|_| anyhow::anyhow!("Invalid encryption key"))?,
            iam,
            app_id: config.iam_app_id.clone(),
            honeycomb: config.honeycomb_url.trim_end_matches('/').into(),
            station: config.spacestation_url.trim_end_matches('/').into(),
            station_key: config.spacestation_key.clone(),
            station_table: config.spacestation_table.clone(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            locks: Mutex::new(HashMap::new()),
            telemetry,
            webhook,
        })
    }
    pub fn diagnostic(&self, event: &str, method: &str, path: &str, status: u16, elapsed_ms: u64) {
        if let Some(telemetry) = &self.telemetry {
            telemetry.record(json!({"source":"ting.backend","event":event,"step":"complete","method":method,"path":path,"status":status,"elapsed_ms":elapsed_ms,"version":env!("CARGO_PKG_VERSION")}));
        }
    }
    pub fn webhook(&self, headers: &HeaderMap, raw: &[u8]) -> Result<Value> {
        self.webhook
            .as_ref()
            .ok_or_else(unavailable)?
            .verify(headers, raw)
            .map_err(|_| {
                Error::new(
                    401,
                    "authentication_required",
                    "IAM webhook signature verification failed.",
                    "Use the current signing key and exact signed request bytes.",
                )
            })?;
        // IAM authority is checked live on each operation and every 30 seconds for receivers;
        // webhook redelivery therefore needs no mutable authorization projection.
        Ok(json!({"accepted":true}))
    }
    pub async fn revalidate(&self, p: &Principal) -> Result<Principal> {
        let (s, _) = self.live(&p.session).await?;
        if s.id != p.id || s.context != p.context || s.kind != p.kind {
            return Err(expired());
        }
        Ok(p.clone())
    }
    pub async fn authenticate_session(&self, id: &str) -> Result<Principal> {
        let (s, _) = self.live(id).await?;
        Ok(Principal {
            context: s.context,
            id: s.id,
            kind: s.kind,
            session: id.into(),
        })
    }
    pub fn fence_context(
        &self,
        context: &str,
        state: &str,
        key_hash: &str,
        revoke: bool,
    ) -> Result<()> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage)?;
        tx.execute("INSERT INTO testing_contexts VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,key_hash=excluded.key_hash",params![context,state,key_hash]).map_err(storage)?;
        if revoke {
            // ponytail: lifecycle scans encrypted sessions; add a context index if this becomes large.
            let rows: Vec<(String, Vec<u8>)> = {
                let mut q = tx
                    .prepare("SELECT id,payload FROM sessions WHERE revoked=0")
                    .map_err(storage)?;
                q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                    .map_err(storage)?
                    .collect::<std::result::Result<_, _>>()
                    .map_err(storage)?
            };
            for (id, bytes) in rows {
                let session: Session = self.open(&id, &bytes)?;
                if session.context == context {
                    tx.execute(
                        "UPDATE sessions SET revoked=1,revoke_pending=1 WHERE id=?",
                        [id],
                    )
                    .map_err(storage)?;
                }
            }
        }
        tx.commit().map_err(storage)?;
        Ok(())
    }
    fn check_context(&self, context: &str, key: &str) -> Result<()> {
        let known: Option<(String, String)> = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT state,key_hash FROM testing_contexts WHERE id=?",
                [context],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        if let Some((state, expected)) = known {
            if state == "pending" {
                return Err(Error::unavailable(
                    "This testing environment has an unfinished lifecycle operation.",
                ));
            }
            if state != "active" || expected != hash(key.as_bytes()) {
                return Err(forbidden());
            }
        }
        Ok(())
    }
    fn lock(&self, id: &str) -> Arc<AsyncMutex<()>> {
        let mut locks = self.locks.lock().unwrap();
        locks.retain(|_, v| v.strong_count() > 0);
        if let Some(lock) = locks.get(id).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(AsyncMutex::new(()));
        locks.insert(id.into(), Arc::downgrade(&lock));
        lock
    }
    fn seal(&self, id: &str, value: &impl Serialize) -> Result<Vec<u8>> {
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        let bytes = serde_json::to_vec(value).map_err(storage)?;
        let encrypted = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &bytes,
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| storage("encryption"))?;
        Ok([nonce.as_slice(), encrypted.as_slice()].concat())
    }
    fn open<T: serde::de::DeserializeOwned>(&self, id: &str, bytes: &[u8]) -> Result<T> {
        if bytes.len() < 28 {
            return Err(storage("invalid ciphertext"));
        }
        let data = self
            .cipher
            .decrypt(
                Nonce::from_slice(&bytes[..12]),
                Payload {
                    msg: &bytes[12..],
                    aad: id.as_bytes(),
                },
            )
            .map_err(|_| storage("decryption"))?;
        serde_json::from_slice(&data).map_err(storage)
    }
    fn session(&self, id: &str) -> Result<Session> {
        let data: Option<Vec<u8>> = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT payload FROM sessions WHERE id=? AND revoked=0",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?;
        self.open(id, &data.ok_or_else(expired)?)
    }
    fn save(&self, id: &str, s: &Session) -> Result<()> {
        let encrypted = self.seal(id, s)?;
        self.db
            .lock()
            .unwrap()
            .execute(
                "UPDATE sessions SET payload=? WHERE id=?",
                params![encrypted, id],
            )
            .map_err(storage)?;
        Ok(())
    }
    fn client(&self, test: Option<&TestContext>) -> Result<Client> {
        match test {
            Some(t) => Ok(self
                .iam
                .with_credential(Credential::application(&self.app_id, &t.secret))
                .with_environment(EnvironmentKey::new(&t.key).map_err(|_| forbidden())?)),
            None => Ok(self.iam.clone()),
        }
    }
    async fn test_headers(&self, headers: &HeaderMap) -> Result<Option<TestContext>> {
        let secret = headers.get("iam_test_app_secret");
        let key = headers.get("x-testing-environment-key");
        match (secret, key) {
            (None, None) => Ok(None),
            (Some(secret), Some(key)) => {
                let mut test = TestContext {
                    id: String::new(),
                    secret: secret.to_str().map_err(|_| forbidden())?.into(),
                    key: key.to_str().map_err(|_| forbidden())?.into(),
                };
                let validated = self
                    .client(Some(&test))?
                    .applications()
                    .testing_context()
                    .await
                    .map_err(iam_error)?;
                if validated.application.app_id != self.app_id {
                    return Err(forbidden());
                }
                test.id = validated.environment_id.to_string();
                self.check_context(&test.id, &test.key)?;
                Ok(Some(test))
            }
            _ => Err(Error::new(
                400,
                "test_context_required",
                "Both IAM_TEST_APP_SECRET and X-Testing-Environment-Key are required together.",
                "Supply both current test credentials or omit both for production.",
            )),
        }
    }
    async fn inspect(&self, s: &Session) -> Result<models::TokenIntrospection> {
        let client = self.client(s.test.as_ref())?;
        if let Some(test) = &s.test {
            self.check_context(&test.id, &test.key)?;
            let current = client
                .applications()
                .testing_context()
                .await
                .map_err(iam_error)?;
            if current.environment_id.to_string() != s.context
                || current.application.app_id != self.app_id
                || test.id != s.context
            {
                return Err(forbidden());
            }
        }
        let token = client
            .oauth()
            .introspect(
                &models::TokenIntrospectionRequest {
                    token: s.access.clone(),
                    token_type_hint: None,
                },
                None,
            )
            .await
            .map_err(iam_error)?;
        if !token.active
            || token.public_id.as_deref() != Some(&s.id)
            || token.client_id.as_deref().or(token.audience.as_deref()) != Some(&self.app_id)
            || token.client_id.as_deref().is_some_and(|a| a != self.app_id)
            || token.audience.as_deref().is_some_and(|a| a != self.app_id)
        {
            return Err(expired());
        }
        let kind = serde_json::to_value(&token.actor_type).map_err(storage)?;
        if kind.as_str() != Some(&s.kind) {
            return Err(expired());
        }
        for org in token
            .authorization
            .iter()
            .chain(token.authorizations.iter().flatten())
        {
            if org.audience != self.app_id
                || org.public_id.as_deref() != Some(&s.id)
                || org
                    .testing_environment_id
                    .map(|id| id.to_string())
                    .as_deref()
                    != s.test.as_ref().map(|t| t.id.as_str())
            {
                return Err(forbidden());
            }
        }
        Ok(token)
    }
    async fn live(&self, id: &str) -> Result<(Session, models::TokenIntrospection)> {
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        let mut session = self.session(id)?;
        if session.expires <= now() + 10 || session.refresh_key.is_some() {
            if session.refresh_key.is_none() {
                session.refresh_key = Some(secret());
                self.save(id, &session)?;
            }
            let refreshed = self
                .client(session.test.as_ref())?
                .oauth()
                .refresh(
                    &self.app_id,
                    &session.refresh,
                    &mutation(session.refresh_key.as_ref().unwrap())?,
                )
                .await
                .map_err(iam_error)?;
            session.access = refreshed.access_token;
            session.refresh = refreshed.refresh_token;
            session.expires = now() + refreshed.expires_in;
            session.refresh_key = None;
            self.save(id, &session)?;
        }
        let inspected = self.inspect(&session).await?;
        Ok((session, inspected))
    }
    pub async fn authenticate(&self, token: &str, headers: &HeaderMap) -> Result<Principal> {
        if !token.starts_with("ting_") || token.len() != 69 {
            return Err(expired());
        }
        let id = hash(token.as_bytes());
        let (session, _) = self.live(&id).await?;
        if let Some(test) = self.test_headers(headers).await? {
            if session
                .test
                .as_ref()
                .is_none_or(|s| s.id != test.id || s.secret != test.secret || s.key != test.key)
            {
                return Err(Error::new(
                    403,
                    "test_context_mismatch",
                    "Test headers do not match this session.",
                    "Use the session's original current testing credentials.",
                ));
            }
        }
        Ok(Principal {
            context: session.context,
            id: session.id,
            kind: session.kind,
            session: id,
        })
    }
    pub async fn login(&self, slt: &str, key: &str, headers: &HeaderMap) -> Result<(u16, Value)> {
        mutation(key)?;
        if slt.is_empty() || slt.len() > 8192 {
            return Err(Error::invalid(
                "slt must be a nonempty short-lived IAM token.",
            ));
        }
        let test = self.test_headers(headers).await?;
        let context = test
            .as_ref()
            .map(|t| t.id.clone())
            .unwrap_or("production".into());
        let operation = hash(format!("{context}:{key}").as_bytes());
        let slt_hash = hash(slt.as_bytes());
        let lock = self.lock(&operation);
        let _guard = lock.lock().await;
        let prior: Option<(String, i64, Option<Vec<u8>>, Option<Vec<u8>>)> = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT slt_hash,created,payload,response FROM logins WHERE id=?",
                [&operation],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(storage)?;
        let mut restored = None;
        let mut exchanged_at = now();
        if let Some((original, created, payload, response)) = prior {
            exchanged_at = created;
            if original != slt_hash {
                return Err(Error::new(
                    409,
                    "idempotency_conflict",
                    "This login key was used for a different short-lived token.",
                    "Retry the original token or obtain a fresh login attempt.",
                ));
            }
            if created + 120 < now() {
                return Err(expired());
            }
            if let Some(response) = response {
                return Ok((200, self.open(&operation, &response)?));
            }
            restored = payload;
        } else {
            self.db
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO logins(id,slt_hash,created) VALUES(?,?,?)",
                    params![operation, slt_hash, now()],
                )
                .map_err(storage)?;
        }
        let tokens: models::OAuthTokenResponse = if let Some(bytes) = restored {
            self.open(&operation, &bytes)?
        } else {
            let tokens = self
                .client(test.as_ref())?
                .oauth()
                .login(&self.app_id, slt, &mutation(key)?)
                .await
                .map_err(iam_error)?;
            let encrypted = self.seal(&operation, &tokens)?;
            self.db
                .lock()
                .unwrap()
                .execute(
                    "UPDATE logins SET payload=? WHERE id=?",
                    params![encrypted, operation],
                )
                .map_err(storage)?;
            tokens
        };
        let actor = tokens.actor.as_ref().ok_or_else(unavailable)?;
        let kind = serde_json::to_value(&actor.type_field)
            .map_err(storage)?
            .as_str()
            .filter(|k| matches!(*k, "carbon" | "silicon"))
            .ok_or_else(unavailable)?
            .to_owned();
        let session = Session {
            context,
            id: actor.public_id.clone(),
            kind,
            access: tokens.access_token,
            refresh: tokens.refresh_token,
            // A recovered exchange must not extend the upstream token's lifetime.
            expires: exchanged_at + tokens.expires_in,
            test,
            refresh_key: None,
            revoke_key: secret(),
        };
        self.inspect(&session).await?;
        let token = format!("ting_{}", secret());
        let id = hash(token.as_bytes());
        let response =
            json!({"authenticated":true,"id":session.id,"kind":session.kind,"session_token":token});
        let payload = self.seal(&id, &session)?;
        let replay = self.seal(&operation, &response)?;
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage)?;
        tx.execute(
            "INSERT INTO sessions(id,payload) VALUES(?,?)",
            params![id, payload],
        )
        .map_err(storage)?;
        tx.execute(
            "UPDATE logins SET response=?,payload=NULL WHERE id=?",
            params![replay, operation],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok((201, response))
    }
    pub async fn logout(&self, p: &Principal) -> Result<Value> {
        let lock = self.lock(&p.session);
        let _guard = lock.lock().await;
        let session = self.session(&p.session)?;
        self.db
            .lock()
            .unwrap()
            .execute(
                "UPDATE sessions SET revoked=1,revoke_pending=1 WHERE id=?",
                [&p.session],
            )
            .map_err(storage)?;
        self.revoke(&p.session, &session).await?;
        Ok(json!({"authenticated":false}))
    }
    async fn revoke(&self, id: &str, s: &Session) -> Result<()> {
        self.client(s.test.as_ref())?
            .oauth()
            .revoke(
                &models::OAuthRevocationRequest {
                    token: s.refresh.clone(),
                    token_type_hint: Some(
                        models::OAuthRevocationRequestTokenTypeHint::RefreshToken,
                    ),
                },
                &mutation(&s.revoke_key)?,
            )
            .await
            .map_err(iam_error)?;
        self.db
            .lock()
            .unwrap()
            .execute("UPDATE sessions SET revoke_pending=0 WHERE id=?", [id])
            .map_err(storage)?;
        Ok(())
    }
    /// Called by the server's maintenance task; logout is already locally final.
    pub async fn retry_revocations(&self) {
        let pending: Vec<(String, Vec<u8>)> = {
            let db = self.db.lock().unwrap();
            let Ok(mut q) =
                db.prepare("SELECT id,payload FROM sessions WHERE revoke_pending=1 LIMIT 100")
            else {
                return;
            };
            let Ok(rows) = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?))) else {
                return;
            };
            rows.filter_map(std::result::Result::ok).collect()
        };
        for (id, bytes) in pending {
            if let Ok(s) = self.open::<Session>(&id, &bytes) {
                let _ = self.revoke(&id, &s).await;
            }
        }
        let _ = self.db.lock().unwrap().execute(
            "UPDATE logins SET response=NULL,payload=NULL WHERE created<?",
            [now() - 120],
        );
    }
    async fn authority(
        &self,
        p: &Principal,
        org: &str,
    ) -> Result<(Session, models::ApplicationAuthorization)> {
        let (s, t) = self.live(&p.session).await?;
        let org = t
            .authorization
            .into_iter()
            .chain(t.authorizations.unwrap_or_default())
            .find(|a| a.org_id == org || a.organization_id.to_string() == org)
            .ok_or_else(forbidden)?;
        Ok((s, org))
    }
    pub async fn orgs(&self, p: &Principal) -> Result<Value> {
        let (s, t) = self.live(&p.session).await?;
        let client = self
            .client(s.test.as_ref())?
            .with_credential(Credential::bearer(s.access));
        let mut items = Vec::new();
        for org in t
            .authorization
            .into_iter()
            .chain(t.authorizations.unwrap_or_default())
        {
            let details = client
                .application_reads()
                .organization(&org.org_id)
                .await
                .map_err(iam_error)?;
            items.push(json!({"id":org.organization_id,"name":details["name"].as_str().unwrap_or(&org.org_id),"handle":org.org_id}));
        }
        Ok(json!({"items":items}))
    }
    pub async fn org(&self, p: &Principal, org: &str) -> Result<String> {
        Ok(self.authority(p, org).await?.1.organization_id.to_string())
    }
    pub async fn apps(&self, p: &Principal, org: &str) -> Result<Value> {
        let (s, a) = self.authority(p, org).await?;
        let client = self.client(s.test.as_ref())?;
        let catalog = client
            .obo()
            .endpoints("tos>honeycomb")
            .await
            .map_err(iam_error)?;
        let mut items = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let mut body = json!({"org_id":a.org_id,"limit":100});
            if let Some(after) = &after {
                body["after"] = json!(after);
            }
            let raw = serde_json::to_vec(&body).map_err(storage)?;
            let proof = client
                .obo()
                .exchange_signed(
                    &models::OboExchangeRequest {
                        org_id: Some(a.org_id.clone()),
                        subject_token: s.access.clone(),
                        audience: "tos>honeycomb".into(),
                        endpoint_id: "honeycomb.apps.list".into(),
                        metadata: json!({}),
                        request: models::OboExchangeRequestBinding {
                            method: "POST".into(),
                            body_sha256: hash(&raw),
                        },
                    },
                    &catalog,
                    &Mutation::new(),
                )
                .await
                .map_err(iam_error)?;
            let mut request = self
                .http
                .post(format!("{}/api/v1/obo/apps/list", self.honeycomb))
                .header("Content-Type", "application/json")
                .header("X-IAM-OBO-Access-Proof", proof.access_proof)
                .body(raw);
            if let Some(test) = proof.testing_context {
                request = request
                    .header("X-Testing-Environment-Key", test.iam_test_key)
                    .header("IAM_TEST_APP_SECRET", test.app_secret);
            }
            let response = request.send().await.map_err(|_| unavailable())?;
            if matches!(response.status().as_u16(), 401 | 403) {
                return Err(forbidden());
            }
            if !response.status().is_success() {
                return Err(unavailable());
            }
            let body: Value = response.json().await.map_err(|_| unavailable())?;
            let page = body["items"].as_array().ok_or_else(unavailable)?;
            for app in page {
                let app_id = app["app_id"].as_str().ok_or_else(unavailable)?;
                if app["org_id"].as_str() != Some(&a.org_id) {
                    return Err(unavailable());
                }
                items.push(json!({"app_id":app_id,"name":app["name"],"can_manage_tings":matches!(a.org_role.as_deref(),Some("owner"|"admin"))}));
            }
            match body["next_cursor"].as_str() {
                Some(next) if Some(next) != after.as_deref() => after = Some(next.into()),
                Some(_) => return Err(unavailable()),
                None => break,
            }
        }
        Ok(json!({"items":items}))
    }
    pub async fn permission(
        &self,
        p: &Principal,
        org: &str,
        app: &str,
        manage: bool,
    ) -> Result<()> {
        let apps = self.apps(p, org).await?;
        if apps["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["app_id"] == app && (!manage || a["can_manage_tings"] == true))
        {
            Ok(())
        } else {
            Err(forbidden())
        }
    }
    pub async fn proof(&self, headers: &HeaderMap, path: &str, raw: &[u8]) -> Result<Proof> {
        let proof = bearer(headers)?;
        let endpoint = match path {
            "/v1/tings" => "tings.send",
            "/v1/subscriptions" => "subscriptions.register",
            "/v1/subscriptions/query" => "subscriptions.query",
            "/v1/subscriptions/revoke" => "subscriptions.revoke",
            "/v1/sent/query" => "sent.query",
            _ => {
                return Err(Error::invalid(
                    "No IAM endpoint is registered for this path.",
                ));
            }
        };
        let body: Value = serde_json::from_slice(raw)
            .map_err(|_| Error::invalid("The signed body must be JSON."))?;
        let org = body["org_id"]
            .as_str()
            .ok_or_else(|| Error::invalid("org_id is required."))?;
        let test = self.test_headers(headers).await?;
        let verified=self.client(test.as_ref())?.obo().verify(&models::OboVerifyRequest {access_proof:proof.into(),request:models::OboVerifyRequestBinding {method:"POST".into(),path:path.into(),body_sha256:hash(raw)}}).await.map_err(|e|match e {
            silicon_iam_client::Error::Api(a) if matches!(a.status,400|401|403|404|409|410)=>{
                let code=if a.code.contains("consum") {"proof_consumed"} else if a.code.contains("expir") {"proof_expired"} else {"invalid_proof"};
                Error::new(401,code,"IAM rejected this request-bound proof.","Obtain a fresh proof for the exact body, endpoint, audience and organization.")
            }
            _=>Error::new(503,"proof_verification_uncertain","IAM proof verification could not be confirmed; nothing was executed.","Retry the same Ting operation using a fresh proof."),
        })?;
        let a = &verified.authorization;
        if verified.valid != true
            || verified.audience != self.app_id
            || a.audience != self.app_id
            || verified.endpoint.path != path
            || verified.endpoint.endpoint_id != endpoint
            || (verified.org_id != org && a.organization_id.to_string() != org)
            || a.org_id != verified.org_id
            || a.public_id.as_deref() != Some(&verified.actor.public_id)
            || verified.actor.public_id.is_empty()
            || a.testing_environment_id.map(|v| v.to_string()).as_deref()
                != test.as_ref().map(|v| v.id.as_str())
            || verified.expires_at.unix_timestamp() <= now()
            || verified.expires_at.unix_timestamp() - verified.consumed_at.unix_timestamp() > 60
            || verified.consumed_at > verified.expires_at
            || verified.issuer_app_id.is_empty()
            || !verified.metadata.as_object().is_some_and(|m| m.is_empty())
            || !a
                .scopes
                .contains(&format!("obo:{}:{}", self.app_id, endpoint))
        {
            return Err(Error::new(
                401,
                "invalid_proof",
                "The verified proof does not authorize this request.",
                "Obtain a new proof matching the exact request and current consent.",
            ));
        }
        if body
            .get("app_id")
            .is_some_and(|id| id != &json!(verified.issuer_app_id))
            || body
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| !kind.starts_with(&format!("{}.", verified.issuer_app_id)))
        {
            return Err(forbidden());
        }
        Ok(Proof {
            context: test.map(|t| t.id).unwrap_or("production".into()),
            org_id: a.organization_id.to_string(),
            app_id: verified.issuer_app_id,
            actor_id: verified.actor.public_id,
        })
    }
    pub async fn report(&self, p: &Principal, body: Value, version: Option<&str>) -> Result<Value> {
        validate_report(&body)?;
        if self.station_key.is_empty() || self.station_table.is_empty() {
            return Err(report_error());
        }
        let id = format!("bug_{}", uuid::Uuid::new_v4().simple());
        let batch = uuid::Uuid::new_v4().to_string();
        let mut record = body;
        record["event"] = json!("bug_report");
        record["report_id"] = json!(id);
        record["reporter_id"] = json!(p.id);
        record["context"] = json!(p.context);
        record["source"] = json!("ting.backend");
        if let Some(version) = version {
            record["app_version"] = json!(version);
        }
        let pr = record.get("pr_ref").cloned().unwrap_or(Value::Null);
        let raw=json!({"batch_id":batch,"records":[{"key":self.station_key,"metadata":{"record_id":uuid::Uuid::new_v4(),"table_id":self.station_table,"event_ts_ms":chrono::Utc::now().timestamp_millis()},"record":record}]}).to_string();
        let url = format!(
            "{}/api/ws/ingest",
            self.station
                .replacen("https://", "wss://", 1)
                .replacen("http://", "ws://", 1)
        );
        tokio::time::timeout(Duration::from_secs(20), async {
            let (mut socket, _) = tokio_tungstenite::connect_async(url)
                .await
                .map_err(|_| report_error())?;
            socket
                .send(tokio_tungstenite::tungstenite::Message::Text(raw.into()))
                .await
                .map_err(|_| report_error())?;
            while let Some(message) = socket.next().await {
                match message.map_err(|_| report_error())? {
                    tokio_tungstenite::tungstenite::Message::Text(text) => {
                        let ack: Value = serde_json::from_str(&text).map_err(|_| report_error())?;
                        if ack["batch_id"] != batch
                            || ack["status"] != "ok"
                            || ack
                                .get("rejected")
                                .and_then(Value::as_array)
                                .is_some_and(|r| !r.is_empty())
                            || ack.get("code").is_some_and(|v| !v.is_null())
                        {
                            return Err(report_error());
                        }
                        let _ = socket.close(None).await;
                        return Ok(json!({"id":id,"submitted":true,"pr_ref":pr}));
                    }
                    tokio_tungstenite::tungstenite::Message::Ping(data) => socket
                        .send(tokio_tungstenite::tungstenite::Message::Pong(data))
                        .await
                        .map_err(|_| report_error())?,
                    tokio_tungstenite::tungstenite::Message::Close(_) => break,
                    _ => {}
                }
            }
            Err(report_error())
        })
        .await
        .map_err(|_| report_error())?
    }
}

fn report_error() -> Error {
    Error::new(
        503,
        "report_storage_unconfirmed",
        "Space Station has not confirmed durable storage of this report.",
        "Do not automatically retry: the report may already have been stored.",
    )
}
fn validate_report(v: &Value) -> Result<()> {
    use base64::Engine;
    let object = v
        .as_object()
        .ok_or_else(|| Error::invalid("A bug report must be a JSON object."))?;
    if object
        .keys()
        .any(|k| !matches!(k.as_str(), "title" | "body" | "pr_ref" | "attachments"))
    {
        return Err(Error::invalid("Unknown bug report field."));
    }
    if serde_json::to_vec(v).map_err(storage)?.len() > 192 * 1024 {
        return Err(Error::new(
            413,
            "payload_too_large",
            "Bug report exceeds 192 KiB.",
            "Reduce the report or attachments; content is never truncated.",
        ));
    }
    if !v["title"]
        .as_str()
        .is_some_and(|s| !s.is_empty() && s.len() <= 200)
        || !v["body"].as_str().is_some_and(|s| !s.is_empty())
    {
        return Err(Error::invalid(
            "title requires 1–200 UTF-8 bytes and body requires nonempty text.",
        ));
    }
    if let Some(pr) = v.get("pr_ref").filter(|v| !v.is_null()) {
        let valid = pr
            .as_str()
            .filter(|s| s.len() <= 2048)
            .and_then(|s| url::Url::parse(s).ok())
            .is_some_and(|u| {
                u.scheme() == "https"
                    && u.host_str().is_some()
                    && u.username().is_empty()
                    && u.password().is_none()
            });
        if !valid {
            return Err(Error::invalid(
                "pr_ref must be an absolute HTTPS pull-request URL.",
            ));
        }
    }
    if let Some(attachments) = v.get("attachments") {
        let attachments = attachments
            .as_array()
            .filter(|a| a.len() <= 8)
            .ok_or_else(|| Error::invalid("attachments must contain at most eight files."))?;
        for a in attachments {
            let fields = a
                .as_object()
                .ok_or_else(|| Error::invalid("Each attachment must be an object."))?;
            if fields.len() != 3
                || fields
                    .keys()
                    .any(|k| !matches!(k.as_str(), "name" | "encoding" | "content"))
            {
                return Err(Error::invalid(
                    "Attachments require name, encoding and content only.",
                ));
            }
            if !a["name"].as_str().is_some_and(|n| {
                !n.is_empty()
                    && !matches!(n, "." | "..")
                    && !n.contains(['/', '\\'])
                    && !n.chars().any(char::is_control)
            }) {
                return Err(Error::invalid("Attachment name must be a basename."));
            }
            let content = a["content"]
                .as_str()
                .ok_or_else(|| Error::invalid("Attachment content must be a string."))?;
            match a["encoding"].as_str() {
                Some("utf-8") => {}
                Some("base64") => {
                    base64::engine::general_purpose::STANDARD
                        .decode(content)
                        .map_err(|_| Error::invalid("Attachment base64 is invalid."))?;
                }
                _ => {
                    return Err(Error::invalid(
                        "Attachment encoding must be utf-8 or base64.",
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_sessions_bind_rows_and_lifecycle_revocation_is_durable() {
        let database =
            std::env::temp_dir().join(format!("ting-auth-test-{}", uuid::Uuid::new_v4()));
        let config = crate::Config {
            database_path: database.to_string_lossy().into_owned(),
            encryption_key: "ab".repeat(32),
            iam_url: "http://127.0.0.1:1".into(),
            iam_app_id: "tos>ting".into(),
            iam_app_secret: "test-only-secret".into(),
            honeycomb_url: "http://127.0.0.1:1".into(),
            spacestation_url: "http://127.0.0.1:1".into(),
            spacestation_key: String::new(),
            spacestation_table: String::new(),
            frontend_origin: "http://127.0.0.1:1".into(),
            public_origin: "http://127.0.0.1:1".into(),
            repository_url: String::new(),
            docs_url: String::new(),
            rust_package: String::new(),
        };
        let auth = Auth::new(&config).unwrap();
        let context = uuid::Uuid::new_v4().to_string();
        let session = Session {
            context: context.clone(),
            id: "test-actor".into(),
            kind: "carbon".into(),
            access: "sensitive-access-token".into(),
            refresh: "sensitive-refresh-token".into(),
            expires: now() + 3600,
            test: None,
            refresh_key: None,
            revoke_key: secret(),
        };
        let id = hash(b"opaque-test-session");
        let encrypted = auth.seal(&id, &session).unwrap();
        assert!(
            !encrypted
                .windows(session.access.len())
                .any(|bytes| bytes == session.access.as_bytes())
        );
        assert!(auth.open::<Session>("different-row", &encrypted).is_err());
        let mut altered = encrypted.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(auth.open::<Session>(&id, &altered).is_err());
        auth.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO sessions(id,payload) VALUES(?,?)",
                params![id, encrypted],
            )
            .unwrap();
        assert!(auth.session(&id).is_ok());
        auth.fence_context(&context, "disabled", &hash(b"test-key"), true)
            .unwrap();
        assert!(auth.session(&id).is_err());
        drop(auth);
        let reopened = Auth::new(&config).unwrap();
        assert!(reopened.session(&id).is_err());
        let pending: i64 = reopened
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT revoke_pending FROM sessions WHERE id=?",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 1);
        drop(reopened);
        for suffix in [".auth", ".auth-wal", ".auth-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", database.display()));
        }
    }
    #[test]
    fn reports_reject_lossy_or_invalid_attachments() {
        assert!(validate_report(&json!({"title":"Bug","body":"Exact content","attachments":[{"name":"log.txt","encoding":"base64","content":"YWJj"}]})).is_ok());
        assert!(validate_report(&json!({"title":"Bug","body":"Exact content","attachments":[{"name":"../log","encoding":"base64","content":"YWJj"}]})).is_err());
        assert!(validate_report(&json!({"title":"Bug","body":"Exact content","attachments":[{"name":"log","encoding":"base64","content":"YWJj\n"}]})).is_err());
        assert!(validate_report(&json!({"title":"Bug","body":"a".repeat(192*1024)})).is_err());
    }
}
