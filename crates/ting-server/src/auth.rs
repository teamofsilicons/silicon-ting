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
    pub(crate) test: Option<TestContext>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct TestContext {
    id: String,
    secret: String,
    key: String,
    #[serde(default)]
    generation: Option<i64>,
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
        // IAM and telemetry enable different rustls providers; select one before
        // either client starts a background connection.
        let _ = rustls::crypto::ring::default_provider().install_default();
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
        // Read the authoritative lifecycle generation without duplicating it in credentials.
        db.execute("ATTACH DATABASE ? AS delivery", [&config.database_path])?;
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
                .user_agent(concat!("silicon-ting-server/", env!("CARGO_PKG_VERSION")))
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
    pub async fn authenticate_session_org(
        &self,
        id: &str,
        org: &str,
    ) -> Result<(Principal, String)> {
        let (s, token) = self.live(id).await?;
        let org = Self::org_authorization(token, org)?
            .organization_id
            .to_string();
        Ok((
            Principal {
                context: s.context,
                id: s.id,
                kind: s.kind,
                session: id.into(),
            },
            org,
        ))
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
    fn check_context(&self, context: &str, key: &str) -> Result<i64> {
        let db = self.db.lock().unwrap();
        let known: Option<(String, String)> = db
            .query_row(
                "SELECT state,key_hash FROM testing_contexts WHERE id=?",
                [context],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        let (state, expected) = known.ok_or_else(|| {
            Error::unavailable("Import this testing environment through Honeycomb before use.")
        })?;
        if state == "pending" {
            return Err(Error::unavailable(
                "This testing environment has an unfinished lifecycle operation.",
            ));
        }
        if state != "active" || expected != hash(key.as_bytes()) {
            return Err(forbidden());
        }
        db
            .query_row(
                "SELECT generation FROM delivery.lifecycle_environments WHERE id=? AND state='active' AND key_hash=? AND generation>0",
                params![context, expected],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?
            .ok_or_else(|| Error::unavailable("This testing environment has no active lifecycle generation."))
    }
    fn session_environment(&self, session: &Session) -> Result<Value> {
        match &session.test {
            None if session.context == "production" => Ok(json!({"kind":"production"})),
            Some(test) if test.id == session.context => {
                let generation = self.check_context(&test.id, &test.key)?;
                if test.generation != Some(generation) {
                    return Err(expired());
                }
                Ok(json!({"kind":"testing","id":test.id,"generation":generation}))
            }
            _ => Err(expired()),
        }
    }
    fn current_session(&self, principal: &Principal) -> Result<Session> {
        let session = self.session(&principal.session)?;
        if session.id != principal.id
            || session.kind != principal.kind
            || session.context != principal.context
            || session.expires <= now()
        {
            return Err(expired());
        }
        self.session_environment(&session)?;
        Ok(session)
    }
    pub fn check_session(&self, principal: &Principal) -> Result<()> {
        self.current_session(principal).map(|_| ())
    }
    pub fn check_proof(&self, proof: &Proof) -> Result<()> {
        match &proof.test {
            None if proof.context == "production" => Ok(()),
            Some(test)
                if test.id == proof.context
                    && test.generation == Some(self.check_context(&test.id, &test.key)?) =>
            {
                Ok(())
            }
            _ => Err(forbidden()),
        }
    }
    pub fn me(&self, principal: &Principal) -> Result<Value> {
        let session = self.current_session(principal)?;
        Ok(
            json!({"id":session.id,"kind":session.kind,"authenticated":true,"environment":self.session_environment(&session)?}),
        )
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
                    generation: None,
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
                test.generation = Some(self.check_context(&test.id, &test.key)?);
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
        self.session_environment(s)?;
        let client = self.client(s.test.as_ref())?;
        if let Some(test) = &s.test {
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
        // An IAM request can overlap a clean or rotation; do not attest the old generation.
        self.session_environment(s)?;
        Ok(token)
    }
    async fn live(&self, id: &str) -> Result<(Session, models::TokenIntrospection)> {
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        let mut session = self.session(id)?;
        self.session_environment(&session)?;
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
        self.session(id)?;
        Ok((session, inspected))
    }
    pub async fn authenticate(&self, token: &str, headers: &HeaderMap) -> Result<Principal> {
        if !token.starts_with("ting_") || token.len() != 69 {
            return Err(expired());
        }
        let id = hash(token.as_bytes());
        let (session, _) = self.live(&id).await?;
        if let Some(test) = self.test_headers(headers).await? {
            if session.test.as_ref().is_none_or(|s| {
                s.id != test.id
                    || s.secret != test.secret
                    || s.key != test.key
                    || s.generation != test.generation
            }) {
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
        let binding = match &test {
            Some(t) => format!("{context}:{}:{key}", t.generation.ok_or_else(expired)?),
            None => format!("{context}:{key}"),
        };
        let operation = hash(binding.as_bytes());
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
        if s.id != p.id || s.context != p.context || s.kind != p.kind {
            return Err(expired());
        }
        Ok((s, Self::org_authorization(t, org)?))
    }
    fn org_authorization(
        token: models::TokenIntrospection,
        org: &str,
    ) -> Result<models::ApplicationAuthorization> {
        token
            .authorization
            .into_iter()
            .chain(token.authorizations.unwrap_or_default())
            .find(|a| a.org_id == org || a.organization_id.to_string() == org)
            .ok_or_else(forbidden)
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
            context: test
                .as_ref()
                .map(|t| t.id.clone())
                .unwrap_or("production".into()),
            org_id: a.organization_id.to_string(),
            app_id: verified.issuer_app_id,
            actor_id: verified.actor.public_id,
            test,
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
            use tokio_tungstenite::tungstenite::client::IntoClientRequest;
            let mut request = url.into_client_request().map_err(|_| report_error())?;
            request.headers_mut().insert(
                "User-Agent",
                concat!("silicon-ting-server/", env!("CARGO_PKG_VERSION"))
                    .parse()
                    .map_err(|_| report_error())?,
            );
            let (mut socket, _) = tokio_tungstenite::connect_async(request)
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
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};

    pub(crate) struct MockIam {
        pub reply: Mutex<Value>,
        pub status: AtomicU16,
        pub calls: Mutex<Vec<String>>,
        pub block_next: AtomicBool,
        pub block_path: Mutex<Option<String>>,
        pub blocked: tokio::sync::Notify,
        pub release: tokio::sync::Notify,
        context: String,
    }
    pub(crate) struct Fixture {
        pub app: crate::Shared,
        pub principal: Principal,
        pub proof: Proof,
        pub token: String,
        pub iam: Arc<MockIam>,
        task: tokio::task::JoinHandle<()>,
        _directory: tempfile::TempDir,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl Fixture {
        pub fn hook(&self, receiver: &str) -> String {
            self.app
                .store
                .create_hook(
                    &self.principal,
                    &self.proof.org_id,
                    receiver,
                    &uuid::Uuid::new_v4().to_string(),
                    &json!({"receiver_id":receiver}),
                )
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .into()
        }
        pub fn send(&self, key: &str) -> String {
            self.app.store.send(&self.proof, &json!({"org_id":self.proof.org_id,"type":"tos>example.msg.received","data":{},"for":self.principal.id,"key":key})).unwrap().1["id"].as_str().unwrap().into()
        }
        pub fn receipt(&self, hook: &str, id: &str) -> (i64, i64) {
            Connection::open(&self.app.config.database_path)
                .unwrap()
                .query_row(
                    "SELECT delivery,read FROM deliveries WHERE hook=? AND message=?",
                    params![hook, id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap()
        }
        pub fn take_calls(&self) -> Vec<String> {
            std::mem::take(&mut *self.iam.calls.lock().unwrap())
        }
    }
    pub(crate) async fn fixture(testing: bool) -> Fixture {
        use axum::{
            Json, Router,
            extract::{Request, State},
            response::IntoResponse,
        };
        let directory = tempfile::tempdir().unwrap();
        let context = uuid::Uuid::new_v4().to_string();
        let environment_key = "k".repeat(32);
        let org = uuid::Uuid::new_v4().to_string();
        let iam = Arc::new(MockIam {
            reply: Mutex::new(
                json!({"active":true,"public_id":"si_fixture","actor_type":"silicon","client_id":"tos>ting","authorization":{
                "organization_id":org,"org_id":"tos","membership_id":"fixture-member","membership_version":1,"authorization_epoch":1,
                "audience":"tos>ting","public_id":"si_fixture","actor_type":"silicon","scopes":[],
                "testing_environment_id":if testing {Some(&context)} else {None},"org_role":null,"tags":null}}),
            ),
            status: AtomicU16::new(200),
            calls: Mutex::new(vec![]),
            block_next: AtomicBool::new(false),
            block_path: Mutex::new(None),
            blocked: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            context: context.clone(),
        });
        async fn respond(
            State(iam): State<Arc<MockIam>>,
            request: Request,
        ) -> axum::response::Response {
            let path = request.uri().path().to_owned();
            iam.calls.lock().unwrap().push(path.clone());
            if iam.block_next.swap(false, Ordering::SeqCst)
                || iam
                    .block_path
                    .lock()
                    .unwrap()
                    .take_if(|wanted| wanted == &path)
                    .is_some()
            {
                iam.blocked.notify_one();
                iam.release.notified().await;
            }
            let body = match path.as_str() {
                "/api/v1/oauth/introspect" => iam.reply.lock().unwrap().clone(),
                "/api/v1/app-auth/tokens" => {
                    json!({"access_token":"fixture-access", "refresh_token":"fixture-refresh", "expires_in":3600,
                    "token_type":"Bearer", "scope":"", "actor":{"type":"silicon", "public_id":"si_fixture"}})
                }
                "/api/v1/obo-access/verify" => {
                    let raw = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                        .await
                        .unwrap();
                    let request: Value = serde_json::from_slice(&raw).unwrap();
                    let target = request["request"]["path"].as_str().unwrap();
                    let endpoint = match target {
                        "/v1/tings" => "tings.send",
                        "/v1/subscriptions" => "subscriptions.register",
                        "/v1/subscriptions/query" => "subscriptions.query",
                        "/v1/subscriptions/revoke" => "subscriptions.revoke",
                        "/v1/sent/query" => "sent.query",
                        _ => panic!("unexpected proof path: {target}"),
                    };
                    let mut authorization = iam.reply.lock().unwrap()["authorization"].clone();
                    authorization["scopes"] = json!([format!("obo:tos>ting:{endpoint}")]);
                    json!({"valid":true,"proof_id":uuid::Uuid::new_v4(),"issuer_app_id":"tos>example","audience":"tos>ting",
                        "actor":{"type":"silicon","public_id":"si_fixture"},"authorization":authorization,"org_id":"tos",
                        "endpoint":{"endpoint_id":endpoint,"path":target},"metadata":{},
                        "expires_at":(chrono::Utc::now()+chrono::Duration::seconds(30)).to_rfc3339(),
                        "consumed_at":chrono::Utc::now().to_rfc3339()})
                }
                "/api/v1/application/testing-context" => {
                    json!({"environment_id":iam.context,"application":{
                    "app_id":"tos>ting","base_url":"https://ting.example","app_scope":{"iam":[],"external":[]},"webhook_scope":[],"testing_idle_days":30}})
                }
                _ => panic!("unexpected IAM route: {path}"),
            };
            (
                axum::http::StatusCode::from_u16(iam.status.load(Ordering::SeqCst)).unwrap(),
                Json(body),
            )
                .into_response()
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let iam_url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new().fallback(respond).with_state(iam.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let config = crate::Config {
            database_path: directory
                .path()
                .join("ting.sqlite")
                .to_string_lossy()
                .into_owned(),
            encryption_key: "ab".repeat(32),
            iam_url,
            iam_app_id: "tos>ting".into(),
            iam_app_secret: "fixture-secret".into(),
            honeycomb_url: "http://127.0.0.1:1".into(),
            spacestation_url: "http://127.0.0.1:1".into(),
            spacestation_key: String::new(),
            spacestation_table: String::new(),
            frontend_origin: "http://127.0.0.1:1".into(),
            public_origin: "http://127.0.0.1:1".into(),
            browser_origins: vec![],
            repository_url: String::new(),
            docs_url: String::new(),
            rust_package: String::new(),
        };
        let auth = Auth::new(&config).unwrap();
        let token = format!("ting_{}", "a".repeat(64));
        let id = hash(token.as_bytes());
        let session = Session {
            context: if testing {
                context.clone()
            } else {
                "production".into()
            },
            id: "si_fixture".into(),
            kind: "silicon".into(),
            access: "fixture-access".into(),
            refresh: "fixture-refresh".into(),
            expires: now() + 3600,
            test: testing.then(|| TestContext {
                id: context.clone(),
                secret: "fixture-secret".into(),
                key: environment_key.clone(),
                generation: Some(1),
            }),
            refresh_key: None,
            revoke_key: secret(),
        };
        auth.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO sessions(id,payload) VALUES(?,?)",
                params![id, auth.seal(&id, &session).unwrap()],
            )
            .unwrap();
        let principal = Principal {
            context: session.context.clone(),
            id: session.id,
            kind: session.kind,
            session: id,
        };
        let proof = Proof {
            context: principal.context.clone(),
            org_id: org,
            app_id: "tos>example".into(),
            actor_id: principal.id.clone(),
            test: session.test,
        };
        let store = crate::store::Store::open(&config.database_path).unwrap();
        if testing {
            auth.fence_context(&context, "active", &hash(environment_key.as_bytes()), false)
                .unwrap();
            Connection::open(&config.database_path)
                .unwrap()
                .execute(
                    "INSERT INTO lifecycle_environments VALUES(?1,1,1,1,?2,'active')",
                    params![context, hash(environment_key.as_bytes())],
                )
                .unwrap();
        }
        store
            .register_type(
                &principal,
                &proof.org_id,
                &proof.app_id,
                &json!({"type":"tos>example.msg.received","description":"Fixture"}),
                false,
            )
            .unwrap();
        store
            .subscribe_app(
                &proof,
                &json!({"org_id":proof.org_id,"app_id":proof.app_id}),
            )
            .unwrap();
        let app = Arc::new(crate::App {
            config,
            auth,
            store,
            hub: crate::ws::Hub::default(),
            changed: tokio::sync::Notify::new(),
            mutations: AsyncMutex::new(()),
        });
        Fixture {
            app,
            principal,
            proof,
            token,
            iam,
            task,
            _directory: directory,
        }
    }
    #[tokio::test]
    async fn me_attests_the_live_session_environment_and_fences_stale_generations() {
        use axum::{
            extract::{Path, RawQuery, State},
            http::Method,
        };
        async fn get_me(f: &Fixture) -> Result<Value> {
            let mut headers = HeaderMap::new();
            headers.insert(
                "cookie",
                format!("ting_session={}", f.token).parse().unwrap(),
            );
            let response = crate::http(
                State(f.app.clone()),
                Path("me".into()),
                RawQuery(None),
                Method::GET,
                headers,
                Ok(axum::body::Bytes::new()),
            )
            .await?;
            assert_eq!(response.status(), 200);
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            Ok(serde_json::from_slice(&bytes).unwrap())
        }

        let production = fixture(false).await;
        assert_eq!(
            get_me(&production).await.unwrap(),
            json!({
                "id":"si_fixture", "kind":"silicon", "authenticated":true,
                "environment":{"kind":"production"}
            })
        );
        let auth = &production.app.auth;
        let mut malformed = auth.session(&production.principal.session).unwrap();
        malformed.context.clear();
        auth.save(&production.principal.session, &malformed)
            .unwrap();
        assert_eq!(get_me(&production).await.unwrap_err().status, 401);

        let mut testing = fixture(true).await;
        let mut headers = HeaderMap::new();
        headers.insert("iam_test_app_secret", "fixture-secret".parse().unwrap());
        headers.insert("x-testing-environment-key", "k".repeat(32).parse().unwrap());
        let (status, login) = testing
            .app
            .auth
            .login("fixture-slt", &uuid::Uuid::new_v4().to_string(), &headers)
            .await
            .unwrap();
        assert_eq!(status, 201);
        testing.token = login["session_token"].as_str().unwrap().into();
        testing.principal = testing
            .app
            .auth
            .authenticate(&testing.token, &HeaderMap::new())
            .await
            .unwrap();
        assert_eq!(
            get_me(&testing).await.unwrap(),
            json!({
                "id":"si_fixture", "kind":"silicon", "authenticated":true,
                "environment":{"kind":"testing", "id":testing.principal.context, "generation":1}
            })
        );
        let auth = &testing.app.auth;
        let original = auth.session(&testing.principal.session).unwrap();
        let mut legacy = original.clone();
        legacy.test.as_mut().unwrap().generation = None;
        auth.save(&testing.principal.session, &legacy).unwrap();
        assert_eq!(get_me(&testing).await.unwrap_err().status, 401);
        auth.save(&testing.principal.session, &original).unwrap();

        // Even without a session revocation, a clean cannot relabel an old cookie.
        Connection::open(&testing.app.config.database_path)
            .unwrap()
            .execute(
                "UPDATE lifecycle_environments SET generation=2 WHERE id=?",
                [&testing.principal.context],
            )
            .unwrap();
        assert_eq!(get_me(&testing).await.unwrap_err().status, 401);
        let mut fresh = original.clone();
        fresh.test.as_mut().unwrap().generation = Some(2);
        auth.save(&testing.principal.session, &fresh).unwrap();
        assert_eq!(
            get_me(&testing).await.unwrap()["environment"]["generation"],
            2
        );

        let key_hash = hash(fresh.test.as_ref().unwrap().key.as_bytes());
        for (state, key, status) in [
            ("pending", key_hash.as_str(), 503),
            ("active", "rotated-key-hash", 403),
            ("retired", key_hash.as_str(), 403),
        ] {
            auth.fence_context(&testing.principal.context, state, key, false)
                .unwrap();
            assert_eq!(get_me(&testing).await.unwrap_err().status, status);
        }
        auth.fence_context(&testing.principal.context, "active", &key_hash, false)
            .unwrap();
        Connection::open(&testing.app.config.database_path)
            .unwrap()
            .execute(
                "DELETE FROM lifecycle_environments WHERE id=?",
                [&testing.principal.context],
            )
            .unwrap();
        assert_eq!(get_me(&testing).await.unwrap_err().status, 503);
    }

    #[tokio::test]
    async fn session_mutation_rechecks_generation_after_waiting_for_gate() {
        use axum::{
            extract::{Path, RawQuery, State},
            http::Method,
        };
        let f = fixture(true).await;
        let gate = f.app.mutations.lock().await;
        let app = f.app.clone();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {}", f.token).parse().unwrap(),
        );
        headers.insert("content-type", "application/json".parse().unwrap());
        let mut pending = tokio::spawn(async move {
            crate::http(
                State(app),
                Path("orgs/tos/preferences".into()),
                RawQuery(None),
                Method::PUT,
                headers,
                Ok(
                    serde_json::to_vec(&json!({"app_id":"tos>example","enabled":false}))
                        .unwrap()
                        .into(),
                ),
            )
            .await
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut pending)
                .await
                .is_err()
        );
        assert_eq!(
            f.take_calls(),
            vec![
                "/api/v1/application/testing-context",
                "/api/v1/oauth/introspect",
                "/api/v1/application/testing-context",
                "/api/v1/oauth/introspect",
            ]
        );
        Connection::open(&f.app.config.database_path)
            .unwrap()
            .execute(
                "UPDATE lifecycle_environments SET generation=2 WHERE id=?",
                [&f.principal.context],
            )
            .unwrap();
        drop(gate);
        assert_eq!(pending.await.unwrap().unwrap_err().status, 401);
        assert!(
            f.app
                .store
                .preferences(&f.principal, &f.proof.org_id, &json!({}))
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn proof_operations_recheck_generation_after_iam_and_before_storage() {
        for path in [
            "/v1/tings",
            "/v1/subscriptions",
            "/v1/subscriptions/query",
            "/v1/sent/query",
        ] {
            let f = fixture(true).await;
            let body = if path == "/v1/tings" {
                json!({"org_id":f.proof.org_id,"type":"tos>example.msg.received","data":{},"for":f.principal.id,"key":"stale-proof"})
            } else {
                json!({"org_id":f.proof.org_id,"app_id":"tos>example"})
            };
            let mut headers = HeaderMap::new();
            headers.insert("authorization", "Bearer fixture-proof".parse().unwrap());
            headers.insert("iam_test_app_secret", "fixture-secret".parse().unwrap());
            headers.insert("x-testing-environment-key", "k".repeat(32).parse().unwrap());
            *f.iam.block_path.lock().unwrap() = Some("/api/v1/obo-access/verify".into());
            let gate = f.app.mutations.lock().await;
            let app = f.app.clone();
            let (h, b) = (headers.clone(), body.clone());
            let pending = tokio::spawn(async move {
                crate::app_call(&app, &h, path, &serde_json::to_vec(&b).unwrap(), &b).await
            });
            tokio::time::timeout(Duration::from_secs(2), f.iam.blocked.notified())
                .await
                .unwrap();
            Connection::open(&f.app.config.database_path)
                .unwrap()
                .execute(
                    "UPDATE lifecycle_environments SET generation=2 WHERE id=?",
                    [&f.principal.context],
                )
                .unwrap();
            f.iam.release.notify_one();
            drop(gate);
            assert_eq!(pending.await.unwrap().unwrap_err().status, 403, "{path}");
            // The same operation freshly verified in the new generation remains usable.
            assert!(
                crate::app_call(
                    &f.app,
                    &headers,
                    path,
                    &serde_json::to_vec(&body).unwrap(),
                    &body
                )
                .await
                .is_ok(),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn session_revalidation_rejects_a_clean_during_iam_verification() {
        let f = fixture(true).await;
        f.iam.block_next.store(true, Ordering::SeqCst);
        let app = f.app.clone();
        let token = f.token.clone();
        let pending =
            tokio::spawn(async move { app.auth.authenticate(&token, &HeaderMap::new()).await });
        tokio::time::timeout(Duration::from_secs(2), f.iam.blocked.notified())
            .await
            .unwrap();
        Connection::open(&f.app.config.database_path)
            .unwrap()
            .execute(
                "UPDATE lifecycle_environments SET generation=2 WHERE id=?",
                [&f.principal.context],
            )
            .unwrap();
        f.iam.release.notify_one();
        assert_eq!(pending.await.unwrap().err().unwrap().status, 401);
    }

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
            browser_origins: vec![],
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
        for suffix in ["", ".auth", ".auth-wal", ".auth-shm"] {
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
