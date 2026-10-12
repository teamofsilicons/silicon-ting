//! Silicon Accounts owns identity and session lifetime; upstream tokens stay encrypted here.
use crate::{
    error::{Error, Result},
    validation as v,
};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axum::http::HeaderMap;
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Clone)]
pub struct Principal {
    pub context: String,
    /// Immutable Accounts UUID, never a mutable c:/si: handle.
    pub id: String,
    pub kind: String,
    pub session: String,
}
pub struct Proof {
    pub context: String,
    pub app_id: String,
    pub actor_id: String,
    pub expires_at: i64,
}
pub struct AppAuthority {
    pub context: String,
    pub app_id: String,
    pub expires_at: i64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Session {
    uuid: String,
    id: String,
    kind: String,
    refresh: String,
    expires: i64,
}
pub struct Auth {
    db: Mutex<Connection>,
    cipher: Aes256Gcm,
    accounts: String,
    app_id: String,
    app_secret: String,
    apps_url: String,
    http: reqwest::Client,
    locks: Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
}
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn hash(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}
pub fn secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn storage(_: impl std::fmt::Display) -> Error {
    Error::unavailable("Credential storage is unavailable; retry the same operation.")
}
fn unavailable() -> Error {
    Error::unavailable(
        "Silicon Accounts could not confirm authority. Your saved session is unchanged; retry shortly.",
    )
}
fn expired() -> Error {
    Error::new(
        401,
        "session_expired",
        "This session has expired or was revoked.",
        "Sign in through Silicon Accounts again.",
    )
}
fn forbidden() -> Error {
    Error::new(
        403,
        "permission_denied",
        "This account or proof cannot perform this operation.",
        "Use an app author account or a proof with the required Ting scope.",
    )
}
fn timestamp(value: &Value) -> Result<i64> {
    value
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|s| s.timestamp())
        .ok_or_else(unavailable)
}
fn iso(timestamp: i64) -> String {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}
fn identity(account: &Value) -> Result<(&str, &str, &str)> {
    let uuid = account["uuid"]
        .as_str()
        .filter(|s| uuid::Uuid::parse_str(s).is_ok_and(|u| u.to_string() == *s))
        .ok_or_else(unavailable)?;
    let id = account["id"].as_str().ok_or_else(unavailable)?;
    let kind = account["kind"]
        .as_str()
        .filter(|k| v::actor_kind(id) == Some(*k))
        .ok_or_else(unavailable)?;
    Ok((uuid, id, kind))
}
impl Auth {
    pub fn new(config: &crate::Config) -> anyhow::Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let key = hex::decode(&config.encryption_key)?;
        anyhow::ensure!(
            key.len() == 32,
            "TING_ENCRYPTION_KEY must contain 32 random bytes in hex"
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
          CREATE TABLE IF NOT EXISTS account_sessions(id TEXT PRIMARY KEY,payload BLOB NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,revoke_pending INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS account_logins(id TEXT PRIMARY KEY,credential_hash TEXT NOT NULL,response BLOB NOT NULL,session TEXT NOT NULL);
          CREATE UNIQUE INDEX IF NOT EXISTS account_login_credential ON account_logins(credential_hash);
          CREATE TABLE IF NOT EXISTS account_exchanges(id TEXT PRIMARY KEY,credential_hash TEXT NOT NULL UNIQUE);")?;
        Ok(Self {
            db: Mutex::new(db),
            cipher: Aes256Gcm::new_from_slice(&key)
                .map_err(|_| anyhow::anyhow!("Invalid encryption key"))?,
            accounts: config.accounts_url.trim_end_matches('/').into(),
            app_id: config.accounts_app_id.clone(),
            app_secret: config.accounts_app_secret.clone(),
            apps_url: config.apps_url.trim_end_matches('/').into(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .user_agent(concat!("silicon-ting-server/", env!("CARGO_PKG_VERSION")))
                .build()?,
            locks: Mutex::new(HashMap::new()),
        })
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
        let data = serde_json::to_vec(value).map_err(storage)?;
        let bytes = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &data,
                    aad: id.as_bytes(),
                },
            )
            .map_err(storage)?;
        Ok([nonce.as_slice(), bytes.as_slice()].concat())
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
            .map_err(storage)?;
        serde_json::from_slice(&data).map_err(storage)
    }
    fn session(&self, id: &str) -> Result<Session> {
        let bytes: Option<Vec<u8>> = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT payload FROM account_sessions WHERE id=? AND revoked=0",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?;
        let s: Session = self.open(id, &bytes.ok_or_else(expired)?)?;
        if s.expires <= now() {
            return Err(expired());
        }
        Ok(s)
    }
    fn save(&self, id: &str, s: &Session) -> Result<()> {
        let bytes = self.seal(id, s)?;
        self.db
            .lock()
            .unwrap()
            .execute(
                "UPDATE account_sessions SET payload=? WHERE id=? AND revoked=0",
                params![bytes, id],
            )
            .map_err(storage)?;
        Ok(())
    }
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(method, format!("{}{path}", self.accounts))
            .basic_auth(&self.app_id, Some(&self.app_secret))
    }
    async fn upstream(&self, r: reqwest::RequestBuilder) -> Result<Value> {
        let response = r.send().await.map_err(|_| unavailable())?;
        let status = response.status();
        let value: Value = response.json().await.map_err(|_| unavailable())?;
        if !status.is_success() {
            if value["error"] == "invalid_grant" {
                return Err(expired());
            }
            if status.as_u16() == 404 {
                return Err(Error::not_found());
            }
            // Invalid app credentials and dependency failures are not a user logout.
            return Err(unavailable());
        }
        Ok(value)
    }
    pub fn session_id(token: &str) -> Result<String> {
        if !token
            .strip_prefix("ting_")
            .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(expired());
        }
        Ok(hash(token.as_bytes()))
    }
    async fn live(&self, id: &str) -> Result<Session> {
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        let mut s = self.session(id)?;
        // Introspection accepts refresh tokens and checks the whole sign-in live.
        // Ting needs identity only; no rotation means a lost refresh response cannot end a session.
        let value = self
            .upstream(
                self.request(reqwest::Method::POST, "/v1/oauth/introspect")
                    .form(&[("token", &s.refresh)]),
            )
            .await?;
        match value["active"].as_bool() {
            Some(true) => {}
            Some(false) => return Err(expired()),
            None => return Err(unavailable()),
        }
        if value["sub"] != s.uuid
            || value["aud"] != self.app_id
            || value["kind"] != s.kind
            || value["token_type"] != "refresh_token"
            || !value["exp"].as_i64().is_some_and(|exp| exp > now())
        {
            return Err(unavailable());
        }
        if let Some(handle) = value["id"]
            .as_str()
            .filter(|id| v::actor_kind(id) == Some(s.kind.as_str()))
            && handle != s.id
        {
            s.id = handle.into();
            self.save(id, &s)?;
        }
        self.session(id)?;
        Ok(s)
    }
    fn principal(id: &str, s: &Session) -> Principal {
        Principal {
            context: "accounts".into(),
            id: s.uuid.clone(),
            kind: s.kind.clone(),
            session: id.into(),
        }
    }
    pub async fn authenticate(&self, token: &str, _headers: &HeaderMap) -> Result<Principal> {
        let id = Self::session_id(token)?;
        let s = self.live(&id).await?;
        Ok(Self::principal(&id, &s))
    }
    pub async fn revalidate(&self, p: &Principal) -> Result<Principal> {
        let s = self.live(&p.session).await?;
        if s.uuid != p.id || s.kind != p.kind {
            return Err(expired());
        }
        Ok(Self::principal(&p.session, &s))
    }
    pub async fn authenticate_session(&self, id: &str) -> Result<Principal> {
        let s = self.live(id).await?;
        Ok(Self::principal(id, &s))
    }
    pub fn check_session_id(&self, id: &str) -> Result<()> {
        self.session(id).map(|_| ())
    }
    pub fn check_session(&self, p: &Principal) -> Result<()> {
        let s = self.session(&p.session)?;
        if s.uuid != p.id || s.kind != p.kind {
            return Err(expired());
        }
        Ok(())
    }
    pub fn check_proof(&self, p: &Proof) -> Result<()> {
        if p.expires_at <= now() {
            Err(expired())
        } else {
            Ok(())
        }
    }
    pub fn check_app(&self, p: &AppAuthority) -> Result<()> {
        if p.expires_at <= now() {
            Err(expired())
        } else {
            Ok(())
        }
    }
    fn tokens(value: &Value, _started: i64) -> Result<Session> {
        let (uuid, id, kind) = identity(&value["account"])?;
        let refresh = value["refresh_token"]
            .as_str()
            .filter(|s| s.starts_with("sar_"))
            .ok_or_else(unavailable)?;
        let expires = timestamp(&value["refresh_token_expires_at"])?;
        if expires <= now() {
            return Err(expired());
        }
        Ok(Session {
            uuid: uuid.into(),
            id: id.into(),
            kind: kind.into(),
            refresh: refresh.into(),
            expires,
        })
    }
    pub async fn login(&self, slt: &str, key: &str, _headers: &HeaderMap) -> Result<(u16, Value)> {
        if !slt.starts_with("slt_") || slt.len() > 8192 {
            return Err(Error::invalid(
                "Supply a Silicon Accounts short-lived token for Ting.",
            ));
        }
        self.exchange(
            key,
            slt,
            &[
                ("grant_type", "urn:silicon:params:oauth:grant-type:slt"),
                ("slt", slt),
            ],
        )
        .await
    }
    pub async fn login_code(
        &self,
        code: &str,
        key: &str,
        redirect: &str,
        verifier: &str,
    ) -> Result<(u16, Value)> {
        self.exchange(
            key,
            code,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect),
                ("code_verifier", verifier),
            ],
        )
        .await
    }
    async fn exchange(
        &self,
        key: &str,
        credential: &str,
        form: &[(&str, &str)],
    ) -> Result<(u16, Value)> {
        if !(16..=255).contains(&key.len()) || !key.bytes().all(|b| (33..=126).contains(&b)) {
            return Err(Error::invalid(
                "Idempotency-Key must contain 16–255 visible ASCII characters.",
            ));
        }
        let operation = hash(key.as_bytes());
        let credential_hash = hash(credential.as_bytes());
        let lock = self.lock("login");
        let _guard = lock.lock().await;
        let old: Option<(String, Vec<u8>, String)> = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT credential_hash,response,session FROM account_logins WHERE id=?",
                [&operation],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(storage)?;
        if let Some((previous, bytes, session)) = old {
            if previous != credential_hash {
                return Err(Error::new(
                    409,
                    "idempotency_conflict",
                    "This login key was used with another credential.",
                    "Repeat the original login or use a new key.",
                ));
            }
            self.session(&session)?;
            return Ok((200, self.open(&operation, &bytes)?));
        }
        let used: bool = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM account_logins WHERE credential_hash=?)",
                [&credential_hash],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if used {
            return Err(expired());
        }
        // Accounts exchanges are single-use and do not support idempotent replay.
        // Save the attempt first so a lost upstream response never reuses a code and revokes its family.
        let pending: bool = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM account_exchanges WHERE id=? OR credential_hash=?)",
                params![operation, credential_hash],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if pending {
            return Err(Error::new(
                409,
                "login_outcome_unknown",
                "The previous Accounts exchange has no saved result.",
                "Keep your existing session. Obtain a fresh short-lived token or start a new browser sign-in.",
            ));
        }
        self.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO account_exchanges VALUES(?,?)",
                params![operation, credential_hash],
            )
            .map_err(storage)?;
        let started = now();
        let value = self
            .upstream(
                self.request(reqwest::Method::POST, "/v1/oauth/token")
                    .header("Idempotency-Key", key)
                    .form(form),
            )
            .await?;
        let session = Self::tokens(&value, started)?;
        let token = format!("ting_{}", secret());
        let id = Self::session_id(&token)?;
        let response = json!({"session_token":token,"expires_at":iso(session.expires),"identity":{"uuid":session.uuid,"id":session.id,"kind":session.kind}});
        let encrypted = self.seal(&id, &session)?;
        let receipt = self.seal(&operation, &response)?;
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction().map_err(storage)?;
        tx.execute(
            "INSERT INTO account_sessions(id,payload) VALUES(?,?)",
            params![id, encrypted],
        )
        .map_err(storage)?;
        tx.execute(
            "INSERT INTO account_logins VALUES(?,?,?,?)",
            params![operation, credential_hash, receipt, id],
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok((201, response))
    }
    pub fn me(&self, p: &Principal) -> Result<Value> {
        let s = self.session(&p.session)?;
        Ok(
            json!({"authenticated":true,"uuid":s.uuid,"id":s.id,"kind":s.kind,"expires_at":iso(s.expires)}),
        )
    }
    pub async fn logout_by_id(&self, id: &str) -> Result<Value> {
        let lock = self.lock(id);
        let _guard = lock.lock().await;
        self.db
            .lock()
            .unwrap()
            .execute(
                "UPDATE account_sessions SET revoked=1,revoke_pending=1 WHERE id=?",
                [id],
            )
            .map_err(storage)?;
        let _ = self.revoke(id).await;
        Ok(json!({"authenticated":false}))
    }
    async fn revoke(&self, id: &str) -> Result<()> {
        let bytes: Option<Vec<u8>> = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT payload FROM account_sessions WHERE id=? AND revoke_pending=1",
                [id],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?;
        if let Some(bytes) = bytes {
            let s: Session = self.open(id, &bytes)?;
            self.upstream(
                self.request(reqwest::Method::POST, "/v1/oauth/revoke")
                    .form(&[("token", &s.refresh)]),
            )
            .await?;
            self.db
                .lock()
                .unwrap()
                .execute(
                    "UPDATE account_sessions SET revoke_pending=0 WHERE id=?",
                    [id],
                )
                .map_err(storage)?;
        }
        Ok(())
    }
    pub async fn retry_revocations(&self) {
        let ids: Vec<String> = {
            let db = self.db.lock().unwrap();
            let Ok(mut q) =
                db.prepare("SELECT id FROM account_sessions WHERE revoke_pending=1 LIMIT 100")
            else {
                return;
            };
            let Ok(rows) = q.query_map([], |r| r.get(0)) else {
                return;
            };
            rows.filter_map(std::result::Result::ok).collect()
        };
        for id in ids {
            let lock = self.lock(&id);
            let _guard = lock.lock().await;
            let _ = self.revoke(&id).await;
        }
    }
    pub async fn resolve_account(&self, account: &str) -> Result<String> {
        let path = if uuid::Uuid::parse_str(account).is_ok() {
            format!("/v1/accounts/{account}")
        } else if v::actor_kind(account).is_some() {
            format!("/v1/accounts/by-id/{account}")
        } else {
            return Err(Error::invalid("Use an account UUID or c:/si: identity."));
        };
        let value = self
            .upstream(self.request(reqwest::Method::GET, &path))
            .await?;
        let (uuid, _, _) = identity(&value)?;
        if value["status"] != "active" {
            return Err(forbidden());
        }
        Ok(uuid.into())
    }
    pub async fn apps(&self, p: &Principal) -> Result<Value> {
        let mut rows = Vec::new();
        let mut offset = 0u64;
        let mut total = None;
        loop {
            let value = self
                .upstream(
                    self.http
                        .get(format!("{}/v1/apps", self.apps_url))
                        .query(&[("limit", 100u64), ("offset", offset)]),
                )
                .await?;
            let items = value["items"].as_array().ok_or_else(unavailable)?;
            let total = *total.get_or_insert(value["total"].as_u64().ok_or_else(unavailable)?);
            for item in items {
                let app = item["app_id"]
                    .as_str()
                    .filter(|s| v::app_id(s))
                    .ok_or_else(unavailable)?;
                let can_manage = item["authors"]
                    .as_array()
                    .is_some_and(|authors| authors.iter().any(|author| author["uuid"] == p.id));
                rows.push(json!({"app_id":app,"name":item["name"].as_str().unwrap_or(app),"can_manage_tings":can_manage}));
            }
            offset += items.len() as u64;
            if offset >= total {
                break;
            }
            if items.is_empty() {
                return Err(unavailable());
            }
        }
        Ok(json!({"items":rows}))
    }
    pub async fn permission(&self, p: &Principal, app: &str, write: bool) -> Result<()> {
        if !v::app_id(app) {
            return Err(Error::invalid("Invalid app ID."));
        }
        if write {
            let value = self
                .upstream(
                    self.http
                        .get(format!("{}/v1/apps/{app}/authors", self.apps_url)),
                )
                .await?;
            if !value["items"]
                .as_array()
                .is_some_and(|authors| authors.iter().any(|a| a["uuid"] == p.id))
            {
                return Err(forbidden());
            }
        }
        Ok(())
    }
    async fn verified(&self, headers: &HeaderMap, path: &str) -> Result<Value> {
        let token = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .filter(|s| s.starts_with("sap_") && s.len() <= 8192)
            .ok_or_else(forbidden)?;
        let value = self
            .upstream(
                self.request(reqwest::Method::POST, "/v1/proofs/verify")
                    .json(&json!({"proof_token":token})),
            )
            .await?;
        let scope = match path {
            "/v1/tings" => "tings.send",
            "/v1/subscriptions" => "subscriptions.register",
            "/v1/subscriptions/query" => "subscriptions.read",
            "/v1/subscriptions/revoke" => "subscriptions.revoke",
            "/v1/sent/query" => "tings.read",
            "/v1/sent/read" => "tings.read.update",
            _ => return Err(forbidden()),
        };
        if value["valid"] != true
            || value["receiving_app"]["app_id"] != self.app_id
            || timestamp(&value["expires_at"])? <= now()
            || !value["scopes"]
                .as_array()
                .is_some_and(|scopes| scopes.iter().any(|s| s == scope))
            || !value["issuing_app"]["app_id"]
                .as_str()
                .is_some_and(v::app_id)
        {
            return Err(forbidden());
        }
        Ok(value)
    }
    pub async fn proof(&self, headers: &HeaderMap, path: &str, _raw: &[u8]) -> Result<Proof> {
        let value = self.verified(headers, path).await?;
        if value["kind"] != "user_verification" {
            return Err(forbidden());
        }
        let (uuid, _, _) = identity(&value["user"])?;
        Ok(Proof {
            context: "accounts".into(),
            app_id: value["issuing_app"]["app_id"].as_str().unwrap().into(),
            actor_id: uuid.into(),
            expires_at: timestamp(&value["expires_at"])?,
        })
    }
    pub async fn app_authority(
        &self,
        headers: &HeaderMap,
        path: &str,
        _raw: &[u8],
        body: &Value,
    ) -> Result<AppAuthority> {
        let value = self.verified(headers, path).await?;
        if value["kind"] != "app_verification" {
            return Err(forbidden());
        }
        let app = value["issuing_app"]["app_id"].as_str().unwrap();
        if body.get("app_id").is_some_and(|v| v != app)
            || body
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|t| v::type_parts(t).map_or(true, |p| p.0 != app))
        {
            return Err(forbidden());
        }
        Ok(AppAuthority {
            context: "accounts".into(),
            app_id: app.into(),
            expires_at: timestamp(&value["expires_at"])?,
        })
    }
    pub fn webhook(&self, headers: &HeaderMap, raw: &[u8]) -> Result<Value> {
        use hmac::{Hmac, Mac};
        let secret = std::env::var("TING_ACCOUNTS_WEBHOOK_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .ok_or_else(unavailable)?;
        let timestamp = headers
            .get("x-accounts-timestamp")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(forbidden)?;
        let seconds = timestamp.parse::<i64>().map_err(|_| forbidden())?;
        if now().abs_diff(seconds) > 300 {
            return Err(forbidden());
        }
        let signatures = headers
            .get("x-accounts-signature")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(forbidden)?;
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()).map_err(|_| unavailable())?;
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(raw);
        let verified = signatures
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter_map(|s| s.strip_prefix("v1="))
            .filter_map(|s| hex::decode(s).ok())
            .any(|bytes| mac.clone().verify_slice(&bytes).is_ok());
        if !verified {
            return Err(forbidden());
        }
        let event = v::parse(raw, 1024 * 1024)?;
        if event["app_id"] != self.app_id
            || event["event_id"].as_str()
                != headers
                    .get("x-accounts-event-id")
                    .and_then(|h| h.to_str().ok())
            || event["type"].as_str()
                != headers
                    .get("x-accounts-event-type")
                    .and_then(|h| h.to_str().ok())
        {
            return Err(forbidden());
        }
        // Introspection supplies live identity/revocation on every request; repeated events are harmless.
        Ok(json!({"accepted":true}))
    }
}
