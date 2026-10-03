//! Durable, explicit Honeycomb catalog consent. Login authority is never a grant.
use super::*;

const ENDPOINT: &str = "honeycomb.apps.list";
#[derive(Serialize, Deserialize)]
struct Pending {
    binding: String,
    state: String,
    request: Option<models::OboAuthorizationRequest>,
    authorization: Option<models::OboConsentDetail>,
    completed: bool,
    code_hash: Option<String>,
    #[serde(default)]
    popup_nonce: Option<String>,
    #[serde(default)]
    callback_code: Option<String>,
    #[serde(default)]
    declined: bool,
}
pub(super) fn required() -> Error {
    Error::new(
        403,
        "catalog_authorization_required",
        "Approve Honeycomb access to view and manage your applications.",
        "Open Applications and review Honeycomb access, or run ting apps authorize start. Your Ting login remains active.",
    )
}
fn binding(session: &Session, org: &str) -> String {
    let generation = session
        .test
        .as_ref()
        .map(|t| (&t.id, t.generation, hash(t.key.as_bytes())));
    format!(
        "catalog/{}",
        hash(
            serde_json::to_vec(&(
                session.context.as_str(),
                session.id.as_str(),
                session.kind.as_str(),
                org,
                generation
            ))
            .unwrap()
            .as_slice()
        )
    )
}
fn validate(pair: &models::OboTokenPair, session: &Session, org: &str) -> Result<()> {
    if pair.audience != "honeycomb"
        || pair.endpoint_id != ENDPOINT
        || pair.org_id != org
        || !pair.access_token.starts_with("oba_")
        || !pair.refresh_token.starts_with("obr_")
        || pair.actor.as_ref().is_none_or(|a| {
            a.public_id != session.id
                || !matches!(
                    (&a.type_field, session.kind.as_str()),
                    (models::ActorRefType::Carbon, "carbon")
                        | (models::ActorRefType::Silicon, "silicon")
                )
        })
        || pair.testing_context.is_some() != session.test.is_some()
        || pair
            .testing_context
            .as_ref()
            .is_some_and(|t| t.app_id != "honeycomb" || !t.app_secret.starts_with("ask_"))
    {
        return Err(Error::new(
            403,
            "catalog_context_mismatch",
            "Select the same account and organization for Honeycomb as your Ting workspace.",
            "Start a new approval and select this workspace's account and organization.",
        ));
    }
    Ok(())
}
impl Auth {
    fn catalog_record<T: serde::de::DeserializeOwned>(
        &self,
        table: &str,
        id: &str,
    ) -> Result<Option<T>> {
        // Both table names are internal constants, never request values.
        let sql = match table {
            "pending" => "SELECT payload FROM catalog_authorizations WHERE id=?",
            _ => "SELECT payload FROM catalog_grants WHERE id=?",
        };
        let bytes: Option<Vec<u8>> = self
            .db
            .lock()
            .unwrap()
            .query_row(sql, [id], |row| row.get(0))
            .optional()
            .map_err(storage)?;
        bytes
            .map(|bytes| self.open(&format!("catalog-{table}/{id}"), &bytes))
            .transpose()
    }
    fn save_catalog(
        &self,
        table: &str,
        id: &str,
        value: &impl Serialize,
        context: &str,
    ) -> Result<()> {
        let cipher = self.seal(&format!("catalog-{table}/{id}"), value)?;
        let sql = match table {
            "pending" => {
                "INSERT INTO catalog_authorizations(id,payload,context) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload"
            }
            _ => {
                "INSERT INTO catalog_grants(id,payload,context) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload"
            }
        };
        self.db
            .lock()
            .unwrap()
            .execute(sql, params![id, cipher, context])
            .map_err(storage)?;
        Ok(())
    }
    fn pending_response(id: &str, pending: &Pending) -> Result<Value> {
        let approved = pending.authorization.as_ref().ok_or_else(unavailable)?;
        let wire = serde_json::to_value(approved).map_err(storage)?;
        Ok(
            json!({"authorization_id":id,"consent_url":approved.authorization_url,"state":pending.state,"status":if pending.completed {"completed"} else {"pending"},"expires_at":wire["expires_at"]}),
        )
    }
    pub async fn catalog_start(&self, p: &Principal, org: &str, key: &str) -> Result<Value> {
        self.catalog_start_internal(p, org, key, None).await
    }
    pub async fn catalog_start_browser(
        &self,
        p: &Principal,
        org: &str,
        key: &str,
        callback: &str,
        nonce: &str,
    ) -> Result<Value> {
        self.catalog_start_internal(p, org, key, Some((callback, nonce)))
            .await
    }
    async fn catalog_start_internal(
        &self,
        p: &Principal,
        org: &str,
        key: &str,
        callback: Option<(&str, &str)>,
    ) -> Result<Value> {
        mutation(key)?;
        let (session, authority) = self.authority(p, org).await?;
        let binding = binding(&session, &authority.org_id);
        let id = hash(format!("{binding}/{key}").as_bytes());
        let lock = self.lock(&format!("catalog-request/{id}"));
        let _guard = lock.lock().await;
        let correlation = secret();
        let redirect_uri = callback
            .map(|(base, _)| {
                let mut url = url::Url::parse(base).map_err(|_| unavailable())?;
                url.query_pairs_mut()
                    .append_pair("org_id", org)
                    .append_pair("request_id", &id);
                Ok::<_, Error>(url.to_string())
            })
            .transpose()?;
        let mut pending = match self.catalog_record::<Pending>("pending", &id)? {
            Some(pending) => {
                if pending.popup_nonce.is_some() != callback.is_some() {
                    return Err(Error::new(
                        409,
                        "idempotency_conflict",
                        "This approval key belongs to another delivery mode.",
                        "Use the original request or a new key.",
                    ));
                }
                pending
            }
            None => Pending {
                binding,
                state: correlation.clone(),
                request: Some(models::OboAuthorizationRequest {
                    subject_token: session.access.clone(),
                    org_id: authority.org_id.clone(),
                    endpoints: vec![models::OboAuthorizationEndpoint {
                        audience: "honeycomb".into(),
                        endpoint_id: ENDPOINT.into(),
                    }],
                    state: redirect_uri.as_ref().map(|_| correlation),
                    redirect_uri,
                }),
                authorization: None,
                completed: false,
                code_hash: None,
                popup_nonce: callback.map(|(_, nonce)| nonce.to_owned()),
                callback_code: None,
                declined: false,
            },
        };
        if pending.declined {
            return Err(Error::new(
                409,
                "catalog_approval_declined",
                "The previous approval was declined.",
                "Start a new approval when you are ready.",
            ));
        }
        if let Some((_, nonce)) = callback {
            pending.popup_nonce = Some(nonce.to_owned());
        }
        if pending.authorization.is_none() {
            self.save_catalog("pending", &id, &pending, &session.context)?;
            let result = self
                .client(session.test.as_ref())?
                .obo()
                .authorize(
                    pending.request.as_ref().ok_or_else(unavailable)?,
                    &mutation(&format!("catalog-start-{id}"))?,
                )
                .await
                .map_err(iam_error)?;
            let url = result.authorization_url.as_ref().ok_or_else(unavailable)?;
            let url = url::Url::parse(url).map_err(|_| unavailable())?;
            let configured = url::Url::parse(
                &std::env::var("TING_IAM_CONSENT_URL")
                    .unwrap_or_else(|_| "https://auth.iam.teamofsilicons.com/login".into()),
            )
            .map_err(|_| unavailable())?;
            let request_ids: Vec<_> = url
                .query_pairs()
                .filter(|(key, _)| key == "request")
                .map(|(_, value)| value.into_owned())
                .collect();
            if url.origin() != configured.origin()
                || url.path() != "/obo/consent"
                || request_ids != [result.id.to_string()]
                || !(url.scheme() == "https"
                    || (url.scheme() == "http"
                        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))))
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
            {
                return Err(unavailable());
            }
            self.check_session(p)?;
            pending.authorization = Some(result);
            pending.request = None;
            self.save_catalog("pending", &id, &pending, &session.context)?;
        }
        self.save_catalog("pending", &id, &pending, &session.context)?;
        let retry = pending
            .callback_code
            .clone()
            .filter(|_| !pending.completed && callback.is_some());
        let result = Self::pending_response(&id, &pending)?;
        drop(_guard);
        if let Some(code) = retry {
            return self
                .catalog_complete(p, org, &id, &code, &pending.state)
                .await;
        }
        Ok(result)
    }
    pub async fn catalog_browser_callback(
        &self,
        p: &Principal,
        org: &str,
        id: &str,
        code: Option<&str>,
        state: &str,
        iam_id: &str,
    ) -> Result<(String, bool)> {
        let (session, authority) = self.authority(p, org).await?;
        let lock = self.lock(&format!("catalog-request/{id}"));
        let guard = lock.lock().await;
        let mut pending = self
            .catalog_record::<Pending>("pending", id)?
            .ok_or_else(Error::not_found)?;
        if pending.binding != binding(&session, &authority.org_id)
            || pending.state != state
            || pending
                .authorization
                .as_ref()
                .is_none_or(|a| a.id.to_string() != iam_id)
        {
            return Err(Error::not_found());
        }
        let nonce = pending.popup_nonce.clone().ok_or_else(Error::not_found)?;
        if let Some(code) = code {
            if !code.starts_with("obc_") || code.len() > 16384 {
                return Err(Error::invalid("Invalid approval code."));
            }
            if pending
                .callback_code
                .as_deref()
                .is_some_and(|previous| previous != code)
            {
                return Err(forbidden());
            }
            pending.callback_code = Some(code.to_owned());
        } else {
            pending.declined = true;
        }
        self.save_catalog("pending", id, &pending, &session.context)?;
        drop(guard);
        let success = match code {
            Some(code) => self.catalog_complete(p, org, id, code, state).await.is_ok(),
            None => false,
        };
        Ok((nonce, success))
    }
    pub async fn catalog_status(&self, p: &Principal, org: &str, id: &str) -> Result<Value> {
        let (session, authority) = self.authority(p, org).await?;
        let pending = self
            .catalog_record::<Pending>("pending", id)?
            .ok_or_else(Error::not_found)?;
        if pending.binding != binding(&session, &authority.org_id) {
            return Err(Error::not_found());
        }
        Self::pending_response(id, &pending)
    }
    pub async fn catalog_complete(
        &self,
        p: &Principal,
        org: &str,
        id: &str,
        code: &str,
        state: &str,
    ) -> Result<Value> {
        if code.len() > 16384 || !code.starts_with("obc_") || state.len() > 128 {
            return Err(Error::invalid(
                "A single-use approval code and its state are required.",
            ));
        }
        let (session, authority) = self.authority(p, org).await?;
        let binding = binding(&session, &authority.org_id);
        let lock = self.lock(&format!("catalog-request/{id}"));
        let _guard = lock.lock().await;
        let mut pending = self
            .catalog_record::<Pending>("pending", id)?
            .ok_or_else(Error::not_found)?;
        if pending.binding != binding || pending.state != state {
            return Err(Error::not_found());
        }
        let digest = hash(code.as_bytes());
        if pending.completed {
            if pending.code_hash.as_deref() != Some(&digest) {
                return Err(forbidden());
            }
            return Self::pending_response(id, &pending);
        }
        let approved = pending.authorization.as_ref().ok_or_else(unavailable)?;
        let mut response = self
            .client(session.test.as_ref())?
            .obo()
            .exchange_code(
                approved.id,
                code,
                &mutation(&format!("catalog-complete-{id}-{digest}"))?,
            )
            .await
            .map_err(|error| match error {
                silicon_iam_client::Error::Api(e) if matches!(e.status, 400 | 401 | 403 | 404 | 409 | 410) => Error::new(
                    400, "catalog_code_rejected", "IAM could not accept this approval code.",
                    "Copy the code for this request, or start a new approval if it expired. Your Ting login remains active.",
                ),
                _ => unavailable(),
            })?;
        if response.items.len() != 1 {
            return Err(unavailable());
        }
        let pair = response.items.remove(0);
        validate(&pair, &session, &authority.org_id)?;
        let grant_lock = self.lock(&binding);
        let _grant_guard = grant_lock.lock().await;
        self.check_session(p)?;
        // Commit the encrypted grant and completion receipt together.
        pending.completed = true;
        pending.code_hash = Some(digest);
        let grant_cipher = self.seal(&format!("catalog-grant/{binding}"), &pair)?;
        let pending_cipher = self.seal(&format!("catalog-pending/{id}"), &pending)?;
        {
            let mut db = self.db.lock().unwrap();
            let tx = db.transaction()?;
            tx.execute("INSERT INTO catalog_grants(id,payload,context) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",params![binding,grant_cipher,session.context])?;
            tx.execute(
                "UPDATE catalog_authorizations SET payload=? WHERE id=?",
                params![pending_cipher, id],
            )?;
            tx.commit()?;
        }
        Self::pending_response(id, &pending)
    }
    pub(super) async fn catalog_token(
        &self,
        p: &Principal,
        session: &Session,
        org: &str,
    ) -> Result<models::OboTokenPair> {
        let binding = binding(session, org);
        let lock = self.lock(&binding);
        let _guard = lock.lock().await;
        let mut pair = self
            .catalog_record::<models::OboTokenPair>("grant", &binding)?
            .ok_or_else(required)?;
        validate(&pair, session, org)?;
        if pair.expires_at.unix_timestamp() <= now() + 60 {
            let key = format!("catalog-refresh-{}", hash(pair.refresh_token.as_bytes()));
            let result = self
                .client(session.test.as_ref())?
                .obo()
                .refresh(&pair.refresh_token, &mutation(&key)?)
                .await;
            match result {
                Ok(mut result) if result.items.len() == 1 => pair = result.items.remove(0),
                Err(silicon_iam_client::Error::Api(e))
                    if matches!(e.status, 400 | 401 | 403 | 404 | 410) =>
                {
                    self.db
                        .lock()
                        .unwrap()
                        .execute("DELETE FROM catalog_grants WHERE id=?", [&binding])?;
                    return Err(required());
                }
                _ => return Err(unavailable()),
            }
            validate(&pair, session, org)?;
            self.check_session(p)?;
            self.save_catalog("grant", &binding, &pair, &session.context)?;
        }
        Ok(pair)
    }
    pub(super) async fn forget_catalog(
        &self,
        session: &Session,
        org: &str,
        rejected: &str,
    ) -> Result<()> {
        let binding = binding(session, org);
        let lock = self.lock(&binding);
        let _guard = lock.lock().await;
        if self
            .catalog_record::<models::OboTokenPair>("grant", &binding)?
            .is_some_and(|pair| pair.access_token == rejected)
        {
            self.db
                .lock()
                .unwrap()
                .execute("DELETE FROM catalog_grants WHERE id=?", [binding])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::fixture;
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn browser_callback_binds_state_actor_org_and_recovers_transient_exchange() {
        let f = fixture(false).await;
        let auth = &f.app.auth;
        let p = &f.principal;
        let request = auth
            .catalog_start_browser(
                p,
                "tos",
                "browser-catalog-flow-key",
                "https://ting.example/v1/session/catalog/callback",
                &"a".repeat(64),
            )
            .await
            .unwrap();
        let id = request["authorization_id"].as_str().unwrap();
        let state = request["state"].as_str().unwrap();
        assert!(
            auth.catalog_browser_callback(
                p,
                "tos",
                id,
                Some("obc_browser"),
                "wrong-state",
                "00000000-0000-4000-8000-000000000010"
            )
            .await
            .is_err()
        );
        assert!(
            auth.catalog_browser_callback(
                p,
                "elsewhere",
                id,
                Some("obc_browser"),
                state,
                "00000000-0000-4000-8000-000000000010"
            )
            .await
            .is_err()
        );
        assert!(
            auth.catalog_start(p, "tos", "browser-catalog-flow-key")
                .await
                .is_err()
        );
        assert!(
            auth.catalog_browser_callback(
                p,
                "tos",
                id,
                Some("obc_browser"),
                state,
                "00000000-0000-4000-8000-000000000099"
            )
            .await
            .is_err()
        );
        f.iam.catalog_token_status.store(503, Ordering::SeqCst);
        let (nonce, success) = auth
            .catalog_browser_callback(
                p,
                "tos",
                id,
                Some("obc_browser"),
                state,
                "00000000-0000-4000-8000-000000000010",
            )
            .await
            .unwrap();
        assert_eq!(nonce, "a".repeat(64));
        assert!(!success);
        f.iam.catalog_token_status.store(200, Ordering::SeqCst);
        let recovered = auth
            .catalog_start_browser(
                p,
                "tos",
                "browser-catalog-flow-key",
                "https://ting.example/v1/session/catalog/callback",
                &"b".repeat(64),
            )
            .await
            .unwrap();
        assert_eq!(recovered["status"], "completed");
        let exchanges = f.iam.proof_requests.lock().unwrap().clone();
        assert_eq!(exchanges.len(), 2);
        assert_eq!(exchanges[0]["key"], exchanges[1]["key"]);
        assert!(auth.check_session(p).is_ok());
    }

    #[tokio::test]
    async fn invalid_codes_keep_login_and_refresh_retries_keep_their_identity() {
        for testing in [false, true] {
            let f = fixture(testing).await;
            let auth = &f.app.auth;
            let p = &f.principal;
            let request = auth
                .catalog_start(p, "tos", "catalog-retry-identity-test")
                .await
                .unwrap();
            let id = request["authorization_id"].as_str().unwrap();
            let state = request["state"].as_str().unwrap();
            f.iam.catalog_token_status.store(401, Ordering::SeqCst);
            for _ in 0..2 {
                let rejected = auth
                    .catalog_complete(p, "tos", id, "obc_typo", state)
                    .await
                    .unwrap_err();
                assert_eq!(rejected.status, 400);
                assert_eq!(rejected.body["error"]["code"], "catalog_code_rejected");
                assert!(auth.check_session(p).is_ok());
            }
            f.iam.catalog_token_status.store(200, Ordering::SeqCst);
            auth.catalog_complete(p, "tos", id, "obc_correct", state)
                .await
                .unwrap();
            let exchanges = f.iam.proof_requests.lock().unwrap().clone();
            assert_eq!(exchanges[0]["key"], exchanges[1]["key"]);
            assert_ne!(exchanges[1]["key"], exchanges[2]["key"]);
            let (session, authority) = auth.authority(p, "tos").await.unwrap();
            let binding = binding(&session, &authority.org_id);
            let mut pair = auth
                .catalog_record::<models::OboTokenPair>("grant", &binding)
                .unwrap()
                .unwrap();
            pair.expires_at -= std::time::Duration::from_secs(3600);
            auth.save_catalog("grant", &binding, &pair, &session.context)
                .unwrap();
            f.iam.proof_requests.lock().unwrap().clear();
            f.iam.catalog_token_status.store(503, Ordering::SeqCst);
            assert_eq!(
                auth.catalog_token(p, &session, "tos")
                    .await
                    .unwrap_err()
                    .status,
                503
            );
            assert!(
                auth.catalog_record::<models::OboTokenPair>("grant", &binding)
                    .unwrap()
                    .is_some()
            );
            f.iam.catalog_token_status.store(200, Ordering::SeqCst);
            auth.catalog_token(p, &session, "tos").await.unwrap();
            let refreshes = f.iam.proof_requests.lock().unwrap().clone();
            assert!(refreshes.len() >= 2);
            assert!(refreshes.iter().all(|r| r["key"] == refreshes[0]["key"]
                && r["catalog_token_request"] == refreshes[0]["catalog_token_request"]));
            if testing {
                auth.fence_context(&session.context, "cleaning", "new-generation", true)
                    .unwrap();
                assert!(
                    auth.catalog_record::<models::OboTokenPair>("grant", &binding)
                        .unwrap()
                        .is_none()
                );
                assert!(
                    auth.catalog_record::<Pending>("pending", id)
                        .unwrap()
                        .is_none()
                );
            }
        }
    }
    #[tokio::test]
    async fn explicit_catalog_consent_is_encrypted_repeatable_and_plane_bound() {
        for testing in [false, true] {
            let f = fixture(testing).await;
            let auth = &f.app.auth;
            let p = &f.principal;
            assert_eq!(
                auth.apps(p, "tos").await.unwrap_err().body["error"]["code"],
                "catalog_authorization_required"
            );
            let request = auth
                .catalog_start(p, "tos", "catalog-test-start-key")
                .await
                .unwrap();
            assert!(request["expires_at"].is_string());
            let id = request["authorization_id"].as_str().unwrap();
            let state = request["state"].as_str().unwrap();
            assert_eq!(
                auth.catalog_start(p, "tos", "catalog-test-start-key")
                    .await
                    .unwrap(),
                request
            );
            assert_eq!(
                auth.catalog_complete(p, "tos", id, "obc_fixture", "wrong")
                    .await
                    .unwrap_err()
                    .status,
                404
            );
            let completed = auth
                .catalog_complete(p, "tos", id, "obc_fixture", state)
                .await
                .unwrap();
            assert_eq!(completed["status"], "completed");
            assert_eq!(
                auth.catalog_complete(p, "tos", id, "obc_fixture", state)
                    .await
                    .unwrap(),
                completed
            );
            assert!(
                auth.catalog_complete(p, "tos", id, "obc_different", state)
                    .await
                    .is_err()
            );
            assert_eq!(
                auth.apps(p, "tos").await.unwrap()["items"][0]["app_id"],
                "example"
            );
            assert!(auth.apps(p, "tos").await.is_ok());
            let (session, authority) = auth.authority(p, "tos").await.unwrap();
            let binding = binding(&session, &authority.org_id);
            let encrypted: Vec<u8> = auth
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT payload FROM catalog_grants WHERE id=?",
                    [&binding],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(!encrypted.windows(4).any(|w| w == b"oba_" || w == b"obr_"));
            assert!(
                auth.open::<models::OboTokenPair>("another-account", &encrypted)
                    .is_err()
            );
            let mut pair = auth
                .catalog_record::<models::OboTokenPair>("grant", &binding)
                .unwrap()
                .unwrap();
            let mut wrong = pair.clone();
            wrong.actor.as_mut().unwrap().public_id = "c:someoneelse".into();
            assert!(validate(&wrong, &session, "tos").is_err());
            wrong = pair.clone();
            wrong.org_id = "another_org".into();
            assert!(validate(&wrong, &session, "tos").is_err());
            pair.expires_at -= std::time::Duration::from_secs(3600);
            auth.save_catalog("grant", &binding, &pair, &session.context)
                .unwrap();
            f.take_calls();
            let (first, second) = tokio::join!(
                auth.catalog_token(p, &session, "tos"),
                auth.catalog_token(p, &session, "tos")
            );
            assert!(first.is_ok() && second.is_ok());
            assert_eq!(
                f.take_calls()
                    .iter()
                    .filter(|path| path.as_str() == "/api/v1/obo-access/tokens")
                    .count(),
                1
            );
            // Rejecting an old token cannot remove a newly approved grant.
            auth.forget_catalog(&session, "tos", "oba_old")
                .await
                .unwrap();
            assert!(auth.catalog_token(p, &session, "tos").await.is_ok());
            let mut changed = session.clone();
            changed.context = "other-plane".into();
            assert_eq!(
                auth.catalog_token(p, &changed, "tos")
                    .await
                    .unwrap_err()
                    .body["error"]["code"],
                "catalog_authorization_required"
            );
            auth.logout_by_id(&p.session).await.unwrap();
            assert!(
                auth.catalog_record::<models::OboTokenPair>("grant", &binding)
                    .unwrap()
                    .is_some()
            );
        }
    }
}
