//! ATA authorizes an application; recipient registration remains user-authorized OBO.
use super::*;

fn rejected() -> Error {
    Error::new(
        401,
        "invalid_ata_token",
        "IAM did not confirm this application's authority for the endpoint.",
        "Use a current ATA access token approved for Ting and this endpoint.",
    )
}

impl Auth {
    pub async fn app_authority(
        &self,
        headers: &HeaderMap,
        path: &str,
        raw: &[u8],
        body: &Value,
    ) -> Result<AppAuthority> {
        if !matches!(
            path,
            "/v1/tings"
                | "/v1/sent/query"
                | "/v1/sent/read"
                | "/v1/subscriptions/query"
                | "/v1/subscriptions/revoke"
        ) {
            return Err(forbidden());
        }
        let token = bearer(headers)?;
        // Select the protocol once. Rejection must never try another authority type.
        if token.starts_with("oba_") {
            let proof = self.proof(headers, path, raw).await?;
            self.check_proof(&proof)?;
            return Ok(proof.application());
        }
        let suffix = token.strip_prefix("ata_").ok_or_else(rejected)?;
        if suffix.len() != 43
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        {
            return Err(rejected());
        }
        let app_id = if path == "/v1/tings" {
            v::type_parts(v::string(body, "type", 255)?)?.0
        } else {
            v::string(body, "app_id", 80)?
        };
        if !v::app_id(app_id) {
            return Err(Error::invalid(
                "app_id must be a globally unique application ID.",
            ));
        }
        // ATA has no selected user organization. The caller supplies the immutable
        // recipient organization returned by OBO registration, not a guessed handle.
        let org = v::string(body, "org_id", 36)?;
        if !uuid::Uuid::parse_str(org).is_ok_and(|id| id.to_string() == org) {
            return Err(Error::invalid(
                "ATA org_id must be the canonical organization UUID returned by recipient registration.",
            ));
        }
        let test = self.test_headers(headers).await?;
        let verified = self
            .client(test.as_ref())?
            .ata()
            .verify(app_id, token, path)
            .await
            .map_err(|error| match error {
                silicon_iam_client::Error::Api(e)
                    if matches!(e.status, 400 | 401 | 403 | 404 | 409 | 410) =>
                {
                    rejected()
                }
                _ => Error::new(
                    503,
                    "ata_verification_uncertain",
                    "IAM verification could not be confirmed; nothing was executed.",
                    "Retry the same Ting operation and idempotency key.",
                ),
            })?;
        if !verified.verified {
            return Err(rejected());
        }
        let expiry = verified.valid_till.ok_or_else(rejected)?.to_string();
        let expires_at = chrono::NaiveDateTime::parse_from_str(&expiry, "%Y%m%d%H%M%S")
            .ok()
            .filter(|_| expiry.len() == 14)
            .map(|date| date.and_utc().timestamp())
            .filter(|expires| *expires > now())
            .ok_or_else(rejected)?;
        let authority = AppAuthority {
            context: test
                .as_ref()
                .map(|test| test.id.clone())
                .unwrap_or_else(|| "production".into()),
            org_id: org.into(),
            app_id: app_id.into(),
            expires_at,
            test,
        };
        self.check_app(&authority)?;
        Ok(authority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::{Fixture, fixture};
    use axum::{body::Body, http::Request};
    use std::sync::atomic::Ordering;
    use tower::ServiceExt;

    fn token(testing: bool) -> String {
        format!("ata_{}", if testing { "t" } else { "p" }.repeat(43))
    }
    fn headers(testing: bool) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {}", token(testing)).parse().unwrap(),
        );
        if testing {
            headers.insert("iam_test_app_secret", "fixture-secret".parse().unwrap());
            headers.insert("x-testing-environment-key", "k".repeat(32).parse().unwrap());
        }
        headers
    }
    fn send_body(f: &Fixture, key: &str) -> Value {
        json!({"org_id":f.proof.org_id,"type":"example.msg.received","data":{"text":"App-owned send"},"for":f.principal.id,"key":key})
    }
    async fn request(f: &Fixture, headers: &HeaderMap, path: &str, body: &Value) -> (u16, Value) {
        let mut request = Request::post(path)
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        *request.headers_mut() = headers.clone();
        request
            .headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        let response = crate::router(f.app.clone()).oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn ata_sends_after_obo_registration_and_retains_app_scoped_operations() {
        for testing in [false, true] {
            let f = fixture(testing).await;
            let headers = headers(testing);
            Connection::open(&f.app.config.database_path)
                .unwrap()
                .execute("DELETE FROM grants", [])
                .unwrap();
            let body = send_body(&f, "ata-http");
            assert_eq!(
                request(&f, &headers, "/v1/tings", &body).await.1["error"]["code"],
                "recipient_not_registered"
            );
            let mut obo_headers = headers.clone();
            obo_headers.insert("authorization", "Bearer oba_fixture".parse().unwrap());
            let (registered, registration) = request(
                &f,
                &obo_headers,
                "/v1/subscriptions",
                &json!({"org_id":"tos","app_id":"example"}),
            )
            .await;
            assert_eq!(registered, 201);
            assert_eq!(registration["org_id"], f.proof.org_id);
            assert_eq!(registration["for"], f.principal.id);
            assert_eq!(registration["active"], true);

            // Sending as the application does not introspect or impersonate its recipient.
            f.iam.reply.lock().unwrap()["active"] = false.into();
            f.iam.obo_status.store(401, Ordering::SeqCst);
            assert_eq!(request(&f, &obo_headers, "/v1/tings", &body).await.0, 401);
            f.take_calls();
            f.iam.ata_requests.lock().unwrap().clear();
            let (status, first) = request(&f, &headers, "/v1/tings", &body).await;
            assert_eq!(status, 202);
            assert_eq!(
                request(&f, &headers, "/v1/tings", &body).await,
                (200, first.clone())
            );
            assert_eq!(
                f.iam.ata_requests.lock().unwrap().len(),
                2,
                "idempotent replay still verifies current ATA authority"
            );
            assert!(
                !f.take_calls()
                    .iter()
                    .any(|path| path.contains("introspect") || path.contains("obo-access"))
            );
            let mut changed = body.clone();
            changed["data"] = json!({"changed":true});
            assert_eq!(request(&f, &headers, "/v1/tings", &changed).await.0, 409);

            let query = json!({"org_id":f.proof.org_id,"app_id":"example","id":first["id"]});
            assert_eq!(
                request(&f, &headers, "/v1/sent/query", &query).await.1["read"],
                false
            );
            let read = json!({"org_id":f.proof.org_id,"app_id":"example","message_ids":[first["id"]],"read":true,"key":"ata-read"});
            assert_eq!(request(&f, &headers, "/v1/sent/read", &read).await.0, 200);
            assert_eq!(
                request(&f, &headers, "/v1/sent/query", &query).await.1["read"],
                true
            );
            let subscriptions = json!({"org_id":f.proof.org_id,"app_id":"example"});
            let (_, listed) =
                request(&f, &headers, "/v1/subscriptions/query", &subscriptions).await;
            assert_eq!(listed["items"][0]["id"], registration["id"]);
            let mut revoke = json!({"org_id":f.proof.org_id,"id":registration["id"]});
            assert_eq!(
                request(&f, &headers, "/v1/subscriptions/revoke", &revoke)
                    .await
                    .0,
                400,
                "ATA cannot infer the origin from a subscription ID"
            );
            revoke["app_id"] = "example".into();
            assert_eq!(
                request(&f, &headers, "/v1/subscriptions/revoke", &revoke)
                    .await
                    .1["active"],
                false
            );
            assert_eq!(
                request(
                    &f,
                    &headers,
                    "/v1/tings",
                    &send_body(&f, "after-unsubscribe")
                )
                .await
                .1["error"]["code"],
                "recipient_not_registered"
            );
            // A receipt is recoverable after unsubscribe, but cannot create another delivery.
            assert_eq!(
                request(&f, &headers, "/v1/tings", &body).await,
                (200, first)
            );
            *f.iam.ata_reply.lock().unwrap() = json!({"verified":false});
            assert_eq!(
                request(&f, &headers, "/v1/tings", &body).await.1["error"]["code"],
                "invalid_ata_token",
                "revoked ATA cannot even read an old receipt"
            );
            let calls = f.iam.ata_requests.lock().unwrap();
            for call in calls.iter() {
                assert_eq!(call["app_id"], "example");
                assert_eq!(call["app_proof_token"], token(testing));
                assert!(!call.as_object().unwrap().contains_key("actor"));
            }
            for endpoint in [
                "/v1/tings",
                "/v1/sent/query",
                "/v1/sent/read",
                "/v1/subscriptions/query",
                "/v1/subscriptions/revoke",
            ] {
                assert!(calls.iter().any(|call| call["endpoint"] == endpoint));
            }
        }
    }

    #[tokio::test]
    async fn ata_rejects_bad_authority_and_cannot_create_recipient_or_receiver_consent() {
        let f = fixture(false).await;
        let headers = headers(false);
        let body = send_body(&f, "rejected");
        let good = f.iam.ata_reply.lock().unwrap().clone();
        for (reply, upstream, status, code) in [
            (json!({"verified":false}), 200, 401, "invalid_ata_token"),
            (
                json!({"verified":true,"valid_till":20200101000000i64}),
                200,
                401,
                "invalid_ata_token",
            ),
            (
                json!({"verified":true,"valid_till":20261301000000i64}),
                200,
                401,
                "invalid_ata_token",
            ),
            (
                json!({"verified":true}),
                200,
                503,
                "ata_verification_uncertain",
            ),
            (good.clone(), 401, 401, "invalid_ata_token"),
            (good.clone(), 503, 503, "ata_verification_uncertain"),
        ] {
            *f.iam.ata_reply.lock().unwrap() = reply;
            f.iam.ata_status.store(upstream, Ordering::SeqCst);
            let response = request(&f, &headers, "/v1/tings", &body).await;
            assert_eq!(response.0, status);
            assert_eq!(response.1["error"]["code"], code);
            assert!(
                f.iam.proof_requests.lock().unwrap().is_empty(),
                "ATA rejection must never try OBO"
            );
        }
        *f.iam.ata_reply.lock().unwrap() = good;
        f.iam.ata_status.store(200, Ordering::SeqCst);
        for (field, value, expected) in [
            ("org_id", json!("tos"), 400),
            ("org_id", json!(uuid::Uuid::new_v4()), 403),
            ("for", json!("si:unregistered"), 403),
            ("type", json!("other.msg.received"), 401),
            ("type", json!("example.unknown.received"), 404),
        ] {
            let mut changed = body.clone();
            changed[field] = value;
            assert_eq!(
                request(&f, &headers, "/v1/tings", &changed).await.0,
                expected,
                "{field}"
            );
        }
        for token in [
            "atr_not-an-access-token".to_owned(),
            "ata_short".to_owned(),
            "ting_not-app-authority".to_owned(),
        ] {
            let mut invalid = headers.clone();
            invalid.insert("authorization", format!("Bearer {token}").parse().unwrap());
            let before = f.iam.ata_requests.lock().unwrap().len();
            assert_eq!(request(&f, &invalid, "/v1/tings", &body).await.0, 401);
            assert_eq!(f.iam.ata_requests.lock().unwrap().len(), before);
        }
        let registration =
            json!({"org_id":f.proof.org_id,"app_id":"example","for":"si:unregistered"});
        assert_eq!(
            request(&f, &headers, "/v1/subscriptions", &registration)
                .await
                .1["error"]["code"],
            "invalid_obo_token"
        );
        let receiver = json!({"org_id":f.proof.org_id,"app_id":"example","for":f.principal.id,"key":"receiver-test-key","environment_id":f.principal.context,"generation":1});
        assert_eq!(
            request(&f, &headers, "/v1/receivers/bootstrap", &receiver)
                .await
                .1["error"]["code"],
            "invalid_obo_token"
        );
        assert!(
            f.app
                .store
                .tings(
                    &f.proof.context,
                    &f.proof.org_id,
                    None,
                    Some("example"),
                    &json!({})
                )
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn ata_never_crosses_worlds_and_rechecks_clean_generation_before_mutation() {
        let f = fixture(true).await;
        let body = send_body(&f, "world-crossing");
        let testing_headers = headers(true);
        let mut wrong = testing_headers.clone();
        wrong.insert(
            "authorization",
            format!("Bearer {}", token(false)).parse().unwrap(),
        );
        assert_eq!(request(&f, &wrong, "/v1/tings", &body).await.0, 401);
        wrong = headers(false);
        wrong.insert(
            "authorization",
            format!("Bearer {}", token(true)).parse().unwrap(),
        );
        assert_eq!(request(&f, &wrong, "/v1/tings", &body).await.0, 401);
        wrong = testing_headers.clone();
        wrong.insert("x-testing-environment-key", "x".repeat(32).parse().unwrap());
        assert_eq!(request(&f, &wrong, "/v1/tings", &body).await.0, 403);
        wrong = testing_headers;
        wrong.remove("iam_test_app_secret");
        assert_eq!(request(&f, &wrong, "/v1/tings", &body).await.0, 400);

        for path in [
            "/v1/tings",
            "/v1/sent/query",
            "/v1/sent/read",
            "/v1/subscriptions/query",
            "/v1/subscriptions/revoke",
        ] {
            let f = fixture(true).await;
            let body = match path {
                "/v1/tings" => send_body(&f, "before-clean"),
                "/v1/sent/read" => {
                    json!({"org_id":f.proof.org_id,"app_id":"example","message_ids":[f.send("before-clean")],"read":true,"key":"before-clean"})
                }
                "/v1/subscriptions/revoke" => {
                    json!({"org_id":f.proof.org_id,"app_id":"example","id":f.app.store.grants(&f.proof.context,&f.proof.org_id,None,Some("example")).unwrap()[0]["id"]})
                }
                _ => json!({"org_id":f.proof.org_id,"app_id":"example"}),
            };
            *f.iam.block_path.lock().unwrap() = Some("/api/v1/ata-access/verify".into());
            let gate = f.app.mutations.lock().await;
            let app = f.app.clone();
            let pending = tokio::spawn(async move {
                crate::app_call(
                    &app,
                    &headers(true),
                    path,
                    &serde_json::to_vec(&body).unwrap(),
                    &body,
                )
                .await
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
            assert_eq!(
                f.app
                    .store
                    .grants(&f.proof.context, &f.proof.org_id, None, Some("example"))
                    .unwrap()[0]["active"],
                true
            );
            let retained = f
                .app
                .store
                .tings(
                    &f.proof.context,
                    &f.proof.org_id,
                    None,
                    Some("example"),
                    &json!({}),
                )
                .unwrap();
            if path == "/v1/sent/read" {
                assert_eq!(retained[0]["read"], false);
            } else {
                assert!(retained.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn ata_http_and_websocket_share_reverification_and_send_idempotency() {
        use tokio_tungstenite::tungstenite::Message;
        for testing in [false, true] {
            let f = fixture(testing).await;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("ws://{}/v1/ws?protocol=v1", listener.local_addr().unwrap());
            let app = f.app.clone();
            let server = tokio::spawn(async move {
                axum::serve(listener, crate::router(app)).await.unwrap();
            });
            let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
            let ready = socket.next().await.unwrap().unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(ready.to_text().unwrap()).unwrap()["op"],
                "ready"
            );
            let body = send_body(&f, "transport-replay");
            let (status, first) = request(&f, &headers(testing), "/v1/tings", &body).await;
            assert_eq!(status, 202);
            let mut frame = json!({"op":"send","request_id":"ata-ws","proof_token":token(testing),"body":body.to_string()});
            if testing {
                frame["headers"] = json!({"IAM_TEST_APP_SECRET":"fixture-secret","X-Testing-Environment-Key":"k".repeat(32)});
            }
            socket
                .send(Message::Text(frame.to_string().into()))
                .await
                .unwrap();
            let replay: Value =
                serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            assert_eq!(replay["op"], "accepted");
            assert_eq!(replay["id"], first["id"]);
            assert_eq!(f.iam.ata_requests.lock().unwrap().len(), 2);
            *f.iam.ata_reply.lock().unwrap() = json!({"verified":false});
            socket
                .send(Message::Text(frame.to_string().into()))
                .await
                .unwrap();
            let rejected: Value =
                serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap())
                    .unwrap();
            assert_eq!(rejected["error"]["code"], "invalid_ata_token");
            assert_eq!(f.iam.ata_requests.lock().unwrap().len(), 3);
            assert!(
                f.iam
                    .ata_requests
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|call| call["endpoint"] == "/v1/tings")
            );
            socket.close(None).await.unwrap();
            server.abort();
        }
    }
}
