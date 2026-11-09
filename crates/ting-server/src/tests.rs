use super::*;
use std::{path::PathBuf, time::Duration};
use ting_client::{
    Client,
    websocket::{Event, WebSocket},
};

const ALICE: &str = "00000000-0000-4000-8000-000000000001";
const BOB: &str = "00000000-0000-4000-8000-000000000002";

fn account(id: &str) -> Value {
    if id == BOB || id == "c:bob" {
        json!({"uuid": BOB, "id": "c:bob", "kind": "carbon", "status": "active"})
    } else {
        json!({"uuid": ALICE, "id": "c:alice", "kind": "carbon", "status": "active"})
    }
}

struct Server {
    app: Shared,
    client: Client,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    directory: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

impl Server {
    async fn start() -> Self {
        let accounts = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let accounts_url = format!("http://{}", accounts.local_addr().unwrap());
        let accounts_router = Router::new().route(
            "/v1/proofs/verify",
            axum::routing::post(|Json(body): Json<Value>| async move {
                if body["proof_token"] == "sap_slow" {
                    tokio::time::sleep(Duration::from_secs(11)).await;
                }
                Json(json!({
                    "valid": true, "kind": if body["proof_token"] == "sap_user" { "user_verification" } else { "app_verification" },
                    "issuing_app": {"app_id": "demo"}, "receiving_app": {"app_id": "ting"},
                    "scopes": ["tings.send", "subscriptions.register"], "user": account(ALICE),
                    "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()
                }))
            }),
        )
        .route("/v1/oauth/token", axum::routing::post(|| async {
            Json(json!({"account": account(ALICE), "refresh_token": "sar_test",
                "refresh_token_expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()}))
        }))
        .route("/v1/oauth/introspect", axum::routing::post(|| async {
            Json(json!({"active": true, "sub": ALICE, "aud": "ting", "kind": "carbon",
                "token_type": "refresh_token", "exp": store::now() + 3600, "id": "c:alice"}))
        }))
        .route("/v1/accounts/{id}", get(|Path(id): Path<String>| async move { Json(account(&id)) }))
        .route("/v1/accounts/by-id/{id}", get(|Path(id): Path<String>| async move { Json(account(&id)) }));
        let accounts_task =
            tokio::spawn(async move { axum::serve(accounts, accounts_router).await.unwrap() });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let directory = std::env::temp_dir().join(format!("ting-tests-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let config = Config {
            type_prefix_aliases: namespaces::Prefixes::default(),
            database_path: directory.join("ting.sqlite").to_str().unwrap().into(),
            encryption_key: "00".repeat(32),
            accounts_url,
            accounts_app_id: "ting".into(),
            accounts_app_secret: "test-only".into(),
            apps_url: origin.clone(),
            frontend_origin: origin.clone(),
            public_origin: origin.clone(),
            browser_origins: vec![],
            repository_url: "https://example.com/ting".into(),
            docs_url: "https://example.com/docs".into(),
            rust_package: "silicon-ting-client".into(),
        };
        let app = Arc::new(App {
            auth: auth::Auth::new(&config).unwrap(),
            store: store::Store::open(&config.database_path, &config.type_prefix_aliases).unwrap(),
            config,
            hub: ws::Hub::default(),
            changed: Notify::new(),
            mutations: Mutex::new(()),
        });
        app.store.register_type(&auth::Principal {
            context: "accounts".into(), id: uuid::Uuid::new_v4().to_string(),
            kind: "silicon".into(), session: "test-author".into(),
        }, "demo", &json!({
            "type": "demo.finished", "description": "A task finished",
            "schema": {"type": "object", "properties": {"task": {"type": "string"}}, "required": ["task"], "additionalProperties": false}
        }), None).unwrap();
        let service = router(app.clone());
        let server_task =
            tokio::spawn(async move { axum::serve(listener, service).await.unwrap() });
        Self {
            app,
            client: Client::new(&origin).unwrap(),
            tasks: vec![accounts_task, server_task],
            directory,
        }
    }

    async fn send(&self, session_id: &str, key: &str, data: Value) -> ting_client::Result<Value> {
        self.client
            .json(
                "POST",
                "/v1/tings",
                Some(json!({
                    "type": "demo.finished", "session_id": session_id, "key": key, "data": data
                })),
                Some("sap_test_only"),
            )
            .await
    }

    async fn login(&self) -> String {
        let result = self
            .client
            .request(
                "POST",
                "/v1/session",
                Some(br#"{"slt":"slt_test"}"#.to_vec()),
                None,
                Some("test-login-operation"),
            )
            .await
            .unwrap();
        result["session_token"].as_str().unwrap().to_owned()
    }
}

#[tokio::test]
async fn anonymous_sessions_receive_only_registered_apps_and_disappear_on_disconnect() {
    let server = Server::start().await;
    let mut socket = WebSocket::connect(&server.client).await.unwrap();
    let sid = socket.session_id().to_owned();
    let error = server
        .send(&sid, "unregistered", json!({"task": "first"}))
        .await
        .unwrap_err();
    assert_eq!(error.code, "recipient_not_registered");
    socket.register(&["demo".into()], None).await.unwrap();
    let accepted = server
        .send(&sid, "registered", json!({"task": "second"}))
        .await
        .unwrap();
    let event = tokio::time::timeout(Duration::from_secs(3), socket.next_event())
        .await
        .unwrap()
        .unwrap();
    match event {
        Event::Tings {
            webhook_id,
            session_id,
            tings,
        } => {
            assert!(webhook_id.is_none());
            assert_eq!(session_id.as_deref(), Some(sid.as_str()));
            assert_eq!(tings.len(), 1);
            assert_eq!(tings[0]["id"], accepted["id"]);
            assert_eq!(tings[0]["data"]["task"], "second");
        }
        other => panic!("unexpected event: {other:?}"),
    }
    let replay = server
        .send(&sid, "registered", json!({"task": "second"}))
        .await
        .unwrap();
    assert_eq!(replay["id"], accepted["id"]);
    drop(socket);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if server
                .send(
                    &sid,
                    &uuid::Uuid::new_v4().to_string(),
                    json!({"task": "third"}),
                )
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn public_schemas_are_enforced_before_acceptance() {
    let server = Server::start().await;
    let public = reqwest::Client::new()
        .get(format!("{}/v1/apps/demo/types", server.client.origin))
        .header("Origin", "https://another-app.example")
        .send()
        .await
        .unwrap();
    assert!(public.status().is_success());
    assert_eq!(public.headers()["access-control-allow-origin"], "*");
    assert!(
        !public
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    let private = reqwest::Client::new()
        .get(format!("{}/v1/preferences", server.client.origin))
        .header("Origin", "https://another-app.example")
        .send()
        .await
        .unwrap();
    assert_eq!(private.status(), StatusCode::FORBIDDEN);
    let catalog = server
        .client
        .json("GET", "/v1/apps/demo/types", None, None)
        .await
        .unwrap();
    assert_eq!(catalog["items"][0]["type"], "demo.finished");
    assert_eq!(catalog["items"][0]["schema"]["required"], json!(["task"]));
    let mut socket = WebSocket::connect(&server.client).await.unwrap();
    socket.register(&["demo".into()], None).await.unwrap();
    assert!(
        server
            .send(socket.session_id(), "invalid", json!({"task": 42}))
            .await
            .is_err()
    );
    assert!(
        server
            .send(socket.session_id(), "valid", json!({"task": "ready"}))
            .await
            .is_ok()
    );
    // Type ownership is checked against the verified app even for anonymous targets.
    let rejected = server.client.json("POST", "/v1/tings", Some(json!({
        "type": "someoneelse.finished", "session_id": socket.session_id(), "key": "wrong-app", "data": {}
    })), Some("sap_test_only")).await;
    assert!(rejected.is_err());
    assert!(server.app.store.types_for_app("demo").unwrap().len() == 1);
}

#[tokio::test]
async fn heartbeat_continues_while_accounts_verification_is_slow() {
    let server = Server::start().await;
    let mut socket = WebSocket::connect(&server.client).await.unwrap();
    socket.register(&["demo".into()], None).await.unwrap();
    let prepared = ting_client::Prepared::new(ting_client::ProofOperation::Send, serde_json::to_vec(&json!({
        "type": "demo.finished", "session_id": socket.session_id(), "key": "slow-proof", "data": {"task": "done"}
    })).unwrap()).unwrap();
    let accepted = socket.send(&prepared, "sap_slow").await.unwrap();
    assert_eq!(accepted["status"], "accepted");
    assert!(socket.is_connected());
}

#[tokio::test]
async fn identity_sessions_fan_out_target_and_honor_sender_blocks() {
    let server = Server::start().await;
    let token = server.login().await;
    server
        .client
        .json(
            "POST",
            "/v1/subscriptions",
            Some(json!({"app_id": "demo"})),
            Some("sap_user"),
        )
        .await
        .unwrap();
    let mut first = WebSocket::connect(&server.client).await.unwrap();
    let mut second = WebSocket::connect(&server.client).await.unwrap();
    let unrelated = WebSocket::connect(&server.client).await.unwrap();
    first.register(&[], Some(&token)).await.unwrap();
    second.register(&[], Some(&token)).await.unwrap();
    let sessions = server
        .client
        .json("GET", "/v1/sessions", None, Some(&token))
        .await
        .unwrap();
    assert_eq!(sessions["items"].as_array().unwrap().len(), 2);
    let all = server.client.json("POST", "/v1/tings", Some(json!({
        "type": "demo.finished", "for": "c:alice", "key": "all", "data": {"task": "everywhere"}
    })), Some("sap_test_only")).await.unwrap();
    for socket in [&mut first, &mut second] {
        let event = tokio::time::timeout(Duration::from_secs(3), socket.next_event())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(event, Event::Tings { tings, .. } if tings[0]["id"] == all["id"]));
    }
    let targeted = server
        .send(first.session_id(), "one", json!({"task": "here"}))
        .await
        .unwrap();
    assert_eq!(targeted["for"], ALICE);
    let event = tokio::time::timeout(Duration::from_secs(3), first.next_event())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event, Event::Tings { tings, .. } if tings[0]["id"] == targeted["id"]));
    assert!(
        tokio::time::timeout(Duration::from_millis(150), second.next_event())
            .await
            .is_err()
    );
    let wrong_session = server.client.json("POST", "/v1/tings", Some(json!({
        "type": "demo.finished", "for": "c:alice", "session_id": unrelated.session_id(), "key": "wrong-session", "data": {"task": "no"}
    })), Some("sap_test_only")).await.unwrap_err();
    assert_eq!(wrong_session.code, "session_gone");

    server
        .client
        .json(
            "PUT",
            "/v1/preferences",
            Some(json!({"from": "c:bob", "mode": "blocked"})),
            Some(&token),
        )
        .await
        .unwrap();
    let blocked = server.client.json("POST", "/v1/tings", Some(json!({
        "type": "demo.finished", "for": "c:alice", "from": "c:bob", "key": "blocked", "data": {"task": "no"}
    })), Some("sap_test_only")).await.unwrap();
    assert_eq!(blocked["status"], "blocked");
    let inbox = server
        .client
        .json("GET", "/v1/inbox", None, Some(&token))
        .await
        .unwrap();
    assert_eq!(inbox["items"].as_array().unwrap().len(), 2);
    let schedule = server
        .client
        .json(
            "PUT",
            "/v1/silent-schedule",
            Some(json!({"enabled":false,"time":"18:30","timezone":"Asia/Kolkata"})),
            Some(&token),
        )
        .await
        .unwrap();
    assert_eq!(schedule["enabled"], false);
    assert_eq!(schedule["time"], "18:30");
}

#[tokio::test]
async fn timezone_detection_initializes_midnight_without_overwriting_saved_choices() {
    let server = Server::start().await;
    let http = reqwest::Client::new();
    let login: Value = http
        .post(format!("{}/v1/session", server.client.origin))
        .header("Idempotency-Key", "timezone-login-operation")
        .json(&json!({"slt":"slt_timezone"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = login["session_token"].as_str().unwrap();
    let path = format!("{}/v1/silent-schedule", server.client.origin);
    let fallback: Value = http
        .get(&path)
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fallback["time"], "09:00");
    assert_eq!(fallback["timezone"], "UTC");
    let detected: Value = http
        .get(&path)
        .bearer_auth(token)
        .header("X-Ting-Timezone", "Asia/Kolkata")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detected["time"], "00:00");
    assert_eq!(detected["timezone"], "Asia/Kolkata");
    http.put(&path)
        .bearer_auth(token)
        .json(&json!({"time":"18:30","enabled":false}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let saved: Value = http
        .get(&path)
        .bearer_auth(token)
        .header("X-Ting-Timezone", "America/New_York")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(saved["time"], "18:30");
    assert_eq!(saved["timezone"], "Asia/Kolkata");
    assert_eq!(saved["enabled"], false);
}
