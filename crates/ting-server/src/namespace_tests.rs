use super::*;
use axum::{
    extract::Path,
    routing::{get, post},
};
use rusqlite::params;
use std::path::PathBuf;
const ACCOUNT: &str = "11111111-1111-4111-8111-111111111111";
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("ting-prefix-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }
    fn database(&self) -> String {
        self.0.join("ting.sqlite").to_str().unwrap().into()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn aliases() -> namespaces::Prefixes {
    namespaces::Prefixes::parse(r#"{"cells":"silicon-cells"}"#).unwrap()
}
fn principal() -> auth::Principal {
    auth::Principal {
        context: "accounts".into(),
        id: ACCOUNT.into(),
        kind: "carbon".into(),
        session: "fixture".into(),
    }
}
fn expiration() -> String {
    (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()
}
fn account() -> Value {
    json!({"uuid":ACCOUNT,"id":"c:fixture","kind":"carbon","status":"active"})
}

#[test]
fn prefix_configuration_is_explicit_and_unambiguous() {
    assert!(
        namespaces::Prefixes::default()
            .owns("write", "write.document.shared")
            .unwrap()
    );
    let aliases = aliases();
    assert!(
        aliases
            .owns("silicon-cells", "cells.database.failing")
            .unwrap()
    );
    assert!(!aliases.owns("cells", "cells.database.failing").unwrap());
    for invalid in [
        r#"{"cells":"silicon-cells","cells":"other"}"#,
        r#"{"cells":"silicon-cells","silicon-cells":"other"}"#,
        r#"{"cells":"cells"}"#,
        r#"{"Cells":"silicon-cells"}"#,
        r#"{"cells":null}"#,
        r#"{"cells":"../other"}"#,
    ] {
        assert!(namespaces::Prefixes::parse(invalid).is_err());
    }
}
#[test]
fn existing_namespace_ownership_cannot_be_stolen_or_removed() -> anyhow::Result<()> {
    let directory = Directory::new();
    let path = directory.database();
    let p = principal();
    let default = namespaces::Prefixes::default();
    let original = store::Store::open(&path, &default)?;
    original.register_type(
        &p,
        "cells",
        &json!({"type":"cells.database.failing","description":"Existing owner"}),
        None,
    )?;
    drop(original);
    assert!(store::Store::open(&path, &aliases()).is_err());
    let db = rusqlite::Connection::open(&path)?;
    assert_eq!(
        db.query_row(
            "SELECT app FROM types WHERE name='cells.database.failing'",
            [],
            |r| r.get::<_, String>(0)
        )?,
        "cells"
    );
    assert_eq!(
        db.query_row(
            "SELECT owner_app FROM type_namespaces WHERE prefix='cells'",
            [],
            |r| r.get::<_, String>(0)
        )?,
        "cells"
    );
    drop(db);
    let directory = Directory::new();
    let path = directory.database();
    // Even an unused explicitly configured alias is durably reserved. A stale
    // process opened before the reservation cannot subsequently claim that prefix.
    let stale = store::Store::open(&path, &default)?;
    let owner = store::Store::open(&path, &aliases())?;
    assert!(
        stale
            .register_type(
                &p,
                "cells",
                &json!({"type":"cells.database.failing","description":"Takeover"}),
                None
            )
            .is_err()
    );
    owner.register_type(
        &p,
        "silicon-cells",
        &json!({"type":"cells.database.failing","description":"Owned by actual app"}),
        None,
    )?;
    drop(stale);
    drop(owner);
    assert!(store::Store::open(&path, &default).is_err());
    assert!(
        store::Store::open(
            &path,
            &namespaces::Prefixes::parse(r#"{"cells":"unrelated"}"#)?
        )
        .is_err()
    );
    let reopened = store::Store::open(&path, &aliases())?;
    assert_eq!(reopened.types(&p, "silicon-cells")?.len(), 1);
    assert!(reopened.types(&p, "cells")?.is_empty());
    Ok(())
}
#[test]
fn historical_senders_and_preferences_keep_canonical_app_identity() -> anyhow::Result<()> {
    let directory = Directory::new();
    let path = directory.database();
    let default = namespaces::Prefixes::default();
    let p = principal();
    let old = store::Store::open(&path, &default)?;
    old.preference(
        &p,
        &json!({"app_id":"cells","type":"cells.database.future","enabled":false}),
        false,
    )?;
    drop(old);
    let mapped = store::Store::open(&path, &aliases())?;
    // A recipient may remove an old personal preference without gaining authority
    // to write a preference under a now-different type owner.
    assert!(
        mapped
            .preference(
                &p,
                &json!({"app_id":"cells","type":"cells.database.future","enabled":true}),
                false
            )
            .is_err()
    );
    mapped.preference(
        &p,
        &json!({"app_id":"cells","type":"cells.database.future"}),
        true,
    )?;
    assert!(mapped.preferences(&p, &json!({}))?.is_empty());
    drop(mapped);
    let directory = Directory::new();
    let path = directory.database();
    let store = store::Store::open(&path, &default)?;
    drop(store);
    let db = rusqlite::Connection::open(&path)?;
    db.execute("INSERT INTO tings(id,ctx,app,recipient,type,created,body,silent) VALUES('historic','accounts','cells',?,'cells.database.legacy',?,'{}',0)",params![ACCOUNT,chrono::Utc::now().to_rfc3339()])?;
    drop(db);
    assert!(
        store::Store::open(&path, &aliases()).is_err(),
        "historical sender ownership must not be transferred even if its type row is absent"
    );
    Ok(())
}
async fn fixture_proof(Json(body): Json<Value>) -> Json<Value> {
    let token = body["proof_token"].as_str().unwrap_or("");
    let (issuer, kind) = match token {
        "sap_cells" => ("silicon-cells", "app_verification"),
        "sap_cells_user" => ("silicon-cells", "user_verification"),
        "sap_wrong" => ("cells", "app_verification"),
        "sap_other" => ("other", "app_verification"),
        _ => return Json(json!({"valid":false})),
    };
    Json(
        json!({"valid":true,"receiving_app":{"app_id":"ting"},"issuing_app":{"app_id":issuer},"expires_at":expiration(),"kind":kind,"scopes":["tings.send","tings.read","tings.read.update","subscriptions.register","subscriptions.read","subscriptions.revoke"],"user":account()}),
    )
}
async fn fixture_token() -> Json<Value> {
    Json(
        json!({"account":account(),"refresh_token":"sar_fixture","refresh_token_expires_at":expiration()}),
    )
}
async fn fixture_introspection() -> Json<Value> {
    Json(
        json!({"active":true,"sub":ACCOUNT,"aud":"ting","kind":"carbon","token_type":"refresh_token","exp":chrono::Utc::now().timestamp()+3600,"id":"c:fixture"}),
    )
}
async fn fixture_authors(Path(app): Path<String>) -> Json<Value> {
    // The same fixture person authors both apps. Rejection of /apps/cells/types
    // therefore demonstrates prefix ownership, not incidental missing authorship.
    Json(
        json!({"items":if matches!(app.as_str(),"silicon-cells"|"cells"){vec![json!({"uuid":ACCOUNT})]}else{vec![]}}),
    )
}
async fn spawn(router: Router) -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Ok((url, task))
}
async fn call(
    client: &reqwest::Client,
    url: &str,
    method: reqwest::Method,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> anyhow::Result<(u16, Value)> {
    let mut request = client
        .request(method, format!("{url}{path}"))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await?;
    let status = response.status().as_u16();
    Ok((status, response.json().await?))
}
async fn send(client: &reqwest::Client, url: &str, key: &str) -> anyhow::Result<Value> {
    let (status,result)=call(client,url,reqwest::Method::POST,"/v1/tings","sap_cells",Some(json!({"type":"cells.database.failing","for":ACCOUNT,"key":key,"data":{"message":"fixture"}}))).await?;
    assert_eq!(status, 202, "{result}");
    Ok(result)
}
#[tokio::test]
async fn real_http_alias_authority_registration_preferences_and_history() -> anyhow::Result<()> {
    http_acceptance(None).await
}
#[tokio::test]
#[ignore = "Run scripts/test-prefix-aliases.py to build and exercise the actual CLI"]
async fn real_cli_alias_registration_preferences_and_history() -> anyhow::Result<()> {
    let binary = std::env::var("TING_TEST_CLI")?;
    http_acceptance(Some(&binary)).await
}
async fn cli(
    binary: &str,
    home: &std::path::Path,
    url: &str,
    args: &[&str],
    stdin: &str,
) -> anyhow::Result<Value> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new(binary)
        .env("SILICON_HOME", home)
        .args(["--api-url", url, "--json"])
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().unwrap();
    input.write_all(stdin.as_bytes()).await?;
    drop(input);
    let output = tokio::time::timeout(std::time::Duration::from_secs(15), child.wait_with_output())
        .await??;
    anyhow::ensure!(
        output.status.success(),
        "CLI fixture operation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
async fn http_acceptance(binary: Option<&str>) -> anyhow::Result<()> {
    let fixture = Router::new()
        .route("/v1/proofs/verify", post(fixture_proof))
        .route("/v1/oauth/token", post(fixture_token))
        .route("/v1/oauth/introspect", post(fixture_introspection))
        .route("/v1/accounts/{account}", get(|| async { Json(account()) }))
        .route("/v1/apps/{app}/authors", get(fixture_authors));
    let (upstream, fixture_task) = spawn(fixture).await?;
    let directory = Directory::new();
    let path = directory.database();
    let config = Config {
        type_prefix_aliases: aliases(),
        database_path: path.clone(),
        encryption_key: "41".repeat(32),
        accounts_url: upstream.clone(),
        accounts_app_id: "ting".into(),
        accounts_app_secret: "fixture-only".into(),
        apps_url: upstream,
        frontend_origin: "http://localhost".into(),
        public_origin: "http://localhost".into(),
        browser_origins: vec![],
        repository_url: "https://example.com/repo".into(),
        docs_url: "https://example.com/docs".into(),
        rust_package: "silicon-ting-client".into(),
    };
    let app = Arc::new(App {
        auth: auth::Auth::new(&config)?,
        store: store::Store::open(&path, &config.type_prefix_aliases)?,
        config,
        hub: ws::Hub::default(),
        changed: Notify::new(),
        mutations: Mutex::new(()),
    });
    let (url, server) = spawn(router(app.clone())).await?;
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{url}/v1/session"))
        .header("Idempotency-Key", "fixture-login-key-0001")
        .json(&json!({"slt":"slt_fixture"}))
        .send()
        .await?;
    let status = response.status().as_u16();
    let login: Value = response.json().await?;
    assert_eq!(status, 201, "{login}");
    let token = login["session_token"].as_str().unwrap();
    let definition = json!({"type":"cells.database.failing","description":"Database failure"});
    let (status, _) = call(
        &client,
        &url,
        reqwest::Method::POST,
        "/v1/apps/silicon-cells/types",
        token,
        Some(definition.clone()),
    )
    .await?;
    assert_eq!(status, 201);
    let (status, _) = call(
        &client,
        &url,
        reqwest::Method::POST,
        "/v1/apps/silicon-cells/types",
        token,
        Some(definition.clone()),
    )
    .await?;
    assert_eq!(status, 200);
    let (status, _) = call(
        &client,
        &url,
        reqwest::Method::POST,
        "/v1/apps/cells/types",
        token,
        Some(definition),
    )
    .await?;
    assert_eq!(status, 400);
    let (status, _) = call(
        &client,
        &url,
        reqwest::Method::PATCH,
        "/v1/apps/silicon-cells/types/cells.database.failing",
        token,
        Some(json!({"description":"Updated by real owner"})),
    )
    .await?;
    assert_eq!(status, 200);
    let (status, _) = call(
        &client,
        &url,
        reqwest::Method::PATCH,
        "/v1/apps/cells/types/cells.database.failing",
        token,
        Some(json!({"description":"Takeover"})),
    )
    .await?;
    assert_eq!(status, 404);
    let (status, listed) = call(
        &client,
        &url,
        reqwest::Method::GET,
        "/v1/apps/silicon-cells/types",
        token,
        None,
    )
    .await?;
    assert_eq!(status, 200);
    assert_eq!(listed["items"][0]["type"], "cells.database.failing");
    let (status, _) = call(
        &client,
        &url,
        reqwest::Method::POST,
        "/v1/subscriptions",
        "sap_cells_user",
        Some(json!({"app_id":"cells"})),
    )
    .await?;
    assert_eq!(status, 403);
    let (status, subscription) = call(
        &client,
        &url,
        reqwest::Method::POST,
        "/v1/subscriptions",
        "sap_cells_user",
        Some(json!({"app_id":"silicon-cells"})),
    )
    .await?;
    assert_eq!(status, 201);
    assert_eq!(subscription["app_id"], "silicon-cells");
    assert_eq!(send(&client, &url, "send-1").await?["silent"], false);
    for proof in ["sap_wrong", "sap_other"] {
        let (status, _) = call(
            &client,
            &url,
            reqwest::Method::POST,
            "/v1/tings",
            proof,
            Some(json!({"type":"cells.database.failing","for":ACCOUNT,"key":"wrong","data":{}})),
        )
        .await?;
        assert_eq!(status, 403);
    }
    for (preference, key, silent) in [
        (
            json!({"app_id":"silicon-cells","enabled":false}),
            "send-2",
            true,
        ),
        (
            json!({"app_id":"silicon-cells","service":"database","enabled":true}),
            "send-3",
            false,
        ),
        (
            json!({"app_id":"silicon-cells","type":"cells.database.failing","enabled":false}),
            "send-4",
            true,
        ),
    ] {
        let (status, _) = call(
            &client,
            &url,
            reqwest::Method::PUT,
            "/v1/preferences",
            token,
            Some(preference),
        )
        .await?;
        assert_eq!(status, 200);
        assert_eq!(send(&client, &url, key).await?["silent"], silent);
    }
    let (status, _) = call(
        &client,
        &url,
        reqwest::Method::PUT,
        "/v1/preferences",
        token,
        Some(json!({"app_id":"cells","type":"cells.database.failing","enabled":true})),
    )
    .await?;
    assert_eq!(status, 400);
    let (_, preferences) = call(
        &client,
        &url,
        reqwest::Method::GET,
        "/v1/preferences?app_id=silicon-cells&type=cells.database.failing",
        token,
        None,
    )
    .await?;
    assert_eq!(preferences["items"].as_array().unwrap().len(), 1);
    assert_eq!(preferences["items"][0]["app_id"], "silicon-cells");
    let (status, history) = call(
        &client,
        &url,
        reqwest::Method::POST,
        "/v1/sent/query",
        "sap_cells",
        Some(json!({"app_id":"silicon-cells","type":"cells.database.failing"})),
    )
    .await?;
    assert_eq!(status, 200);
    assert_eq!(history["items"].as_array().unwrap().len(), 4);
    let (status, foreign) = call(
        &client,
        &url,
        reqwest::Method::POST,
        "/v1/sent/query",
        "sap_wrong",
        Some(json!({"app_id":"cells"})),
    )
    .await?;
    assert_eq!(status, 200);
    assert!(foreign["items"].as_array().unwrap().is_empty());
    let (status, _) = call(
        &client,
        &url,
        reqwest::Method::POST,
        "/v1/sent/query",
        "sap_cells",
        Some(json!({"app_id":"cells"})),
    )
    .await?;
    assert_eq!(status, 403);
    // Catch-up and offer SQL must derive the service from the label, not from
    // the longer canonical app ID. Muting a service also blocks already queued work.
    let p = principal();
    app.store.preference(
        &p,
        &json!({"app_id":"silicon-cells","type":"cells.database.failing"}),
        true,
    )?;
    app.store
        .preference(&p, &json!({"app_id":"silicon-cells","enabled":true}), false)?;
    app.store.preference(
        &p,
        &json!({"app_id":"silicon-cells","service":"database","enabled":false}),
        false,
    )?;
    let muted = app
        .store
        .create_hook(&p, "receiver-muted", "hook-muted", &json!({}))?;
    assert_eq!(muted["pending"], 0);
    app.store.preference(
        &p,
        &json!({"app_id":"silicon-cells","service":"database","enabled":true}),
        false,
    )?;
    let hook = app
        .store
        .create_hook(&p, "receiver", "hook-enabled", &json!({}))?;
    assert_eq!(hook["pending"], 2);
    let hid = hook["id"].as_str().unwrap();
    app.store.preference(
        &p,
        &json!({"app_id":"silicon-cells","service":"database","enabled":false}),
        false,
    )?;
    assert!(app.store.offer("receiver", hid)?.is_none());
    app.store.preference(
        &p,
        &json!({"app_id":"silicon-cells","service":"database","enabled":true}),
        false,
    )?;
    assert_eq!(
        app.store.offer("receiver", hid)?.unwrap()["tings"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let db = rusqlite::Connection::open(&path)?;
    assert_eq!(
        db.query_row(
            "SELECT owner_app FROM type_namespaces WHERE ctx='accounts' AND prefix='cells'",
            [],
            |r| r.get::<_, String>(0)
        )?,
        "silicon-cells"
    );
    assert_eq!(db.query_row("SELECT count(*) FROM tings WHERE app='silicon-cells' AND type='cells.database.failing'",[],|r|r.get::<_,i64>(0))?,4);
    assert_eq!(
        db.query_row("SELECT count(*) FROM grants WHERE app='cells'", [], |r| r
            .get::<_, i64>(
            0
        ))?,
        0
    );
    drop(db);
    if let Some(binary) = binary {
        let home = Directory::new();
        assert_eq!(
            cli(
                binary,
                &home.0,
                &url,
                &["login", "--token-stdin"],
                "slt_fixture_cli\n"
            )
            .await?["authenticated"],
            true
        );
        let registered = cli(
            binary,
            &home.0,
            &url,
            &[
                "types",
                "register",
                "--app",
                "silicon-cells",
                "--type",
                "cells.database.cli",
                "--description",
                "CLI alias fixture",
            ],
            "",
        )
        .await?;
        assert_eq!(registered["type"], "cells.database.cli");
        assert_eq!(
            cli(
                binary,
                &home.0,
                &url,
                &[
                    "types",
                    "update",
                    "--app",
                    "silicon-cells",
                    "--type",
                    "cells.database.cli",
                    "--description",
                    "Updated CLI alias fixture"
                ],
                ""
            )
            .await?["description"],
            "Updated CLI alias fixture"
        );
        assert_eq!(
            cli(
                binary,
                &home.0,
                &url,
                &[
                    "preferences",
                    "set",
                    "--app",
                    "silicon-cells",
                    "--type",
                    "cells.database.cli",
                    "--enabled",
                    "false"
                ],
                ""
            )
            .await?["app_id"],
            "silicon-cells"
        );
        let request = home.0.join("query.json");
        let request = request.to_str().unwrap();
        cli(
            binary,
            &home.0,
            &url,
            &[
                "sent",
                "list",
                "--app",
                "silicon-cells",
                "--type",
                "cells.database.failing",
                "--write-request",
                request,
            ],
            "",
        )
        .await?;
        let history = cli(
            binary,
            &home.0,
            &url,
            &[
                "sent",
                "list",
                "--request-file",
                request,
                "--app-token-stdin",
            ],
            "sap_cells\n",
        )
        .await?;
        assert_eq!(history["items"].as_array().unwrap().len(), 4);
    }
    server.abort();
    fixture_task.abort();
    let _ = server.await;
    let _ = fixture_task.await;
    println!(
        "Verified real HTTP Accounts proof identity, alias type registration/update, canonical subscriptions/sent history, hierarchical preferences and cross-app denial on durable SQLite."
    );
    Ok(())
}
