mod auth;
mod error;
mod lifecycle;
mod migration;
mod receiver;
mod store;
mod telemetry;
mod validation;
mod ws;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, RawQuery, State, WebSocketUpgrade},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use error::{Error, Result};
use serde_json::{Value, json};
use std::{env, sync::Arc};
use tokio::sync::{Mutex, Notify};
use validation as v;

#[derive(Clone)]
pub struct Config {
    pub database_path: String,
    pub encryption_key: String,
    pub iam_url: String,
    pub iam_app_id: String,
    pub iam_app_secret: String,
    pub honeycomb_url: String,
    pub spacestation_url: String,
    pub spacestation_key: String,
    pub spacestation_table: String,
    pub frontend_origin: String,
    pub public_origin: String,
    pub browser_origins: Vec<String>,
    pub repository_url: String,
    pub docs_url: String,
    pub rust_package: String,
}
impl Config {
    fn env() -> anyhow::Result<Self> {
        fn required(k: &str) -> anyhow::Result<String> {
            let s = env::var(k).map_err(|_| anyhow::anyhow!("{k} is required"))?;
            anyhow::ensure!(!s.is_empty(), "{k} must not be empty");
            Ok(s)
        }
        let public_origin = browser_origin(&required("TING_PUBLIC_ORIGIN")?)?;
        let frontend_origin = browser_origin(
            &env::var("TING_FRONTEND_ORIGIN").unwrap_or_else(|_| public_origin.clone()),
        )?;
        let browser_origins =
            browser_origins(&env::var("TING_BROWSER_ORIGINS").unwrap_or_default())?;
        Ok(Self {
            database_path: env::var("TING_DATABASE_PATH").unwrap_or("ting.sqlite".into()),
            encryption_key: required("TING_ENCRYPTION_KEY")?,
            iam_url: required("TING_IAM_URL")?,
            iam_app_id: "ting".into(),
            iam_app_secret: required("TING_IAM_APP_SECRET")?,
            honeycomb_url: required("TING_HONEYCOMB_URL")?,
            spacestation_url: required("TING_SPACESTATION_URL")?,
            spacestation_key: required("TING_SPACESTATION_KEY")?,
            spacestation_table: required("TING_SPACESTATION_TABLE")?,
            frontend_origin,
            public_origin,
            browser_origins,
            repository_url: "https://github.com/teamofsilicons/silicon-ting".into(),
            docs_url: required("TING_DOCS_URL")?,
            rust_package: "silicon-ting-client".into(),
        })
    }
}
fn browser_origin(s: &str) -> anyhow::Result<String> {
    let u = url::Url::parse(s)?;
    anyhow::ensure!(
        u.host_str().is_some_and(|host| !host.contains('*'))
            && (u.scheme() == "https"
                || (u.scheme() == "http"
                    && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))))
            && u.username().is_empty()
            && u.password().is_none()
            && u.path() == "/"
            && u.query().is_none()
            && u.fragment().is_none(),
        "Configured origins must be HTTPS with no path (HTTP permitted on loopback)"
    );
    Ok(u.origin().ascii_serialization())
}
fn browser_origins(s: &str) -> anyhow::Result<Vec<String>> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    s.split(',').map(|s| browser_origin(s.trim())).collect()
}
pub struct App {
    pub config: Config,
    pub auth: auth::Auth,
    pub store: store::Store,
    pub hub: ws::Hub,
    pub changed: Notify,
    pub mutations: Mutex<()>,
}
pub type Shared = Arc<App>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    if !args.is_empty() {
        anyhow::ensure!(
            (args.len() == 2 || (args.len() == 3 && args[2] == "--apply"))
                && args[0] == "--migrate-public-identifiers",
            "Usage: ting-server [--migrate-public-identifiers MAP.json [--apply]]"
        );
        let report = migration::run(
            &env::var("TING_DATABASE_PATH")?,
            &env::var("TING_ENCRYPTION_KEY")?,
            &args[1],
            args.len() == 3,
        )?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();
    let config = Config::env()?;
    let auth = auth::Auth::new(&config)?;
    let store = store::Store::open(&config.database_path)?;
    let app = Arc::new(App {
        config,
        auth,
        store,
        hub: ws::Hub::default(),
        changed: Notify::new(),
        mutations: Mutex::new(()),
    });
    let maintenance = app.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            maintenance.auth.retry_revocations().await;
        }
    });
    let retention = app.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let _gate = retention.mutations.lock().await;
            let result: Result<()> = async {
                for (ctx, org, recipient) in retention.store.expired_owners()? {
                    retention
                        .hub
                        .invalidate(&retention, &ctx, &org, &recipient, "preference_changed")
                        .await?;
                }
                let removed = retention.store.prune()?;
                if removed > 0 {
                    tracing::info!(removed, "expired notification history");
                }
                Ok(())
            }
            .await;
            if let Err(error) = result {
                tracing::error!(error=%error,"notification retention cleanup failed");
            }
        }
    });
    let router = router(app);
    let bind = env::var("TING_BIND").unwrap_or("127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind,"ting server listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
fn router(app: Shared) -> Router {
    Router::new()
        .route(
            "/healthz",
            get(|| async {
                Json(json!({"status":"ok","service":"ting","version":env!("CARGO_PKG_VERSION")}))
            }),
        )
        .route("/v1/ws", get(upgrade))
        .route("/v1/receivers/ws", get(receiver::upgrade))
        .route("/internal/honeycomb/organizations/{org}/testing-environments/{environment}/operations/{operation}", axum::routing::put(lifecycle::handle))
        .route("/v1/{*path}", any(http))
        .fallback(|| async { Error::not_found() })
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), request_id))
        .with_state(app)
}
async fn request_id(
    State(app): State<Shared>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let started = std::time::Instant::now();
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let browser_origin = request.headers().get("origin").cloned();
    let allowed = origin(&app, request.headers());
    let permitted = allowed.is_ok();
    let mut response = match allowed {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    };
    response
        .headers_mut()
        .append("Vary", HeaderValue::from_static("Origin"));
    if let Some(origin) = browser_origin.filter(|_| permitted) {
        response
            .headers_mut()
            .insert("Access-Control-Allow-Origin", origin);
        response.headers_mut().insert(
            "Access-Control-Allow-Credentials",
            HeaderValue::from_static("true"),
        );
        response.headers_mut().insert(
            "Access-Control-Expose-Headers",
            HeaderValue::from_static("Ting-Request-Id"),
        );
    }
    app.auth.diagnostic(
        "http.request.completed",
        &method,
        &path,
        response.status().as_u16(),
        started.elapsed().as_millis() as u64,
    );
    response.headers_mut().insert(
        "Ting-Request-Id",
        HeaderValue::from_str(&store::id("req")).unwrap(),
    );
    response
}
pub fn token(headers: &HeaderMap) -> Result<String> {
    if let Some(h) = headers.get("authorization") {
        return h
            .to_str()
            .ok()
            .and_then(|s| s.strip_prefix("Bearer "))
            .filter(|s| !s.is_empty())
            .map(String::from)
            .ok_or_else(unauth);
    }
    cookie(headers, "ting_session").ok_or_else(unauth)
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|s| s.strip_prefix(&format!("{name}=")).map(String::from))
}
fn unauth() -> Error {
    Error::new(
        401,
        "authentication_required",
        "A valid Ting session is required.",
        "Sign in through IAM or run ting login with a Ting-bound short-lived token.",
    )
}
fn query(raw: Option<String>) -> Result<Value> {
    let mut map = serde_json::Map::new();
    if let Some(raw) = raw {
        for (k, val) in url::form_urlencoded::parse(raw.as_bytes()) {
            if map.contains_key(k.as_ref()) {
                return Err(Error::invalid(
                    "Repeated query parameters are not supported.",
                ));
            }
            let value = if matches!(k.as_ref(), "read" | "silent") {
                match val.as_ref() {
                    "true" => true.into(),
                    "false" => false.into(),
                    _ => {
                        return Err(Error::invalid(
                            "Boolean query values must be true or false.",
                        ));
                    }
                }
            } else if k == "limit" {
                Value::Number(
                    val.parse::<u64>()
                        .map_err(|_| Error::invalid("limit must be an integer from 1 to 100."))?
                        .into(),
                )
            } else {
                val.into_owned().into()
            };
            map.insert(k.into_owned(), value);
        }
    }
    Ok(map.into())
}
fn response(status: u16, value: Value) -> Response {
    (StatusCode::from_u16(status).unwrap(), Json(value)).into_response()
}
fn header<'a>(h: &'a HeaderMap, k: &str) -> Result<&'a str> {
    h.get(k)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 200 && !s.chars().any(char::is_control))
        .ok_or_else(|| Error::invalid(format!("A nonempty {k} header is required.")))
}
fn origin(app: &App, h: &HeaderMap) -> Result<()> {
    if let Some(o) = h.get("origin") {
        if o.to_str().ok() != Some(&app.config.frontend_origin)
            && o.to_str().ok() != Some(&app.config.public_origin)
            && !app
                .config
                .browser_origins
                .iter()
                .any(|allowed| o.to_str().ok() == Some(allowed))
            || h.get_all("origin").iter().count() != 1
        {
            return Err(Error::new(
                403,
                "permission_denied",
                "This browser origin is not permitted.",
                "Use a browser origin explicitly permitted by Ting.",
            ));
        }
    }
    Ok(())
}
async fn http(
    State(app): State<Shared>,
    Path(path): Path<String>,
    RawQuery(raw): RawQuery,
    method: Method,
    headers: HeaderMap,
    bytes: std::result::Result<Bytes, axum::extract::rejection::BytesRejection>,
) -> Result<Response> {
    let bytes = bytes.map_err(|rejection| {
        Error::new(
            rejection.status().as_u16(),
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                "payload_too_large"
            } else {
                "invalid_input"
            },
            "The request body could not be read within the 1 MiB limit.",
            "Send a complete request no larger than 1 MiB.",
        )
    })?;
    if path == "iam/webhook" && method == Method::POST {
        return Ok(response(200, app.auth.webhook(&headers, &bytes)?));
    }
    if method == Method::OPTIONS {
        let mut r = StatusCode::NO_CONTENT.into_response();
        if headers.contains_key("origin") {
            r.headers_mut().insert(
                "Access-Control-Allow-Methods",
                HeaderValue::from_static("GET,POST,PUT,PATCH,DELETE,OPTIONS"),
            );
            r.headers_mut().insert("Access-Control-Allow-Headers",HeaderValue::from_static("Content-Type,Authorization,Idempotency-Key,IAM_TEST_APP_SECRET,X-Testing-Environment-Key,Ting-Client-Version"));
        }
        return Ok(r);
    }
    if !bytes.is_empty()
        && !headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|s| s.split(';').next() == Some("application/json"))
    {
        return Err(Error::invalid(
            "Requests with a body require Content-Type: application/json.",
        ));
    }
    if cookie(&headers, "ting_session").is_some()
        && method != Method::GET
        && headers.get("authorization").is_none()
        && !headers.contains_key("origin")
    {
        return Err(Error::new(
            403,
            "permission_denied",
            "Browser mutations require a permitted Origin.",
            "Make this request from a browser origin explicitly permitted by Ting.",
        ));
    }
    let f = query(raw)?;
    let parts: Vec<_> = path.split('/').collect();
    let b = if bytes.is_empty() {
        json!({})
    } else {
        v::parse(
            &bytes,
            if path == "tings" {
                256 * 1024
            } else if path == "bugs" {
                192 * 1024
            } else {
                1024 * 1024
            },
        )?
    };
    if path == "iam" && method == Method::GET {
        return Ok(response(
            200,
            json!({"app_id":app.config.iam_app_id,"api_version":"v1","repository_url":app.config.repository_url,"docs_url":app.config.docs_url,"rust_package":app.config.rust_package}),
        ));
    }
    if path == "session/login" && method == Method::GET {
        return browser_login(&app, &f);
    }
    if path == "session/callback" && method == Method::GET {
        return browser_callback(&app, &headers, &f).await;
    }
    if path == "session" && method == Method::POST {
        v::fields(&b, &["slt"], &["slt"])?;
        let (status, result) = app
            .auth
            .login(
                v::string(&b, "slt", 16384)?,
                header(&headers, "Idempotency-Key")?,
                &headers,
            )
            .await?;
        return Ok(response(status, result));
    }
    if path == "receivers/bootstrap" && method == Method::POST {
        let (status, result) = receiver::bootstrap(&app, &headers, &bytes, &b).await?;
        return Ok(response(status, result));
    }
    if path.starts_with("receivers/") {
        return receiver::http(&app, &method, &path, &headers, &f).await;
    }
    if method == Method::POST
        && [
            "tings",
            "subscriptions",
            "subscriptions/query",
            "subscriptions/revoke",
            "sent/query",
        ]
        .contains(&path.as_str())
    {
        return app_call(&app, &headers, &format!("/v1/{path}"), &bytes, &b)
            .await
            .map(|(s, v)| response(s, v));
    }
    if path == "telemetry" && method == Method::POST {
        if bytes.len() > 65536 {
            return Err(Error::new(
                413,
                "payload_too_large",
                "Telemetry batches are limited to 64 KiB.",
                "Send a smaller batch.",
            ));
        }
        return Ok(response(202, telemetry::ingest(&app, b).await?));
    }
    if path == "session" && method == Method::DELETE {
        // Possession can revoke this exact opaque session even when IAM access is
        // inactive; durable cleanup must not depend on live login authority.
        let id = auth::Auth::session_id(&token(&headers)?)?;
        let result = app.auth.logout_by_id(&id).await;
        app.hub
            .invalidate_session(&app, &id, "session_expired")
            .await?;
        let mut r = response(200, result?);
        r.headers_mut().insert(
            "Set-Cookie",
            HeaderValue::from_static(
                "ting_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
            ),
        );
        return Ok(r);
    }
    let p = app.auth.authenticate(&token(&headers)?, &headers).await?;
    if path == "me" && method == Method::GET {
        return Ok(response(200, app.auth.me(&p)?));
    }
    if path == "orgs" && method == Method::GET {
        return Ok(response(200, app.auth.orgs(&p).await?));
    }
    if path == "bugs" && method == Method::POST {
        return Ok(response(
            201,
            app.auth
                .report(
                    &p,
                    b,
                    headers
                        .get("Ting-Client-Version")
                        .and_then(|v| v.to_str().ok()),
                )
                .await?,
        ));
    }
    if parts.len() < 3 || parts[0] != "orgs" {
        return Err(Error::not_found());
    }
    let org = app.auth.org(&p, parts[1]).await?;
    let apps = match (method.as_str(), parts[2..].as_ref()) {
        ("GET", ["apps"]) => Some(app.auth.apps(&p, &org).await?),
        ("GET", ["apps", aid, "types"]) => {
            app.auth.permission(&p, &org, aid, false).await?;
            None
        }
        ("POST", ["apps", aid, "types"]) | ("PATCH", ["apps", aid, "types", _]) => {
            app.auth.permission(&p, &org, aid, true).await?;
            None
        }
        _ => None,
    };
    // ponytail: one lifecycle gate serializes store access; use per-environment gates if throughput requires it.
    let _gate = app.mutations.lock().await;
    app.auth.check_session(&p)?;
    let binding = format!("{}:{}:{}:{}", p.context, p.id, org, path);
    match (method.as_str(), parts[2..].as_ref()) {
        ("GET", ["apps"]) => {
            v::fields(&f, &["limit", "cursor"], &[])?;
            let value = apps.unwrap();
            let rows = value["items"].as_array().cloned().unwrap_or_default();
            Ok(response(200, app.store.page(rows, &binding, &f, false)?))
        }
        ("GET", ["apps", aid, "types"]) => {
            v::fields(&f, &["limit", "cursor"], &[])?;
            Ok(response(
                200,
                app.store
                    .page(app.store.types(&p, &org, aid)?, &binding, &f, false)?,
            ))
        }
        ("POST", ["apps", aid, "types"]) => {
            let (s, b) = app.store.register_type(&p, &org, aid, &b, false)?;
            Ok(response(s, b))
        }
        ("PATCH", ["apps", aid, "types", typ]) => {
            if v::type_parts(typ)?.0 != *aid {
                return Err(Error::not_found());
            }
            let (s, b) = app.store.register_type(&p, &org, typ, &b, true)?;
            Ok(response(s, b))
        }
        ("GET", ["subscriptions"]) => {
            v::fields(&f, &["app_id", "for", "limit", "cursor"], &[])?;
            if f.get("for").is_some_and(|x| x.as_str() != Some(&p.id)) {
                return Err(Error::not_found());
            }
            Ok(response(
                200,
                app.store.page(
                    app.store
                        .grants(&p.context, &org, Some(&p.id), f["app_id"].as_str())?,
                    &binding,
                    &f,
                    false,
                )?,
            ))
        }
        ("DELETE", ["subscriptions", sid]) => {
            let (out, recipient) = app.store.revoke(&p.context, &org, sid, Some(&p.id), None)?;
            app.hub
                .invalidate(&app, &p.context, &org, &recipient, "permission_changed")
                .await?;
            Ok(response(200, out))
        }
        ("GET", ["subscriptions", sid, "required-delivery"])
        | ("PUT", ["subscriptions", sid, "required-delivery"]) => {
            let enabled = if method == Method::PUT {
                v::fields(&b, &["enabled"], &["enabled"])?;
                Some(
                    v::optional_bool(&b, "enabled")?
                        .ok_or_else(|| Error::invalid("enabled must be a boolean."))?,
                )
            } else {
                v::fields(&f, &[], &[])?;
                None
            };
            let out = app.store.required_delivery(&p, &org, sid, enabled)?;
            if enabled.is_some() {
                app.hub
                    .invalidate(&app, &p.context, &org, &p.id, "preference_changed")
                    .await?;
                app.changed.notify_waiters();
            }
            Ok(response(200, out))
        }
        ("GET", ["inbox"]) => {
            v::fields(
                &f,
                &["app_id", "type", "read", "silent", "limit", "cursor"],
                &[],
            )?;
            let rows = app
                .store
                .tings(&p.context, &org, Some(&p.id), f["app_id"].as_str(), &f)?;
            Ok(response(200, app.store.page(rows, &binding, &f, true)?))
        }
        ("GET", ["inbox", mid]) => Ok(response(
            200,
            app.store.ting(&p.context, &org, mid, Some(&p.id), None)?,
        )),
        ("POST", ["inbox", "read"]) => {
            v::fields(&b, &["message_ids"], &["message_ids"])?;
            let (out, expired) = app
                .store
                .read(&p, &org, &v::ids(&b, "message_ids", false)?)?;
            if expired {
                app.hub
                    .invalidate(&app, &p.context, &org, &p.id, "preference_changed")
                    .await?;
            }
            app.hub.inbox_changed(&p.context, &org, &p.id).await;
            Ok(response(200, out))
        }
        ("GET", ["preferences"]) => {
            v::fields(&f, &["app_id", "service", "type", "limit", "cursor"], &[])?;
            if !f["service"].is_null() && !f["type"].is_null() {
                return Err(Error::invalid("Specify either service or type."));
            }
            Ok(response(
                200,
                app.store
                    .page(app.store.preferences(&p, &org, &f)?, &binding, &f, false)?,
            ))
        }
        ("PUT", ["preferences"]) | ("DELETE", ["preferences"]) => {
            let out = app.store.preference(
                &p,
                &org,
                if method == Method::DELETE { &f } else { &b },
                method == Method::DELETE,
            )?;
            app.hub
                .invalidate(&app, &p.context, &org, &p.id, "preference_changed")
                .await?;
            Ok(response(200, out))
        }
        ("GET", ["webhooks"]) => {
            v::fields(&f, &["limit", "cursor"], &[])?;
            Ok(response(
                200,
                app.store
                    .page(app.store.hooks(&p, &org)?, &binding, &f, false)?,
            ))
        }
        ("POST", ["webhooks"]) => {
            v::fields(&b, &["receiver_id"], &["receiver_id"])?;
            let recv = v::string(&b, "receiver_id", 255)?;
            let key = header(&headers, "Idempotency-Key")?;
            if let Some(old) = app.store.hook_retry(&p, &org, key, &b)? {
                return Ok(response(200, old));
            }
            app.hub.authorized(recv, &p, &org).await?;
            let out = app.store.create_hook(&p, &org, recv, key, &b)?;
            app.changed.notify_waiters();
            Ok(response(201, out))
        }
        ("PATCH", ["webhooks", hid]) => {
            v::fields(&b, &["receiver_id", "takeover"], &["receiver_id"])?;
            let recv = v::string(&b, "receiver_id", 255)?;
            let takeover = v::optional_bool(&b, "takeover")?.unwrap_or(false);
            app.hub.authorized(recv, &p, &org).await?;
            let replaced = app
                .store
                .bind(&p, &org, recv, &[hid.to_string()], true, takeover)?;
            app.hub
                .pause_replaced(replaced, &org, "binding_replaced")
                .await;
            app.changed.notify_waiters();
            let out = app
                .store
                .hooks(&p, &org)?
                .into_iter()
                .find(|x| x["id"] == *hid)
                .ok_or_else(Error::not_found)?;
            Ok(response(200, out))
        }
        ("DELETE", ["webhooks", hid]) => {
            if let Some(recv) = app.store.detach(&p, &org, hid)? {
                app.hub
                    .pause_replaced(vec![(recv, hid.to_string())], &org, "hook_detached")
                    .await;
            }
            Ok(response(200, json!({"id":hid,"removed":true})))
        }
        _ => Err(Error::not_found()),
    }
}
pub async fn app_call(
    app: &Shared,
    headers: &HeaderMap,
    path: &str,
    bytes: &[u8],
    b: &Value,
) -> Result<(u16, Value)> {
    v::filters(b)?;
    let p = app.auth.proof(headers, path, bytes).await?;
    v::string(b, "org_id", 255)?;
    let _gate = app.mutations.lock().await;
    app.auth.check_proof(&p)?;
    match path {
        "/v1/tings" => {
            let result = app.store.send(&p, b)?;
            if result.0 == 202 && !result.1["silent"].as_bool().unwrap_or(true) {
                app.hub
                    .inbox_changed(&p.context, &p.org_id, v::string(b, "for", 255)?)
                    .await;
            }
            app.changed.notify_waiters();
            Ok(result)
        }
        "/v1/subscriptions" => {
            let out = app.store.subscribe_app(&p, b)?;
            app.changed.notify_waiters();
            Ok(out)
        }
        "/v1/subscriptions/query" => {
            v::fields(
                b,
                &["org_id", "app_id", "for", "limit", "cursor"],
                &["org_id", "app_id"],
            )?;
            proof_app(&p, b)?;
            let rows =
                app.store
                    .grants(&p.context, &p.org_id, b["for"].as_str(), Some(&p.app_id))?;
            Ok((
                200,
                app.store.page(
                    rows,
                    &format!("{}:{}:{}:subscriptions", p.context, p.org_id, p.app_id),
                    b,
                    false,
                )?,
            ))
        }
        "/v1/subscriptions/revoke" => {
            v::fields(b, &["org_id", "id"], &["org_id", "id"])?;
            let (out, recipient) = app.store.revoke(
                &p.context,
                &p.org_id,
                v::string(b, "id", 255)?,
                None,
                Some(&p.app_id),
            )?;
            app.hub
                .invalidate(app, &p.context, &p.org_id, &recipient, "permission_changed")
                .await?;
            Ok((200, out))
        }
        "/v1/sent/query" => {
            proof_app(&p, b)?;
            let binding = format!("{}:{}:{}:sent", p.context, p.org_id, p.app_id);
            if b.get("id").is_some() {
                v::fields(
                    b,
                    &["org_id", "app_id", "id", "deliveries_cursor"],
                    &["org_id", "app_id", "id"],
                )?;
                let mid = v::string(b, "id", 255)?;
                let mut t = app
                    .store
                    .ting(&p.context, &p.org_id, mid, None, Some(&p.app_id))?;
                let mut f = json!({"limit":100});
                if let Some(c) = b.get("deliveries_cursor") {
                    f["cursor"] = c.clone()
                }
                let page = app.store.page(
                    app.store.deliveries(mid)?,
                    &format!("{binding}:{mid}:deliveries"),
                    &f,
                    false,
                )?;
                t["deliveries"] = page["items"].clone();
                if let Some(c) = page.get("next_cursor") {
                    t["deliveries_next_cursor"] = c.clone()
                }
                Ok((200, t))
            } else {
                v::fields(
                    b,
                    &["org_id", "app_id", "for", "type", "read", "limit", "cursor"],
                    &["org_id", "app_id"],
                )?;
                v::optional_bool(b, "read")?;
                let rows = app.store.tings(
                    &p.context,
                    &p.org_id,
                    b["for"].as_str(),
                    Some(&p.app_id),
                    b,
                )?;
                Ok((200, app.store.page(rows, &binding, b, true)?))
            }
        }
        _ => Err(Error::not_found()),
    }
}
fn proof_app(p: &auth::Proof, b: &Value) -> Result<()> {
    if v::string(b, "app_id", 255)? != p.app_id {
        return Err(Error::new(
            403,
            "permission_denied",
            "The app must match the verified proof issuer.",
            "Prepare a request for the issuing app.",
        ));
    }
    Ok(())
}
fn browser_login(app: &App, f: &Value) -> Result<Response> {
    v::fields(f, &["next"], &[])?;
    let next = f.get("next").and_then(Value::as_str).unwrap_or("/");
    if !next.starts_with('/')
        || next.starts_with("//")
        || next.contains('\\')
        || next.chars().any(char::is_control)
    {
        return Err(Error::invalid("next must be a local absolute path."));
    }
    let state = app.store.login_attempt(next)?;
    let mut callback =
        url::Url::parse(&format!("{}/v1/session/callback", app.config.public_origin))
            .map_err(|_| Error::unavailable("Invalid callback configuration."))?;
    callback.query_pairs_mut().append_pair("state", &state);
    let mut target = url::Url::parse(
        &env::var("TING_IAM_CONSENT_URL")
            .unwrap_or_else(|_| "https://iam.teamofsilicons.com/login".into()),
    )
    .map_err(|_| Error::unavailable("Invalid IAM consent configuration."))?;
    target
        .query_pairs_mut()
        .append_pair("app_id", &app.config.iam_app_id)
        .append_pair("redirect_uri", callback.as_str());
    let mut r = StatusCode::FOUND.into_response();
    r.headers_mut().insert(
        "Location",
        HeaderValue::from_str(target.as_str())
            .map_err(|_| Error::invalid("Invalid login redirect."))?,
    );
    r.headers_mut().insert(
        "Set-Cookie",
        HeaderValue::from_str(&format!(
            "ting_login={state}; Path=/v1/session; HttpOnly; Secure; SameSite=Lax; Max-Age=600"
        ))
        .unwrap(),
    );
    Ok(r)
}
async fn browser_callback(app: &App, h: &HeaderMap, f: &Value) -> Result<Response> {
    v::fields(f, &["slt", "state"], &["slt", "state"])?;
    let state = v::string(f, "state", 255)?;
    if cookie(h, "ting_login").as_deref() != Some(state) {
        return Err(Error::new(
            403,
            "permission_denied",
            "The login callback does not belong to this browser.",
            "Start a new login from Ting.",
        ));
    }
    let next = app.store.take_login_attempt(state)?;
    let (_, session) = app
        .auth
        .login(v::string(f, "slt", 16384)?, state, &HeaderMap::new())
        .await?;
    let token = session["session_token"]
        .as_str()
        .ok_or_else(|| Error::unavailable("IAM session exchange returned no session."))?;
    let mut r = StatusCode::SEE_OTHER.into_response();
    r.headers_mut().insert(
        "Location",
        HeaderValue::from_str(&next).map_err(|_| Error::invalid("Invalid redirect path."))?,
    );
    r.headers_mut().append(
        "Set-Cookie",
        HeaderValue::from_str(&format!(
            "ting_session={token}; Path=/; HttpOnly; Secure; SameSite=Lax"
        ))
        .map_err(|_| Error::unavailable("Invalid session response."))?,
    );
    r.headers_mut().append(
        "Set-Cookie",
        HeaderValue::from_static(
            "ting_login=; Path=/v1/session; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        ),
    );
    Ok(r)
}
async fn upgrade(
    State(app): State<Shared>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    let f = query(raw)?;
    v::fields(&f, &["protocol"], &["protocol"])?;
    if f["protocol"] != "v1" {
        return Err(Error::new(
            400,
            "unsupported_protocol",
            "Unsupported WebSocket protocol.",
            "Use protocol=v1.",
        )
        .details(json!({"supported_protocols":["v1"]})));
    }
    let browser = if headers.contains_key("origin") {
        Some(app.auth.authenticate(&token(&headers)?, &headers).await?)
    } else {
        None
    };
    Ok(ws
        .max_message_size(1024 * 1024)
        .max_frame_size(1024 * 1024)
        .on_upgrade(move |socket| ws::connection(app, socket, browser)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    #[test]
    fn browser_origins_require_explicit_secure_hosts() {
        assert_eq!(browser_origins("").unwrap(), Vec::<String>::new());
        assert_eq!(
            browser_origins(" https://dm.example:443/, http://[::1]:5173 ").unwrap(),
            ["https://dm.example", "http://[::1]:5173"]
        );
        for invalid in [
            "*",
            "https://*.example",
            "null",
            "https://",
            "http://dm.example",
            "https://dm.example/path",
            "https://user@dm.example",
            "https://dm.example?x",
            "https://dm.example#x",
            "https://dm.example,",
        ] {
            assert!(browser_origins(invalid).is_err(), "{invalid}");
        }
    }

    #[tokio::test]
    async fn browser_http_and_websocket_share_origin_policy() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config {
            database_path: directory
                .path()
                .join("ting.sqlite")
                .to_string_lossy()
                .into_owned(),
            encryption_key: "ab".repeat(32),
            iam_url: "http://127.0.0.1:1".into(),
            iam_app_id: "ting".into(),
            iam_app_secret: "fixture-secret".into(),
            honeycomb_url: "http://127.0.0.1:1".into(),
            spacestation_url: "http://127.0.0.1:1".into(),
            spacestation_key: String::new(),
            spacestation_table: String::new(),
            frontend_origin: "https://ting.example".into(),
            public_origin: "https://backend.ting.example".into(),
            browser_origins: browser_origins("https://dm.example,https://interface.example")
                .unwrap(),
            repository_url: String::new(),
            docs_url: String::new(),
            rust_package: String::new(),
        };
        let app = Arc::new(App {
            auth: auth::Auth::new(&config).unwrap(),
            store: store::Store::open(&config.database_path).unwrap(),
            config,
            hub: ws::Hub::default(),
            changed: Notify::new(),
            mutations: Mutex::new(()),
        });
        let router = router(app);
        for origin in [
            "https://ting.example",
            "https://backend.ting.example",
            "https://dm.example",
            "https://interface.example",
        ] {
            for (method, path, cookie, body, status) in [
                ("GET", "/v1/iam", false, "", 200),
                ("OPTIONS", "/v1/me", false, "", 204),
                ("GET", "/v1/me", false, "", 401),
                ("DELETE", "/v1/session", true, "", 401),
                ("POST", "/v1/session", false, "{", 400),
                ("GET", "/missing", false, "", 404),
            ] {
                let mut request = Request::builder()
                    .method(method)
                    .uri(path)
                    .header("Origin", origin)
                    .header("Content-Type", "application/json");
                if cookie {
                    request = request.header("Cookie", "ting_session=invalid");
                }
                let response = router
                    .clone()
                    .oneshot(request.body(Body::from(body)).unwrap())
                    .await
                    .unwrap();
                assert_eq!(response.status().as_u16(), status, "{method} {path}");
                assert_eq!(response.headers()["Access-Control-Allow-Origin"], origin);
                assert_eq!(
                    response.headers()["Access-Control-Allow-Credentials"],
                    "true"
                );
                assert_eq!(
                    response.headers()["Access-Control-Expose-Headers"],
                    "Ting-Request-Id"
                );
                assert_eq!(response.headers()["Vary"], "Origin");
                assert!(response.headers().contains_key("Ting-Request-Id"));
                if method == "OPTIONS" {
                    assert!(
                        response.headers()["Access-Control-Allow-Methods"]
                            .to_str()
                            .unwrap()
                            .contains("DELETE")
                    );
                    assert!(
                        response.headers()["Access-Control-Allow-Headers"]
                            .to_str()
                            .unwrap()
                            .contains("Authorization")
                    );
                }
            }
        }
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/session")
                    .header("Origin", "https://dm.example")
                    .header("Content-Type", "application/json")
                    .body(Body::from(vec![b'x'; 1024 * 1024 + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response.headers()["Access-Control-Allow-Origin"],
            "https://dm.example"
        );
        for origin in [
            "https://dm.example.attacker.test",
            "null",
            "https://dm.example/",
        ] {
            for method in ["GET", "OPTIONS"] {
                let response = router
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri("/v1/iam")
                            .header("Origin", origin)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert!(
                    !response
                        .headers()
                        .contains_key("Access-Control-Allow-Origin")
                );
            }
        }
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/iam")
                    .header("Origin", "https://dm.example")
                    .header("Origin", "https://dm.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/session")
                    .header("Cookie", "ting_session=invalid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            !response
                .headers()
                .contains_key("Access-Control-Allow-Origin")
        );
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/iam")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !response
                .headers()
                .contains_key("Access-Control-Allow-Origin")
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/ws?protocol=v1", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        use tokio_tungstenite::tungstenite::{Error as WsError, client::IntoClientRequest};
        for (origin, status) in [
            ("https://dm.example", 401),
            ("https://interface.example", 401),
            ("https://attacker.test", 403),
        ] {
            let mut request = url.clone().into_client_request().unwrap();
            request
                .headers_mut()
                .insert("Origin", HeaderValue::from_static(origin));
            let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
            let WsError::Http(response) = error else {
                panic!("expected HTTP rejection: {error}")
            };
            assert_eq!(response.status().as_u16(), status);
        }
        server.abort();
    }
}
