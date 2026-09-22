use crate::{
    Shared,
    auth::Principal,
    error::{Error, Result},
    store, validation as v,
};
use axum::{
    extract::ws::{Message, WebSocket},
    http::{HeaderMap, HeaderName, HeaderValue},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, mpsc, watch};

const CONTROL_QUEUE_CAPACITY: usize = 64;
const WRITE_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Default)]
pub struct Hub {
    receivers: RwLock<HashMap<String, Receiver>>,
}
struct Receiver {
    tx: mpsc::Sender<Value>,
    disconnect: watch::Sender<bool>,
    auth: Vec<(Principal, String)>,
    watch: Option<(Principal, String)>,
}
impl Receiver {
    fn send(&self, value: Value) {
        if !*self.disconnect.borrow() && self.tx.try_send(value).is_err() {
            // A missed pause must terminate the connection, never leave it forwarding.
            self.disconnect.send_replace(true);
        }
    }
}
impl Hub {
    pub async fn authorized(&self, r: &str, p: &Principal, org: &str) -> Result<()> {
        let map = self.receivers.read().await;
        let receiver = map
            .get(r)
            .filter(|r| !*r.disconnect.borrow())
            .ok_or_else(|| {
                Error::new(
                    409,
                    "receiver_gone",
                    "The receiver connection is no longer available.",
                    "Authenticate on the current connection before creating or reattaching a hook.",
                )
            })?;
        if !receiver.auth.iter().any(|(a, o)| {
            a.session == p.session && a.context == p.context && a.id == p.id && o == org
        }) {
            return Err(Error::new(
                403,
                "permission_denied",
                "The receiver has not authenticated this session and org.",
                "Send subscribe with an empty webhook list first.",
            ));
        }
        Ok(())
    }
    pub async fn pause_replaced(&self, rows: Vec<(String, String)>, org: &str, reason: &str) {
        let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
        for (r, h) in rows {
            grouped.entry(r).or_default().push(h)
        }
        let map = self.receivers.read().await;
        for (r, hooks) in grouped {
            if let Some(r) = map.get(&r) {
                for chunk in hooks.chunks(100) {
                    r.send(json!({"op":"paused","org_id":org,"webhook_ids":chunk,"reason":reason}));
                }
            }
        }
    }
    pub async fn invalidate(
        &self,
        app: &Shared,
        ctx: &str,
        org: &str,
        recipient: &str,
        reason: &str,
    ) -> Result<()> {
        let rows = app.store.invalidate(ctx, org, recipient)?;
        self.pause_replaced(rows, org, reason).await;
        Ok(())
    }
    pub async fn invalidate_session(
        &self,
        app: &Shared,
        session: &str,
        reason: &str,
    ) -> Result<()> {
        let matches: Vec<(Principal, String)> = {
            let map = self.receivers.read().await;
            map.values()
                .flat_map(|r| r.auth.iter().chain(r.watch.iter()))
                .filter(|(p, _)| p.session == session)
                .cloned()
                .collect()
        };
        for (p, org) in matches {
            self.invalidate(app, &p.context, &org, &p.id, reason)
                .await?
        }
        let mut map = self.receivers.write().await;
        for r in map.values_mut() {
            r.auth.retain(|(p, _)| p.session != session);
            if r.watch.as_ref().is_some_and(|(p, _)| p.session == session) {
                let (_, org) = r.watch.take().unwrap();
                r.send(json!({"op":"paused","org_id":org,"webhook_ids":[],"reason":reason}));
            }
        }
        Ok(())
    }
    pub async fn inbox_changed(&self, ctx: &str, org: &str, recipient: &str) {
        let map = self.receivers.read().await;
        for r in map.values() {
            if r.watch
                .as_ref()
                .is_some_and(|(p, o)| p.context == ctx && p.id == recipient && o == org)
            {
                r.send(json!({"op":"inbox_changed","org_id":org}));
            }
        }
    }
}
fn headers(v: &Value) -> Result<HeaderMap> {
    let mut out = HeaderMap::new();
    if let Some(h) = v.get("headers") {
        v::fields(
            h,
            &["IAM_TEST_APP_SECRET", "X-Testing-Environment-Key"],
            &[],
        )?;
        for (k, value) in h.as_object().unwrap() {
            let val = value
                .as_str()
                .ok_or_else(|| Error::invalid("Test headers must be strings."))?;
            out.insert(
                HeaderName::from_bytes(k.as_bytes())
                    .map_err(|_| Error::invalid("Invalid header."))?,
                HeaderValue::from_str(val).map_err(|_| Error::invalid("Invalid header value."))?,
            );
        }
    }
    Ok(out)
}
fn err(request: Option<&str>, e: Error) -> Value {
    json!({"op":"error","request_id":request,"error":e.body["error"]})
}
async fn handle(app: &Shared, rid: &str, b: &Value, browser: Option<&Principal>) -> Result<Value> {
    let request = v::string(b, "request_id", 100)?;
    let op = v::string(b, "op", 100)?;
    let mut response = match op {
        "send" => {
            v::fields(
                b,
                &["op", "request_id", "proof_token", "body", "headers"],
                &["op", "request_id", "proof_token", "body"],
            )?;
            let mut h = headers(b)?;
            h.insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {}", v::string(b, "proof_token", 32768)?))
                    .map_err(|_| Error::invalid("Invalid proof header."))?,
            );
            let raw = b["body"]
                .as_str()
                .ok_or_else(|| Error::invalid("body must be the exact prepared JSON string."))?
                .as_bytes();
            let body = v::parse(raw, 256 * 1024)?;
            let (_, mut result) = crate::app_call(app, &h, "/v1/tings", raw, &body).await?;
            result["op"] = "accepted".into();
            result
        }
        "subscribe" => {
            v::fields(
                b,
                &[
                    "op",
                    "request_id",
                    "org_id",
                    "session_token",
                    "webhook_ids",
                    "headers",
                ],
                &["op", "request_id", "org_id", "session_token", "webhook_ids"],
            )?;
            let p = app
                .auth
                .authenticate(v::string(b, "session_token", 32768)?, &headers(b)?)
                .await?;
            let org = app.auth.org(&p, v::string(b, "org_id", 255)?).await?;
            let ids = v::ids(b, "webhook_ids", true)?;
            let _gate = app.mutations.lock().await;
            app.auth.check_session(&p)?;
            let replaced = app.store.bind(&p, &org, rid, &ids, false, false)?;
            app.hub
                .pause_replaced(replaced, &org, "binding_replaced")
                .await;
            let mut map = app.hub.receivers.write().await;
            let r = map.get_mut(rid).ok_or_else(Error::not_found)?;
            r.auth
                .retain(|(q, o)| !(q.context == p.context && q.id == p.id && o == &org));
            r.auth.push((p.clone(), org));
            app.changed.notify_waiters();
            json!({"op":"subscribed","for":p.id,"webhook_ids":ids})
        }
        "watch_inbox" => {
            v::fields(
                b,
                &["op", "request_id", "org_id", "session_token"],
                &["op", "request_id", "org_id"],
            )?;
            let p = if let Some(p) = browser {
                app.auth.revalidate(p).await?
            } else {
                app.auth
                    .authenticate(v::string(b, "session_token", 32768)?, &HeaderMap::new())
                    .await?
            };
            let org = app.auth.org(&p, v::string(b, "org_id", 255)?).await?;
            let _gate = app.mutations.lock().await;
            app.auth.check_session(&p)?;
            let mut map = app.hub.receivers.write().await;
            let r = map.get_mut(rid).ok_or_else(Error::not_found)?;
            r.watch = Some((p, org.clone()));
            json!({"op":"watching_inbox","org_id":org})
        }
        "unsubscribe" | "ack" => {
            if op == "ack" {
                v::fields(
                    b,
                    &[
                        "op",
                        "request_id",
                        "org_id",
                        "webhook_id",
                        "message_ids",
                        "kind",
                    ],
                    &[
                        "op",
                        "request_id",
                        "org_id",
                        "webhook_id",
                        "message_ids",
                        "kind",
                    ],
                )?
            } else {
                v::fields(
                    b,
                    &["op", "request_id", "org_id", "webhook_ids", "pause"],
                    &["op", "request_id", "org_id", "webhook_ids"],
                )?
            }
            let requested = v::string(b, "org_id", 255)?;
            let ids = if op == "ack" {
                vec![v::string(b, "webhook_id", 255)?.to_string()]
            } else {
                v::ids(b, "webhook_ids", false)?
            };
            let active = app.store.active_hooks(rid)?;
            let mut canonical = None;
            let mut principals = vec![];
            for hid in &ids {
                let (_, context, org, owner, session) = active
                    .iter()
                    .find(|(h, _, _, _, _)| h == hid)
                    .ok_or_else(Error::not_found)?;
                let (p, org2) = app
                    .auth
                    .authenticate_session_org(session, requested)
                    .await?;
                if org != &org2 || context != &p.context || owner != &p.id {
                    return Err(Error::not_found());
                }
                canonical = Some(org2);
                principals.push(p);
            }
            let org = canonical.ok_or_else(Error::not_found)?;
            let _gate = app.mutations.lock().await;
            for principal in &principals {
                app.auth.check_session(principal)?;
            }
            if op == "ack" {
                let message_ids = v::ids(b, "message_ids", false)?;
                let kind = v::string(b, "kind", 16)?;
                let (ctx, owner, expired) =
                    app.store.ack(rid, &org, &ids[0], &message_ids, kind)?;
                if expired {
                    app.hub
                        .invalidate(app, &ctx, &org, &owner, "preference_changed")
                        .await?;
                }
                if kind == "read" {
                    app.hub.inbox_changed(&ctx, &org, &owner).await;
                    app.changed.notify_waiters();
                }
                json!({"op":"acked","message_ids":message_ids,"webhook_id":ids[0],"kind":kind})
            } else {
                app.store.unsubscribe(
                    rid,
                    &org,
                    &ids,
                    v::optional_bool(b, "pause")?.unwrap_or(false),
                )?;
                json!({"op":"unsubscribed","webhook_ids":ids})
            }
        }
        _ => return Err(Error::invalid("Unknown WebSocket operation.")),
    };
    response["request_id"] = request.into();
    Ok(response)
}
async fn validate_authority(app: &Shared, rid: &str) -> Result<()> {
    let (auth, watch) = {
        let map = app.hub.receivers.read().await;
        let Some(r) = map.get(rid) else { return Ok(()) };
        (r.auth.clone(), r.watch.clone())
    };
    for (p, org) in auth.iter().chain(watch.iter()) {
        let valid = app.auth.org(p, org).await;
        if let Err(e) = valid {
            let reason = if e.status == 401 {
                "session_expired"
            } else if e.status == 403 {
                "permission_changed"
            } else {
                "authorization_unavailable"
            };
            let _gate = app.mutations.lock().await;
            let rows: Vec<_> = app
                .store
                .active_hooks(rid)?
                .into_iter()
                .filter(|(_, ctx, o, u, s)| {
                    ctx == &p.context && o == org && u == &p.id && s == &p.session
                })
                .map(|(h, _, _, _, _)| h)
                .collect();
            if !rows.is_empty() {
                app.store.unsubscribe(rid, org, &rows, false)?;
                app.hub
                    .pause_replaced(
                        rows.into_iter().map(|h| (rid.to_owned(), h)).collect(),
                        org,
                        reason,
                    )
                    .await;
            }
            let mut map = app.hub.receivers.write().await;
            if let Some(r) = map.get_mut(rid) {
                r.auth
                    .retain(|(q, o)| !(q.session == p.session && o == org));
                if r.watch
                    .as_ref()
                    .is_some_and(|(q, o)| q.session == p.session && o == org)
                {
                    r.watch = None;
                    r.send(json!({"op":"paused","org_id":org,"webhook_ids":[],"reason":reason}));
                }
            }
        }
    }
    Ok(())
}
async fn offer(app: &Shared, rid: &str) -> Result<Vec<Value>> {
    let _gate = app.mutations.lock().await;
    let mut out = vec![];
    for (h, _, _, _, _) in app.store.active_hooks(rid)? {
        if let Some(v) = app.store.offer(rid, &h)? {
            out.push(v)
        }
    }
    Ok(out)
}
async fn send(socket: &mut WebSocket, message: Message) -> bool {
    matches!(
        tokio::time::timeout(WRITE_DEADLINE, socket.send(message)).await,
        Ok(Ok(()))
    )
}
pub async fn connection(app: Shared, mut socket: WebSocket, browser: Option<Principal>) {
    let rid = store::id("recv");
    let (tx, mut rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
    let (disconnect, mut disconnected) = watch::channel(false);
    app.hub.receivers.write().await.insert(
        rid.clone(),
        Receiver {
            tx,
            disconnect,
            auth: vec![],
            watch: None,
        },
    );
    tokio::select! {
        biased;
        _ = disconnected.changed() => {},
        _ = async {
            let greeting = json!({"op":"ready","receiver_id":rid,"protocol":"v1"});
            if !send(&mut socket, Message::Text(greeting.to_string().into())).await {
                return;
            }
            let mut delivery = tokio::time::interval(Duration::from_secs(1));
            delivery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut revalidate = tokio::time::interval(Duration::from_secs(30));
            revalidate.tick().await;
            let mut ping = tokio::time::interval(Duration::from_secs(1));
            let mut last_ping = Instant::now();
            let mut awaiting: Option<Instant> = None;
            // Retain notifications received while another selected branch awaits IAM or I/O.
            let changed = app.changed.notified();
            tokio::pin!(changed);
            'connected: loop {
                tokio::select! {
                    incoming = socket.recv() => match incoming {
                        Some(Ok(Message::Text(text))) => {
                            let reply = match v::parse(text.as_bytes(), 1024 * 1024) {
                                Ok(b) => {
                                    let request = b["request_id"].as_str();
                                    match tokio::time::timeout(Duration::from_secs(30), handle(&app, &rid, &b, browser.as_ref())).await {
                                        Ok(Ok(reply)) => reply,
                                        Ok(Err(e)) => err(request, e),
                                        Err(_) => err(request, Error::unavailable("The operation timed out; its result may be uncertain.")),
                                    }
                                }
                                Err(e) => err(None, e),
                            };
                            if !send(&mut socket, Message::Text(reply.to_string().into())).await { break; }
                        }
                        Some(Ok(Message::Ping(b))) => {
                            if !send(&mut socket, Message::Pong(b)).await { break; }
                        }
                        Some(Ok(Message::Pong(_))) => awaiting = None,
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                        Some(Ok(Message::Binary(_))) => {
                            send(&mut socket, Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: 1003, reason: "JSON text frames required".into(),
                            }))).await;
                            break;
                        }
                    },
                    Some(value) = rx.recv() => {
                        if !send(&mut socket, Message::Text(value.to_string().into())).await { break; }
                    }
                    _ = &mut changed => {
                        changed.set(app.changed.notified());
                        match offer(&app, &rid).await {
                            Ok(values) => for value in values {
                                if !send(&mut socket, Message::Text(value.to_string().into())).await { break 'connected; }
                            },
                            Err(_) => break,
                        }
                    }
                    _ = delivery.tick() => {
                        match offer(&app, &rid).await {
                            Ok(values) => for value in values {
                                if !send(&mut socket, Message::Text(value.to_string().into())).await { break 'connected; }
                            },
                            Err(_) => break,
                        }
                    }
                    _ = revalidate.tick() => {
                        if validate_authority(&app, &rid).await.is_err() { break; }
                    }
                    _ = ping.tick() => {
                        if awaiting.is_some_and(|t| t.elapsed() > Duration::from_secs(10)) { break; }
                        if last_ping.elapsed() >= Duration::from_secs(30) && awaiting.is_none() {
                            if !send(&mut socket, Message::Ping(vec![1].into())).await { break; }
                            let now = Instant::now();
                            last_ping = now;
                            awaiting = Some(now);
                        }
                    }
                }
            }
        } => {},
    }
    // Drop transport before waiting on shared state; a lost pause closes promptly.
    drop(socket);
    let _gate = app.mutations.lock().await;
    app.hub.receivers.write().await.remove(&rid);
    let _ = app.store.release_receiver(&rid);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::tests::fixture;
    use futures_util::{SinkExt, StreamExt};
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn acks_use_one_fresh_snapshot_and_rejections_do_not_mutate() {
        for testing in [false, true] {
            let f = fixture(testing).await;
            let hook = f.hook("receiver");
            let message = f.send("ack-fixture");
            f.app.store.offer("receiver", &hook).unwrap().unwrap();
            let mut ack = json!({"op":"ack","request_id":"ack","org_id":"tos","webhook_id":hook,"message_ids":[message],"kind":"delivery"});
            let good = f.iam.reply.lock().unwrap().clone();
            let mut cases = vec![];
            for (field, value, expected) in [
                ("active", json!(false), 401),
                ("authorization", Value::Null, 403),
                ("public_id", json!("si_other"), 401),
                ("actor_type", json!("carbon"), 401),
                ("client_id", json!("tos>other"), 401),
            ] {
                let mut reply = good.clone();
                reply[field] = value;
                cases.push((reply, 200, expected));
            }
            let mut context = good.clone();
            context["authorization"]["testing_environment_id"] =
                uuid::Uuid::new_v4().to_string().into();
            cases.push((context, 200, 403));
            cases.push((
                json!({"error":{"code":"unavailable","message":"fixture unavailable"}}),
                503,
                503,
            ));
            for (reply, status, expected) in cases {
                *f.iam.reply.lock().unwrap() = reply;
                f.iam.status.store(status, Ordering::SeqCst);
                assert_eq!(
                    handle(&f.app, "receiver", &ack, None)
                        .await
                        .unwrap_err()
                        .status,
                    expected
                );
                assert_eq!(f.receipt(&hook, &message), (0, 0));
                let calls = f.take_calls();
                let expected_calls = if testing && status == 200 {
                    vec![
                        "/api/v1/application/testing-context",
                        "/api/v1/oauth/introspect",
                    ]
                } else if testing {
                    vec!["/api/v1/application/testing-context"]
                } else {
                    vec!["/api/v1/oauth/introspect"]
                };
                assert_eq!(calls, expected_calls);
            }
            *f.iam.reply.lock().unwrap() = good;
            f.iam.status.store(200, Ordering::SeqCst);
            for kind in ["delivery", "read"] {
                ack["kind"] = kind.into();
                assert_eq!(
                    handle(&f.app, "receiver", &ack, None).await.unwrap()["op"],
                    "acked"
                );
                assert_eq!(
                    f.receipt(&hook, &message),
                    if kind == "delivery" { (1, 0) } else { (1, 1) }
                );
                assert_eq!(
                    f.take_calls(),
                    if testing {
                        vec![
                            "/api/v1/application/testing-context",
                            "/api/v1/oauth/introspect",
                        ]
                    } else {
                        vec!["/api/v1/oauth/introspect"]
                    }
                );
            }
        }
    }

    #[tokio::test]
    async fn periodic_authority_uses_one_snapshot_and_revocation_still_pauses() {
        let f = fixture(true).await;
        let hook = f.hook("receiver");
        let message = f.send("periodic-fixture");
        f.app.store.offer("receiver", &hook).unwrap().unwrap();
        let (tx, mut rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
        let (disconnect, _) = watch::channel(false);
        f.app.hub.receivers.write().await.insert(
            "receiver".into(),
            Receiver {
                tx,
                disconnect,
                auth: vec![(f.principal.clone(), f.proof.org_id.clone())],
                watch: None,
            },
        );
        validate_authority(&f.app, "receiver").await.unwrap();
        assert_eq!(
            f.take_calls(),
            vec![
                "/api/v1/application/testing-context",
                "/api/v1/oauth/introspect"
            ]
        );
        for field in ["id", "context", "kind"] {
            let mut principal = f.principal.clone();
            match field {
                "id" => principal.id = "si_other".into(),
                "context" => principal.context = "other".into(),
                _ => principal.kind = "carbon".into(),
            }
            assert_eq!(
                f.app.auth.org(&principal, "tos").await.unwrap_err().status,
                401
            );
            assert_eq!(
                f.take_calls(),
                vec![
                    "/api/v1/application/testing-context",
                    "/api/v1/oauth/introspect"
                ]
            );
            assert_eq!(f.receipt(&hook, &message), (0, 0));
        }
        f.iam.reply.lock().unwrap()["active"] = false.into();
        validate_authority(&f.app, "receiver").await.unwrap();
        assert_eq!(
            f.take_calls(),
            vec![
                "/api/v1/application/testing-context",
                "/api/v1/oauth/introspect"
            ]
        );
        assert_eq!(rx.recv().await.unwrap()["reason"], "session_expired");
        assert!(f.app.store.active_hooks("receiver").unwrap().is_empty());
        assert!(f.app.store.offer("receiver", &hook).unwrap().is_none());
        assert_eq!(f.receipt(&hook, &message), (0, 0));
    }

    async fn ws_json<S>(socket: &mut tokio_tungstenite::WebSocketStream<S>) -> Value
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        serde_json::from_str(socket.next().await.unwrap().unwrap().to_text().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn delivery_notification_survives_an_awaiting_ack_handler() {
        use axum::{
            Router,
            extract::{State, WebSocketUpgrade},
            routing::get,
        };
        use tokio_tungstenite::tungstenite::Message as ClientMessage;
        let f = fixture(false).await;
        async fn upgrade(
            State(app): State<Shared>,
            ws: WebSocketUpgrade,
        ) -> axum::response::Response {
            ws.on_upgrade(move |socket| connection(app, socket, None))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/v1/ws", listener.local_addr().unwrap());
        let app = f.app.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().route("/v1/ws", get(upgrade)).with_state(app),
            )
            .await
            .unwrap();
        });
        let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        let ready = ws_json(&mut socket).await;
        let started = tokio::time::Instant::now();
        let receiver = ready["receiver_id"].as_str().unwrap();
        let hook = f.hook(receiver);
        socket.send(ClientMessage::Text(json!({"op":"subscribe","request_id":"subscribe","org_id":"tos","session_token":f.token,"webhook_ids":[hook]}).to_string().into())).await.unwrap();
        assert_eq!(ws_json(&mut socket).await["op"], "subscribed");
        let first = f.send("before-block");
        f.app.changed.notify_waiters();
        assert_eq!(ws_json(&mut socket).await["tings"][0]["id"], first);
        // Enter just after a fallback tick, leaving almost one second before the next.
        let period = Duration::from_secs(1);
        let elapsed = started.elapsed();
        let next = period.mul_f64((elapsed.as_secs_f64() / period.as_secs_f64()).floor() + 1.0)
            + Duration::from_millis(50);
        tokio::time::sleep_until(started + next).await;
        f.iam.block_next.store(true, Ordering::SeqCst);
        socket.send(ClientMessage::Text(json!({"op":"ack","request_id":"read","org_id":"tos","webhook_id":hook,"message_ids":[first],"kind":"read"}).to_string().into())).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), f.iam.blocked.notified())
            .await
            .unwrap();
        let second = f.send("during-block");
        f.app.changed.notify_waiters();
        f.iam.release.notify_one();
        let delivery = tokio::time::timeout(Duration::from_millis(500), async {
            assert_eq!(ws_json(&mut socket).await["op"], "acked");
            ws_json(&mut socket).await
        })
        .await
        .expect("committed delivery must not wait for the one-second fallback");
        assert_eq!(delivery["op"], "tings");
        assert_eq!(delivery["tings"][0]["id"], second);
        socket.close(None).await.unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn full_control_queue_closes_instead_of_losing_a_pause() {
        let (tx, mut rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
        let (disconnect, mut disconnected) = watch::channel(false);
        let receiver = Receiver {
            tx,
            disconnect,
            auth: vec![],
            watch: None,
        };
        for i in 0..CONTROL_QUEUE_CAPACITY {
            receiver.send(json!({"op":"inbox_changed","sequence":i}));
        }
        assert!(!*disconnected.borrow());
        receiver.send(json!({"op":"paused","reason":"permission_changed"}));
        tokio::time::timeout(Duration::from_millis(100), disconnected.changed())
            .await
            .unwrap()
            .unwrap();
        assert!(*disconnected.borrow());
        assert_eq!(rx.len(), CONTROL_QUEUE_CAPACITY);
        assert_eq!(rx.recv().await.unwrap()["sequence"], 0);
        // Once overflow makes a connection terminal, freeing capacity cannot resume it.
        receiver.send(json!({"op":"inbox_changed"}));
        assert_eq!(rx.len(), CONTROL_QUEUE_CAPACITY - 1);
    }
}
