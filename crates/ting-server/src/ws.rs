use crate::{
    Shared,
    auth::Principal,
    error::{Error, Result},
    store, validation as v,
};
use axum::{
    extract::ws::{Message, WebSocket},
    http::{HeaderMap, HeaderValue},
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
    auth: Vec<Principal>,
    watch: Option<Principal>,
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
    pub async fn authorized(&self, r: &str, p: &Principal) -> Result<()> {
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
        if !receiver
            .auth
            .iter()
            .any(|a| a.session == p.session && a.context == p.context && a.id == p.id)
        {
            return Err(Error::new(
                403,
                "permission_denied",
                "The receiver has not authenticated this account session.",
                "Send subscribe with an empty webhook list first.",
            ));
        }
        Ok(())
    }
    pub async fn pause_replaced(&self, rows: Vec<(String, String)>, reason: &str) {
        let mut grouped: HashMap<String, Vec<String>> = HashMap::new();
        for (r, h) in rows {
            grouped.entry(r).or_default().push(h)
        }
        let map = self.receivers.read().await;
        for (r, hooks) in grouped {
            if let Some(r) = map.get(&r) {
                for chunk in hooks.chunks(100) {
                    r.send(json!({"op":"paused","webhook_ids":chunk,"reason":reason}));
                }
            }
        }
    }
    pub async fn invalidate(
        &self,
        app: &Shared,
        ctx: &str,
        recipient: &str,
        reason: &str,
    ) -> Result<()> {
        let rows = app.store.invalidate(ctx, recipient)?;
        self.pause_replaced(rows, reason).await;
        Ok(())
    }
    pub async fn invalidate_session(
        &self,
        app: &Shared,
        session: &str,
        reason: &str,
    ) -> Result<()> {
        let mut map = self.receivers.write().await;
        for (rid, r) in map.iter_mut() {
            let hooks: Vec<String> = app
                .store
                .active_hooks(rid)?
                .into_iter()
                .filter(|(_, _, _, owner_session)| owner_session == session)
                .map(|(id, _, _, _)| id)
                .collect();
            if !hooks.is_empty() {
                app.store.unsubscribe(rid, &hooks, false)?;
                for chunk in hooks.chunks(100) {
                    r.send(json!({"op":"paused","webhook_ids":chunk,"reason":reason}));
                }
            }
            r.auth.retain(|p| p.session != session);
            if r.watch.as_ref().is_some_and(|p| p.session == session) {
                r.watch = None;
                r.send(json!({"op":"paused","webhook_ids":[],"reason":reason}));
            }
        }
        Ok(())
    }
    pub async fn inbox_changed(&self, ctx: &str, recipient: &str) {
        let map = self.receivers.read().await;
        for r in map.values() {
            if r.watch
                .as_ref()
                .is_some_and(|p| p.context == ctx && p.id == recipient)
            {
                r.send(json!({"op":"inbox_changed"}));
            }
        }
    }
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
                &["op", "request_id", "proof_token", "body"],
                &["op", "request_id", "proof_token", "body"],
            )?;
            let mut h = HeaderMap::new();
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
                &["op", "request_id", "session_token", "webhook_ids"],
                &["op", "request_id", "session_token", "webhook_ids"],
            )?;
            let p = app
                .auth
                .authenticate(v::string(b, "session_token", 32768)?, &HeaderMap::new())
                .await?;
            let ids = v::ids(b, "webhook_ids", true)?;
            let _gate = app.mutations.lock().await;
            app.auth.check_session(&p)?;
            let replaced = app.store.bind(&p, rid, &ids, false, false)?;
            app.hub.pause_replaced(replaced, "binding_replaced").await;
            let mut map = app.hub.receivers.write().await;
            let r = map.get_mut(rid).ok_or_else(Error::not_found)?;
            r.auth.retain(|q| !(q.context == p.context && q.id == p.id));
            r.auth.push(p.clone());
            app.changed.notify_waiters();
            json!({"op":"subscribed","for":p.id,"webhook_ids":ids})
        }
        "watch_inbox" => {
            v::fields(
                b,
                &["op", "request_id", "session_token"],
                &["op", "request_id"],
            )?;
            let p = if let Some(p) = browser {
                app.auth.revalidate(p).await?
            } else {
                app.auth
                    .authenticate(v::string(b, "session_token", 32768)?, &HeaderMap::new())
                    .await?
            };
            let _gate = app.mutations.lock().await;
            app.auth.check_session(&p)?;
            let mut map = app.hub.receivers.write().await;
            let r = map.get_mut(rid).ok_or_else(Error::not_found)?;
            r.watch = Some(p);
            json!({"op":"watching_inbox"})
        }
        "unsubscribe" | "ack" => {
            if op == "ack" {
                v::fields(
                    b,
                    &["op", "request_id", "webhook_id", "message_ids", "kind"],
                    &["op", "request_id", "webhook_id", "message_ids", "kind"],
                )?
            } else {
                v::fields(
                    b,
                    &["op", "request_id", "webhook_ids", "pause"],
                    &["op", "request_id", "webhook_ids"],
                )?
            }
            let ids = if op == "ack" {
                vec![v::string(b, "webhook_id", 255)?.to_string()]
            } else {
                v::ids(b, "webhook_ids", false)?
            };
            let active = app.store.active_hooks(rid)?;
            let mut principals = vec![];
            for hid in &ids {
                let (_, context, owner, session) = active
                    .iter()
                    .find(|(h, _, _, _)| h == hid)
                    .ok_or_else(Error::not_found)?;
                let p = app.auth.authenticate_session(session).await?;
                if context != &p.context || owner != &p.id {
                    return Err(Error::not_found());
                }
                principals.push(p);
            }
            let _gate = app.mutations.lock().await;
            for principal in &principals {
                app.auth.check_session(principal)?;
            }
            if op == "ack" {
                let message_ids = v::ids(b, "message_ids", false)?;
                let kind = v::string(b, "kind", 16)?;
                let (ctx, owner, expired) = app.store.ack(rid, &ids[0], &message_ids, kind)?;
                if expired {
                    app.hub
                        .invalidate(app, &ctx, &owner, "preference_changed")
                        .await?;
                }
                if kind == "read" {
                    app.hub.inbox_changed(&ctx, &owner).await;
                    app.changed.notify_waiters();
                }
                json!({"op":"acked","message_ids":message_ids,"webhook_id":ids[0],"kind":kind})
            } else {
                app.store
                    .unsubscribe(rid, &ids, v::optional_bool(b, "pause")?.unwrap_or(false))?;
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
    for p in auth.iter().chain(watch.iter()) {
        let valid = app.auth.revalidate(p).await;
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
                .filter(|(_, ctx, u, s)| ctx == &p.context && u == &p.id && s == &p.session)
                .map(|(h, _, _, _)| h)
                .collect();
            if !rows.is_empty() {
                app.store.unsubscribe(rid, &rows, false)?;
                app.hub
                    .pause_replaced(
                        rows.into_iter().map(|h| (rid.to_owned(), h)).collect(),
                        reason,
                    )
                    .await;
            }
            let mut map = app.hub.receivers.write().await;
            if let Some(r) = map.get_mut(rid) {
                r.auth.retain(|q| q.session != p.session);
                if r.watch.as_ref().is_some_and(|q| q.session == p.session) {
                    r.watch = None;
                    r.send(json!({"op":"paused","webhook_ids":[],"reason":reason}));
                }
            }
        }
    }
    Ok(())
}
async fn offer(app: &Shared, rid: &str) -> Result<Vec<Value>> {
    let _gate = app.mutations.lock().await;
    let mut out = vec![];
    for (h, _, _, session) in app.store.active_hooks(rid)? {
        if let Err(error) = app.auth.check_session_id(&session) {
            if error.status != 401 {
                return Err(error);
            }
            app.store
                .unsubscribe(rid, std::slice::from_ref(&h), false)?;
            app.hub
                .pause_replaced(vec![(rid.to_owned(), h)], "session_expired")
                .await;
            continue;
        }
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
            // Retain notifications received while another selected branch awaits Accounts or I/O.
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
