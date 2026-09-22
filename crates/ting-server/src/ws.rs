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
            for hid in &ids {
                let (_, _, org, _, session) = active
                    .iter()
                    .find(|(h, _, _, _, _)| h == hid)
                    .ok_or_else(Error::not_found)?;
                let p = app.auth.authenticate_session(session).await?;
                let org2 = app.auth.org(&p, requested).await?;
                if org != &org2 {
                    return Err(Error::not_found());
                }
                canonical = Some(org2)
            }
            let org = canonical.ok_or_else(Error::not_found)?;
            let _gate = app.mutations.lock().await;
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
        let valid = match app.auth.revalidate(p).await {
            Ok(q) => app.auth.org(&q, org).await.map(|_| ()),
            Err(e) => Err(e),
        };
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
                    _ = app.changed.notified() => {
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
