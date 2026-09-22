//! Native WebSocket publishing and receiving. Credentials are never persisted or put in URLs.
//!
//! Keep the original [`Prepared`] body/key after an uncertain send, obtain a fresh
//! actor-bound proof, and retry explicitly. Reconnect with [`reconnect_delay`],
//! resetting the failure count after one healthy minute. Restore still-authorized
//! subscriptions using their original hook IDs; refetch after an inbox watch starts
//! or reconnects because hints can be lost and silent arrivals produce no hint.
//! A `Paused` event requires explicit recovery according to its reason; a connected
//! socket does not extend session authority. This client never acknowledges events,
//! reenrolls recipients, refreshes sessions, or retries requests automatically.
//!
//! ```no_run
//! use ting_client::{Client, Prepared, Result, TestHeaders};
//! use ting_client::websocket::WebSocket;
//!
//! async fn publish(client: &Client, original: &Prepared, fresh_proof: &str) -> Result<()> {
//!     let mut socket = WebSocket::connect(client).await?;
//!     let accepted = socket.send(original, fresh_proof, &TestHeaders::default()).await?;
//!     // Persist acceptance before releasing the original handoff record.
//!     assert_eq!(accepted["op"], "accepted");
//!     Ok(())
//! }
//! ```

use crate::{Client, Error, Prepared, ProofOperation, Result, TestHeaders, nonempty, strict_json};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::Instant,
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
const FRAME_LIMIT: usize = 1024 * 1024;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);
const PING_INTERVAL: Duration = Duration::from_secs(30);
const PONG_TIMEOUT: Duration = Duration::from_secs(10);

/// Server notifications, preserved until explicitly consumed. Receiving one sends no ACK.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Event {
    /// A hook may include multiple applications; route every accepted item. Payloads
    /// remain JSON so additional server fields, including each item's `for`, survive.
    Tings {
        org_id: String,
        webhook_id: String,
        tings: Vec<Value>,
    },
    /// Refresh hint only; contains neither content nor delivery/read authority.
    InboxChanged { org_id: String },
    Paused {
        org_id: String,
        webhook_ids: Vec<String>,
        reason: String,
    },
}

struct Command {
    body: Value,
    expected: &'static str,
    reply: oneshot::Sender<Result<Value>>,
}

/// One connection with correlated, serial requests and a bounded notification queue.
/// Ping/pong runs while idle. Dropping this value closes its socket; cancelling a
/// request also closes the socket because its acceptance may be uncertain.
/// Notification overflow closes the connection instead of silently losing a pause.
pub struct WebSocket {
    receiver_id: String,
    commands: mpsc::Sender<Command>,
    events: mpsc::Receiver<Result<Event>>,
    task: JoinHandle<()>,
}

impl Drop for WebSocket {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl WebSocket {
    /// Connect without granting authority. Each send/subscription supplies its own
    /// proof/session and optional verified Ting audience testing credentials.
    pub async fn connect(client: &Client) -> Result<Self> {
        Self::connect_path(client, "/v1/ws").await
    }

    /// Connect to the restricted testing receiver transport. Authenticate with
    /// `watch_receiver` within five seconds. This transport cannot send or ACK.
    pub async fn connect_receiver(client: &Client) -> Result<Self> {
        Self::connect_path(client, "/v1/receivers/ws").await
    }

    async fn connect_path(client: &Client, path: &str) -> Result<Self> {
        // Client.origin is public, so validate again before building a credential-free URL.
        let origin = crate::api_origin(&client.origin)?;
        let url = format!(
            "{}{path}?protocol=v1",
            origin
                .replacen("https://", "wss://", 1)
                .replacen("http://", "ws://", 1)
        );
        let (socket, receiver_id) = tokio::time::timeout(Duration::from_secs(10), async {
            let config = WebSocketConfig::default()
                .max_message_size(Some(FRAME_LIMIT))
                .max_frame_size(Some(FRAME_LIMIT));
            let (mut socket, _) = connect_async_with_config(url, Some(config), false)
                .await
                .map_err(|_| Error::network())?;
            let ready = read_json(&mut socket).await?;
            if ready["op"] != "ready" || ready["protocol"] != "v1" {
                return Err(protocol_error());
            }
            let receiver_id = ready["receiver_id"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(protocol_error)?
                .to_owned();
            Ok((socket, receiver_id))
        })
        .await
        .map_err(|_| Error::network())??;
        let (commands, rx) = mpsc::channel(1);
        let (events, event_rx) = mpsc::channel(64);
        let task = tokio::spawn(run(socket, rx, events));
        Ok(Self {
            receiver_id,
            commands,
            events: event_rx,
            task,
        })
    }

    /// Temporary connection identity used when registering or reattaching a hook.
    pub fn receiver_id(&self) -> &str {
        &self.receiver_id
    }

    /// A transport snapshot only; does not attest session authority or delivery.
    pub fn is_connected(&self) -> bool {
        !self.task.is_finished()
    }

    /// Send the original UTF-8 body string once. A transport error/cancellation may
    /// follow server acceptance; retain these bytes/key and obtain a fresh proof.
    pub async fn send(
        &mut self,
        prepared: &Prepared,
        proof: &str,
        test: &TestHeaders,
    ) -> Result<Value> {
        if prepared.operation != ProofOperation::Send {
            return Err(Error::input(
                "WebSocket send requires a prepared Send operation.",
            ));
        }
        // Validate the authoritative bytes rather than the mutable convenience value.
        let checked = Prepared::new(ProofOperation::Send, prepared.body.clone(), None)?;
        bounded(proof, "Proof token", 32768)?;
        validate_test(test)?;
        let body = std::str::from_utf8(&checked.body)
            .map_err(|_| Error::input("Prepared body must be UTF-8."))?;
        self.request(
            json!({"op":"send","proof_token":proof,"body":body,"headers":test}),
            "accepted",
        )
        .await
    }

    /// An empty hook list authenticates this session/org before hook registration.
    pub async fn subscribe(
        &mut self,
        org: &str,
        session: &str,
        hooks: &[String],
        test: &TestHeaders,
    ) -> Result<Value> {
        bounded(org, "Organization", 255)?;
        bounded(session, "Session token", 32768)?;
        ids(hooks, true)?;
        validate_test(test)?;
        self.request(json!({"op":"subscribe","org_id":org,"session_token":session,"webhook_ids":hooks,"headers":test}), "subscribed").await
    }

    /// Replaces the previous inbox watch. Uses a Ting session, never a DM token.
    pub async fn watch_inbox(&mut self, org: &str, session: &str) -> Result<Value> {
        bounded(org, "Organization", 255)?;
        bounded(session, "Session token", 32768)?;
        self.request(
            json!({"op":"watch_inbox","org_id":org,"session_token":session}),
            "watching_inbox",
        )
        .await
    }

    /// Start a scoped receiver watch using a capability from
    /// `receivers.bootstrap`. Obtain a fresh proof and a new operation key for
    /// renewal, then reconnect; an old operation never extends its original expiry.
    pub async fn watch_receiver(&mut self, receiver_token: &str) -> Result<Value> {
        bounded(receiver_token, "Receiver token", 32768)?;
        self.request(
            json!({"op":"watch","receiver_token":receiver_token}),
            "watching_inbox",
        )
        .await
    }

    pub async fn unsubscribe(&mut self, org: &str, hooks: &[String], pause: bool) -> Result<Value> {
        bounded(org, "Organization", 255)?;
        ids(hooks, false)?;
        self.request(
            json!({"op":"unsubscribe","org_id":org,"webhook_ids":hooks,"pause":pause}),
            "unsubscribed",
        )
        .await
    }

    /// Explicitly acknowledge listed IDs on the currently authorized hook. `delivery`
    /// requires durable queuing; `read` requires durable destination acceptance and
    /// changes Ting's own read state. Neither represents a DM delivered/read receipt.
    pub async fn ack(
        &mut self,
        org: &str,
        hook: &str,
        messages: &[String],
        kind: &str,
    ) -> Result<Value> {
        bounded(org, "Organization", 255)?;
        bounded(hook, "Webhook ID", 255)?;
        ids(messages, false)?;
        if !["delivery", "read"].contains(&kind) {
            return Err(Error::input("ACK kind must be delivery or read."));
        }
        self.request(
            json!({"op":"ack","org_id":org,"webhook_id":hook,"message_ids":messages,"kind":kind}),
            "acked",
        )
        .await
    }

    /// Wait for the next notification; cancellation leaves queued events untouched.
    pub async fn next_event(&mut self) -> Result<Event> {
        self.events
            .recv()
            .await
            .unwrap_or_else(|| Err(Error::network()))
    }

    async fn request(&mut self, mut body: Value, expected: &'static str) -> Result<Value> {
        body["request_id"] = uuid::Uuid::new_v4().to_string().into();
        if body.to_string().len() > FRAME_LIMIT {
            return Err(Error::input("WebSocket request exceeds its byte limit."));
        }
        let (reply, response) = oneshot::channel();
        self.commands
            .send(Command {
                body,
                expected,
                reply,
            })
            .await
            .map_err(|_| Error::network())?;
        response.await.map_err(|_| Error::network())?
    }
}

/// Delay after a failed connection: index 0 starts at one second, then 2, 4, 8,
/// 16, 30 seconds, with up to 20% positive jitter capped at 30 seconds. Reset the
/// failure index after one healthy minute; do not retry revoked authority.
pub fn reconnect_delay(failure_index: u32) -> Duration {
    let base = (1_u64 << failure_index.min(5)).min(30) * 1000;
    let jitter = (uuid::Uuid::new_v4().as_u128() % (base as u128 / 5 + 1)) as u64;
    Duration::from_millis((base + jitter).min(30_000))
}

fn bounded(value: &str, name: &str, max: usize) -> Result<()> {
    nonempty(value, name)?;
    if value.len() > max {
        return Err(Error::input(format!("{name} exceeds {max} bytes.")));
    }
    Ok(())
}

fn ids(values: &[String], empty: bool) -> Result<()> {
    if values.len() > 100 || (!empty && values.is_empty()) {
        return Err(Error::input(
            "Supply at most 100 IDs, and at least one unless authenticating a subscription.",
        ));
    }
    for id in values {
        bounded(id, "ID", 255)?;
    }
    Ok(())
}

fn validate_test(test: &TestHeaders) -> Result<()> {
    match (&test.app_secret, &test.key) {
        (None, None) => Ok(()),
        (Some(secret), Some(key)) => {
            nonempty(secret, "IAM_TEST_APP_SECRET")?;
            nonempty(key, "X-Testing-Environment-Key")
        }
        _ => Err(Error::input("Supply both testing headers or neither.")),
    }
}

fn protocol_error() -> Error {
    Error::new(
        "invalid_server_response",
        "Server returned an invalid WebSocket response; an in-flight request's outcome may be uncertain.",
        "Check protocol compatibility. Preserve the original send bytes/key and obtain a fresh proof before retrying.",
        false,
    )
}

async fn write(socket: &mut Socket, message: Message) -> Result<()> {
    tokio::time::timeout(WRITE_TIMEOUT, socket.send(message))
        .await
        .map_err(|_| Error::network())?
        .map_err(|_| Error::network())
}

async fn read_json(socket: &mut Socket) -> Result<Value> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                return strict_json(text.as_bytes()).map_err(|_| protocol_error());
            }
            Some(Ok(Message::Ping(payload))) => write(socket, Message::Pong(payload)).await?,
            Some(Ok(Message::Pong(_))) => {}
            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return Err(Error::network()),
            _ => return Err(protocol_error()),
        }
    }
}

async fn run(
    mut socket: Socket,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Result<Event>>,
) {
    let mut pending: Option<Command> = None;
    let mut request_deadline = Instant::now() + REQUEST_TIMEOUT;
    let mut next_ping = Instant::now() + PING_INTERVAL;
    let mut pong_deadline = None;
    let error = loop {
        let deadline = if pending.is_some() {
            request_deadline.min(next_ping)
        } else {
            next_ping
        };
        let deadline = pong_deadline.map_or(deadline, |pong: Instant| deadline.min(pong));
        tokio::select! {
            biased;
            _ = async { match &mut pending { Some(command) => command.reply.closed().await, None => std::future::pending().await } } => break Error::network(),
            _ = tokio::time::sleep_until(deadline) => {
                let now = Instant::now();
                if pending.is_some() && now >= request_deadline || pong_deadline.is_some_and(|at| now >= at) { break Error::network(); }
                if now >= next_ping {
                    if let Err(error) = write(&mut socket, Message::Ping(vec![1].into())).await { break error; }
                    next_ping = Instant::now() + PING_INTERVAL;
                    let deadline = Instant::now() + PONG_TIMEOUT;
                    pong_deadline = Some(if pending.is_some() { deadline.max(request_deadline) } else { deadline });
                }
            },
            incoming = socket.next() => {
                let value = match incoming {
                    Some(Ok(Message::Text(text))) => match strict_json(text.as_bytes()) { Ok(value) => value, Err(_) => break protocol_error() },
                    Some(Ok(Message::Ping(payload))) => { if let Err(error) = write(&mut socket, Message::Pong(payload)).await { break error; } continue; },
                    Some(Ok(Message::Pong(_))) => { pong_deadline = None; continue; },
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break Error::network(),
                    _ => break protocol_error(),
                };
                if let Some(id) = value.get("request_id") {
                    if !pending.as_ref().is_some_and(|command| id == &command.body["request_id"]) { break protocol_error(); }
                    let command = pending.take().unwrap();
                    let response = if value["op"] == "error" {
                        match serde_json::from_value(value["error"].clone()) { Ok(error) => Err(error), Err(_) => { let _ = command.reply.send(Err(protocol_error())); break protocol_error(); } }
                    } else if value["op"] == command.expected { Ok(value) }
                    else { let _ = command.reply.send(Err(protocol_error())); break protocol_error(); };
                    if command.reply.send(response).is_err() { break Error::network(); }
                } else {
                    let event = match serde_json::from_value(value) { Ok(event) => event, Err(_) => break protocol_error() };
                    if events.try_send(Ok(event)).is_err() { break Error::new("receiver_overflow", "WebSocket notification queue filled; the connection was closed.", "Consume events promptly, reconnect and recover unfinished hook deliveries or refetch current state.", true); }
                }
            },
            command = commands.recv(), if pending.is_none() => {
                let Some(command) = command else { break Error::network(); };
                if command.reply.is_closed() { continue; }
                let frame = Message::Text(command.body.to_string().into());
                pending = Some(command);
                let sent = tokio::select! {
                    biased;
                    _ = pending.as_mut().unwrap().reply.closed() => Err(Error::network()),
                    result = write(&mut socket, frame) => result,
                };
                if let Err(error) = sent { break error; }
                request_deadline = Instant::now() + REQUEST_TIMEOUT;
                // Ting handles requests inline and cannot read ping until that handler
                // finishes. Keep its full request deadline, even for an earlier ping.
                if let Some(deadline) = &mut pong_deadline { *deadline = (*deadline).max(request_deadline); }
            },
        }
    };
    drop(socket);
    if let Some(command) = pending {
        let _ = command.reply.send(Err(error.clone()));
    }
    let _ = events.try_send(Err(error));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    const BODY: &str = "{ \"org_id\":\"tos\", \"type\":\"tos>dm.sync.changed\", \"for\":\"si_1\", \"key\":\"si_1/event-1\", \"data\":{\"text\":\"नमस्ते\\nhi\"} }";

    async fn fixture() -> (TcpListener, Client) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = Client::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        (listener, client)
    }

    async fn accept(listener: &TcpListener) -> WebSocketStream<TcpStream> {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        respond(
            &mut socket,
            json!({"op":"ready","protocol":"v1","receiver_id":"recv_fixture"}),
        )
        .await;
        socket
    }

    async fn respond(socket: &mut WebSocketStream<TcpStream>, value: Value) {
        socket
            .send(Message::Text(value.to_string().into()))
            .await
            .unwrap();
    }

    async fn receive(socket: &mut WebSocketStream<TcpStream>) -> Value {
        let frame = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        strict_json(frame.to_text().unwrap().as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn scoped_receiver_uses_its_own_route_and_keeps_capability_out_of_url() {
        let (listener, client) = fixture().await;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
                    assert_eq!(request.uri().to_string(), "/v1/receivers/ws?protocol=v1");
                    assert!(!request.headers().contains_key("authorization"));
                    Ok(response)
                },
            )
            .await
            .unwrap();
            respond(
                &mut socket,
                json!({"op":"ready","protocol":"v1","receiver_id":"scoped"}),
            )
            .await;
            let request = receive(&mut socket).await;
            assert_eq!(request["op"], "watch");
            assert_eq!(request["receiver_token"], "private-capability");
            respond(
                &mut socket,
                json!({"op":"watching_inbox","request_id":request["request_id"],"org_id":"org"}),
            )
            .await;
            respond(
                &mut socket,
                json!({"op":"inbox_changed","org_id":"org","app_id":"tos>hook"}),
            )
            .await;
            assert!(
                tokio::time::timeout(Duration::from_millis(50), socket.next())
                    .await
                    .is_err(),
                "A scoped watch must not send automatic ACKs"
            );
        });
        let mut socket = WebSocket::connect_receiver(&client).await.unwrap();
        socket.watch_receiver("private-capability").await.unwrap();
        assert!(
            matches!(socket.next_event().await.unwrap(), Event::InboxChanged {org_id} if org_id == "org")
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sends_exact_prepared_bytes_and_correlates_errors_and_success() {
        let (listener, client) = fixture().await;
        let server = tokio::spawn(async move {
            let mut socket = accept(&listener).await;
            for proof in ["rejected-proof", "fresh-proof"] {
                let request = receive(&mut socket).await;
                assert_eq!(
                    request["body"].as_str().unwrap().as_bytes(),
                    BODY.as_bytes()
                );
                assert_eq!(request["proof_token"], proof);
                assert_eq!(
                    request["headers"],
                    json!({"IAM_TEST_APP_SECRET":"ting-audience-secret","X-Testing-Environment-Key":"environment-key"})
                );
                assert!(!request["request_id"].as_str().unwrap().is_empty());
                if proof == "rejected-proof" {
                    respond(&mut socket, json!({"op":"error","request_id":request["request_id"],"error":{"code":"proof_expired","message":"Expired proof","hint":"Obtain another proof","retryable":false}})).await;
                } else {
                    respond(&mut socket, json!({"op":"accepted","request_id":request["request_id"],"id":"msg_1","key":"si_1/event-1"})).await;
                }
            }
        });
        let mut socket = WebSocket::connect(&client).await.unwrap();
        assert_eq!(socket.receiver_id(), "recv_fixture");
        let mut prepared =
            Prepared::new(ProofOperation::Send, BODY.as_bytes().to_vec(), None).unwrap();
        prepared.value["key"] = "must-not-be-sent".into();
        let test = TestHeaders {
            app_secret: Some("ting-audience-secret".into()),
            key: Some("environment-key".into()),
        };
        assert_eq!(
            socket
                .send(&prepared, "rejected-proof", &test)
                .await
                .unwrap_err()
                .code,
            "proof_expired"
        );
        assert_eq!(
            socket.send(&prepared, "fresh-proof", &test).await.unwrap()["key"],
            "si_1/event-1"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn receives_events_and_pings_without_implicitly_acknowledging_batches() {
        let (listener, client) = fixture().await;
        let server = tokio::spawn(async move {
            let mut socket = accept(&listener).await;
            socket.send(Message::Ping(vec![7, 8].into())).await.unwrap();
            let mut pong = false;
            let request = loop {
                match socket.next().await.unwrap().unwrap() {
                    Message::Pong(bytes) => {
                        assert_eq!(&bytes[..], &[7, 8]);
                        pong = true;
                    }
                    Message::Text(text) => break strict_json(text.as_bytes()).unwrap(),
                    frame => panic!("Unexpected frame: {frame:?}"),
                }
            };
            // A subscribe can race its queued pong; both must arrive before the reply.
            if !pong {
                assert!(
                    matches!(socket.next().await.unwrap().unwrap(), Message::Pong(bytes) if bytes.as_ref() == [7, 8])
                );
            }
            assert_eq!(request["op"], "subscribe");
            assert_eq!(request["webhook_ids"], json!([]));
            respond(&mut socket, json!({"op":"tings","org_id":"tos","webhook_id":"hook_1","tings":[{"id":"dm","type":"tos>dm.sync.changed","for":"si_1"},{"id":"other","type":"tos>other.sync.changed","for":"si_1"}]})).await;
            respond(&mut socket, json!({"op":"paused","org_id":"tos","webhook_ids":["hook_1"],"reason":"session_expired"})).await;
            respond(&mut socket, json!({"op":"subscribed","request_id":request["request_id"],"for":"si_1","webhook_ids":[]})).await;
            let request = receive(&mut socket).await;
            assert_eq!(request["op"], "watch_inbox");
            assert_eq!(request["session_token"], "ting-session");
            respond(&mut socket, json!({"op":"inbox_changed","org_id":"tos"})).await;
            respond(
                &mut socket,
                json!({"op":"watching_inbox","request_id":request["request_id"],"org_id":"tos"}),
            )
            .await;
            assert!(
                tokio::time::timeout(Duration::from_millis(50), socket.next())
                    .await
                    .is_err(),
                "Receiving events must not send an ACK"
            );
        });
        let mut socket = WebSocket::connect(&client).await.unwrap();
        socket
            .subscribe("tos", "ting-session", &[], &TestHeaders::default())
            .await
            .unwrap();
        let Event::Tings { tings, .. } = socket.next_event().await.unwrap() else {
            panic!("Expected batch")
        };
        assert_eq!(tings.len(), 2);
        assert_eq!(tings[1]["for"], "si_1");
        assert!(
            matches!(socket.next_event().await.unwrap(), Event::Paused { reason, .. } if reason == "session_expired")
        );
        socket.watch_inbox("tos", "ting-session").await.unwrap();
        assert!(
            matches!(socket.next_event().await.unwrap(), Event::InboxChanged { org_id } if org_id == "tos")
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_an_inflight_send_closes_the_socket_without_retry() {
        let (listener, client) = fixture().await;
        let (received, request_seen) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut socket = accept(&listener).await;
            assert_eq!(receive(&mut socket).await["body"], BODY);
            received.send(()).unwrap();
            let closed = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .expect("Cancelled request must drop its socket");
            assert!(
                closed.is_none() || matches!(closed, Some(Err(_)) | Some(Ok(Message::Close(_))))
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let mut socket = WebSocket::connect(&client).await.unwrap();
        let prepared = Prepared::new(ProofOperation::Send, BODY.as_bytes().to_vec(), None).unwrap();
        let test = TestHeaders::default();
        let mut request = Box::pin(socket.send(&prepared, "single-use-proof", &test));
        tokio::select! {
            _ = request_seen => {},
            result = &mut request => panic!("No acceptance reply was sent: {result:?}"),
        }
        drop(request);
        server.await.unwrap();
        assert!(!socket.is_connected());
    }

    #[tokio::test]
    async fn rejects_wrong_request_correlation_and_closes() {
        let (listener, client) = fixture().await;
        let server = tokio::spawn(async move {
            let mut socket = accept(&listener).await;
            let _ = receive(&mut socket).await;
            respond(
                &mut socket,
                json!({"op":"accepted","request_id":"unrelated","id":"wrong"}),
            )
            .await;
        });
        let mut socket = WebSocket::connect(&client).await.unwrap();
        let prepared = Prepared::new(ProofOperation::Send, BODY.as_bytes().to_vec(), None).unwrap();
        assert_eq!(
            socket
                .send(&prepared, "proof", &TestHeaders::default())
                .await
                .unwrap_err()
                .code,
            "invalid_server_response"
        );
        server.await.unwrap();
    }

    #[test]
    fn validates_testing_pairs_and_bounds_recovery_backoff() {
        assert!(
            validate_test(&TestHeaders {
                app_secret: Some("secret".into()),
                key: None
            })
            .is_err()
        );
        assert!(
            validate_test(&TestHeaders {
                app_secret: Some("secret".into()),
                key: Some("".into())
            })
            .is_err()
        );
        assert!(ids(&[], true).is_ok());
        assert!(ids(&[], false).is_err());
        for (index, base) in [1., 2., 4., 8., 16., 30.].into_iter().enumerate() {
            let delay = reconnect_delay(index as u32).as_secs_f64();
            assert!(delay >= base && delay <= (base * 1.2).min(30.));
        }
        assert_eq!(reconnect_delay(u32::MAX), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn lost_reply_requires_explicit_reconnect_and_fresh_proof_over_same_body() {
        let (listener, client) = fixture().await;
        let server = tokio::spawn(async move {
            let mut first = accept(&listener).await;
            let initial = receive(&mut first).await;
            assert_eq!(initial["proof_token"], "first-proof");
            drop(first); // Acceptance could have committed before its reply was lost.
            let mut second = accept(&listener).await;
            let retry = receive(&mut second).await;
            assert_eq!(retry["body"], initial["body"]);
            assert_eq!(retry["proof_token"], "fresh-proof");
            assert_ne!(retry["request_id"], initial["request_id"]);
            respond(&mut second, json!({"op":"accepted","request_id":retry["request_id"],"id":"same-message","key":"si_1/event-1"})).await;
        });
        let prepared = Prepared::new(ProofOperation::Send, BODY.as_bytes().to_vec(), None).unwrap();
        let mut socket = WebSocket::connect(&client).await.unwrap();
        let error = socket
            .send(&prepared, "first-proof", &TestHeaders::default())
            .await
            .unwrap_err();
        assert_eq!(error.code, "connection_failed");
        assert!(error.hint.contains("fresh proof"));
        let mut socket = WebSocket::connect(&client).await.unwrap();
        assert_eq!(
            socket
                .send(&prepared, "fresh-proof", &TestHeaders::default())
                .await
                .unwrap()["id"],
            "same-message"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn notification_overflow_closes_instead_of_losing_a_pause_on_a_live_socket() {
        let (listener, client) = fixture().await;
        let server = tokio::spawn(async move {
            let mut socket = accept(&listener).await;
            for _ in 0..64 {
                respond(&mut socket, json!({"op":"inbox_changed","org_id":"tos"})).await;
            }
            respond(
                &mut socket,
                json!({"op":"paused","org_id":"tos","webhook_ids":[],"reason":"session_expired"}),
            )
            .await;
            let closed = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .unwrap();
            assert!(
                closed.is_none() || matches!(closed, Some(Err(_)) | Some(Ok(Message::Close(_))))
            );
        });
        let mut socket = WebSocket::connect(&client).await.unwrap();
        server.await.unwrap();
        assert!(!socket.is_connected());
        for _ in 0..64 {
            assert!(matches!(
                socket.next_event().await.unwrap(),
                Event::InboxChanged { .. }
            ));
        }
        assert!(socket.next_event().await.is_err());
    }

    #[tokio::test]
    async fn heartbeat_allows_inline_handlers_but_request_timeout_still_closes() {
        async fn advance(seconds: u64) {
            // Pause only around simulated waiting; TCP I/O must not auto-advance
            // Tokio's clock past a deadline while the operating system wakes it.
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(seconds)).await;
            tokio::task::yield_now().await;
            tokio::time::resume();
        }
        for (start, handler_delay) in [(29, 15), (31, 15), (29, 36)] {
            let (listener, client) = fixture().await;
            let accepting = tokio::spawn(async move { accept(&listener).await });
            let mut socket = WebSocket::connect(&client).await.unwrap();
            let mut peer = accepting.await.unwrap();
            advance(start).await;
            let prepared =
                Prepared::new(ProofOperation::Send, BODY.as_bytes().to_vec(), None).unwrap();
            let test = TestHeaders::default();
            let mut request = Box::pin(socket.send(&prepared, "fresh-proof", &test));
            assert!(futures_util::poll!(&mut request).is_pending());
            tokio::task::yield_now().await;
            // The real server cannot read or answer pings during an IAM call.
            advance(1).await;
            advance(handler_delay - 1).await;
            if handler_delay > REQUEST_TIMEOUT.as_secs() {
                assert_eq!(request.await.unwrap_err().code, "connection_failed");
                assert!(!socket.is_connected());
                continue;
            }
            assert!(
                futures_util::poll!(&mut request).is_pending(),
                "A valid handler must not lose its socket to the heartbeat"
            );
            let body = loop {
                match peer.next().await.unwrap().unwrap() {
                    Message::Text(text) => break strict_json(text.as_bytes()).unwrap(),
                    Message::Ping(_) => {} // Tungstenite queues the delayed pong.
                    frame => panic!("Unexpected frame: {frame:?}"),
                }
            };
            respond(
                &mut peer,
                json!({"op":"accepted","request_id":body["request_id"],"id":"message"}),
            )
            .await;
            assert_eq!(request.await.unwrap()["id"], "message");
            assert!(socket.is_connected());
        }
    }
}
