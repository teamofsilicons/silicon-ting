//! Native WebSocket publishing and receiving. Credentials are never persisted or put in URLs.
//!
//! Keep the original [`Prepared`] body/key after an uncertain send, use a valid
//! Silicon Accounts app token, and retry explicitly. Reconnect with [`reconnect_delay`],
//! resetting the failure count after one healthy minute. Restore still-authorized
//! subscriptions using their original hook IDs; refetch after an inbox watch starts
//! or reconnects because hints can be lost and silent arrivals produce no hint.
//! A `Paused` event requires explicit recovery according to its reason; a connected
//! socket does not extend session authority. This client never acknowledges events,
//! reenrolls recipients, refreshes sessions, or retries requests automatically.
//!
//! ```no_run
//! use ting_client::{Client, Prepared, Result};
//! use ting_client::websocket::WebSocket;
//!
//! async fn publish(client: &Client, original: &Prepared, fresh_proof: &str) -> Result<()> {
//!     let mut socket = WebSocket::connect(client).await?;
//!     let accepted = socket.send(original, fresh_proof).await?;
//!     // Persist acceptance before releasing the original handoff record.
//!     assert_eq!(accepted["op"], "accepted");
//!     Ok(())
//! }
//! ```

use crate::{Client, Error, Prepared, ProofOperation, Result, nonempty, strict_json};
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
        webhook_id: String,
        tings: Vec<Value>,
    },
    /// Refresh hint only; contains neither content nor delivery/read authority.
    InboxChanged {},
    Paused {
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
    /// app token or account session.
    pub async fn connect(client: &Client) -> Result<Self> {
        Self::connect_path(client, "/v1/ws").await
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
    /// follow server acceptance; retain these bytes/key and use a valid Silicon Accounts app token.
    /// A send requires an app token scoped to tings.send.
    pub async fn send(&mut self, prepared: &Prepared, proof: &str) -> Result<Value> {
        if prepared.operation != ProofOperation::Send {
            return Err(Error::input(
                "WebSocket send requires a prepared Send operation.",
            ));
        }
        // Validate the authoritative bytes rather than the mutable convenience value.
        let checked = Prepared::new(ProofOperation::Send, prepared.body.clone())?;
        bounded(proof, "Proof token", 32768)?;
        let body = std::str::from_utf8(&checked.body)
            .map_err(|_| Error::input("Prepared body must be UTF-8."))?;
        self.request(
            json!({"op":"send","proof_token":proof,"body":body}),
            "accepted",
        )
        .await
    }

    /// An empty hook list authenticates this session before hook registration.
    pub async fn subscribe(&mut self, session: &str, hooks: &[String]) -> Result<Value> {
        bounded(session, "Session token", 32768)?;
        ids(hooks, true)?;
        self.request(
            json!({"op":"subscribe","session_token":session,"webhook_ids":hooks}),
            "subscribed",
        )
        .await
    }

    /// Replaces the previous inbox watch. Uses a Ting session, never a DM token.
    pub async fn watch_inbox(&mut self, session: &str) -> Result<Value> {
        bounded(session, "Session token", 32768)?;
        self.request(
            json!({"op":"watch_inbox","session_token":session}),
            "watching_inbox",
        )
        .await
    }

    pub async fn unsubscribe(&mut self, hooks: &[String], pause: bool) -> Result<Value> {
        ids(hooks, false)?;
        self.request(
            json!({"op":"unsubscribe","webhook_ids":hooks,"pause":pause}),
            "unsubscribed",
        )
        .await
    }

    /// Explicitly acknowledge listed IDs on the currently authorized hook. `delivery`
    /// requires durable queuing; `read` requires durable destination acceptance and
    /// changes Ting's own read state. Neither represents a DM delivered/read receipt.
    pub async fn ack(&mut self, hook: &str, messages: &[String], kind: &str) -> Result<Value> {
        bounded(hook, "Webhook ID", 255)?;
        ids(messages, false)?;
        if !["delivery", "read"].contains(&kind) {
            return Err(Error::input("ACK kind must be delivery or read."));
        }
        self.request(
            json!({"op":"ack","webhook_id":hook,"message_ids":messages,"kind":kind}),
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

fn protocol_error() -> Error {
    Error::new(
        "invalid_server_response",
        "Server returned an invalid WebSocket response; an in-flight request's outcome may be uncertain.",
        "Check protocol compatibility. Preserve the original send bytes/key and use a valid Silicon Accounts app token before retrying.",
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
