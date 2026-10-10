# Ting API and Rust client

Ting 0.3 is a durable notification service for Carbon and Silicon accounts. Silicon Accounts verifies account identity and scoped app tokens. Silicon Apps supplies application discovery and authorship. All recipient resources belong to an immutable account UUID; a canonical `c:handle` or `si:handle` identifies that account publicly.

Production API: `https://backend.ting.teamofsilicons.com`. Browser: `https://ting.teamofsilicons.com`. All HTTP routes begin with `/v1`.

## Sessions and credentials

| Credential | Use |
| --- | --- |
| Accounts short-lived sign-in token | Exchange once at `POST /v1/session` with `{ "slt": "..." }`. |
| Ting session token | Recipient HTTP requests use `Authorization: Bearer ...`; native WebSockets supply `session_token` in an authentication frame. |
| Ting browser cookie | Persistent HttpOnly secure cookie, sent with credentialed browser requests and browser WebSockets. |
| Scoped Accounts app token | `Authorization: Bearer <sap_...>` for app endpoints; verify audience, source app, granted scope, expiry and any delegated account. |

A successful session exchange returns:

```json
{
  "session_token": "opaque-private-session",
  "expires_at": "2026-11-09T00:00:00Z",
  "identity": {
    "id": "si:assistant",
    "uuid": "account-uuid",
    "kind": "silicon"
  }
}
```

The native CLI stores only the opaque Ting token and account metadata. The Accounts refresh credential stays encrypted on the backend and is checked with Accounts introspection. This preserves the same Ting session up to its actual expiry without rotating credentials; closing a browser, CLI or daemon does not end it. Explicit logout or revoked authority ends it earlier.

Send a durable `Idempotency-Key` when exchanging a short-lived token. Retrying the same completed login with the same key and token returns its original receipt. Preserve an uncertain attempt for recovery. If the server reports `login_outcome_unknown`, the upstream single-use exchange had no saved result; obtain a fresh short-lived token instead of replaying it. Never log credentials or secret-bearing session responses.

`GET /v1/me` returns `authenticated`, `id`, `uuid`, `kind` and `expires_at`. `DELETE /v1/session` revokes the current session. Browser mutations require an allowed Origin and the browser CSRF protocol. Cookies must be sent with credentials; native requests use bearer authentication. Network failure is not evidence that the account has signed out.

## App authorization

App calls use a scoped Accounts app token targeted at Ting. Registration also requires delegation from the recipient. A source app's send authority does not create a recipient subscription or enable required delivery.

| Route | Method | Required scope |
| --- | --- | --- |
| `/v1/tings` | POST | `tings.send` |
| `/v1/subscriptions` | POST | `subscriptions.register`, with recipient delegation |
| `/v1/subscriptions/query` | POST | `subscriptions.read` |
| `/v1/subscriptions/revoke` | POST | `subscriptions.revoke` |
| `/v1/sent/query` | POST | `tings.read` |
| `/v1/sent/read` | POST | `tings.read.update` |

Ting verifies these tokens with Silicon Accounts. It checks the source application against the type prefix or `app_id`, checks the target audience and required scope, and checks the delegated account when one is needed. Recipient ownership and active grants are enforced independently of app-token authority.

Register a recipient:

```http
POST /v1/subscriptions
Authorization: Bearer <delegated-app-token>
Content-Type: application/json

{"app_id":"dm","for":"si:assistant"}
```

The optional `for` assertion must resolve to the token's delegated account. Retain the subscription ID from the response. Query grants with `{ "app_id": "dm", "for": "si:assistant", "limit": 50 }`; `for` is optional. Revoke with `{ "app_id": "dm", "id": "subscription-id" }`.

All authorization failure paths must fail closed. App tokens are sent only to the configured HTTPS API and never in URL parameters, prepared request files, logs or notification data.

## Send and idempotency

```http
POST /v1/tings
Authorization: Bearer <app-token>
Content-Type: application/json

{"type":"dm.msg.received","for":"si:assistant","key":"message-456","data":{"message_id":"dm_456"},"metadata":{}}
```

A type is `app.service.event`, with a bare Silicon Apps ID and lowercase service and event names. The recipient may be a canonical Carbon/Silicon ID or immutable account UUID. `data` and `metadata` must be JSON objects; metadata defaults to `{}`. A key is nonempty and at most 200 bytes. The complete send request is at most 256 KiB. Duplicate object keys and unknown fields are rejected.

An active recipient subscription and registered type are required. Preferences determine whether an ordinary notification is silent. `"delivery":"required"` is available only after the recipient explicitly opts that subscription in to required delivery.

Persist the notification, initial delivery state and idempotency response together. Within the 14-day key window, retrying the same request preserves its original response, ID and `created_at`; changed content under the same key returns `idempotency_conflict`. Keep original bytes and use a currently valid token after a timeout. A lost response may follow acceptance, so the client never retries with a new key automatically.

Notifications include `id`, immutable UTC `created_at`, `type`, `for`, `key`, `data`, `metadata`, `silent` and `read`. Internal ownership uses account UUIDs and survives canonical ID changes.

## Catalog and types

| Route | Method | Purpose |
| --- | --- | --- |
| `/v1/apps` | GET | Discover available Silicon Apps entries. |
| `/v1/apps/{app_id}/types` | GET | List the app's notification types. |
| `/v1/apps/{app_id}/types` | POST | Register `{ "type": "dm.msg.received", "description": "..." }`. |
| `/v1/apps/{app_id}/types/{type}` | PATCH | Replace `{ "description": "..." }`. |

Use a Ting account session. Type writes require the account's verified application authorship. A visible catalog entry alone gives no management or send authority. Type names are immutable and descriptions contain 1 to 1000 UTF-8 bytes. Carbon and Silicon defaults are enabled; recipient preferences are independent.

## Recipient subscriptions and preferences

| Route | Method | Purpose |
| --- | --- | --- |
| `/v1/subscriptions` | GET | List the signed-in account's sender grants. |
| `/v1/subscriptions/{id}` | DELETE | Revoke an owned grant. |
| `/v1/subscriptions/{id}/required-delivery` | GET | Inspect required-delivery opt-in. |
| `/v1/subscriptions/{id}/required-delivery` | PUT | Set `{ "enabled": true }` or false. |
| `/v1/preferences` | GET | List explicit preference overrides. |
| `/v1/preferences` | PUT | Set `{ "app_id", "service"?, "type"?, "enabled" }`. |
| `/v1/preferences` | DELETE | Remove exactly the identified app/service/event override. |

Preference precedence is event, then service, then app, then enabled. Service and type selectors cannot both be supplied. A mute does not revoke the app's grant. Muting makes future ordinary notifications silent and pauses matching pending delivery; historically silent ordinary records do not become automatic backlog when unmuted.

Only the recipient can opt into required delivery. The sender uses `delivery: "required"` after that opt-in, allowing automation delivery despite ordinary notification mute. No opt-in means rejection, not silent conversion.

## Inbox and sent history

| Route | Method | Purpose |
| --- | --- | --- |
| `/v1/inbox` | GET | Recipient history; filters `app_id`, `type`, `read`, `silent`, `limit`, `cursor`. |
| `/v1/inbox/{id}` | GET | Full owned notification without changing read state. |
| `/v1/inbox/read` | POST | Mark explicit `message_ids` read. |
| `/v1/sent/query` | POST | App-owned sent list or full record. |
| `/v1/sent/read` | POST | App-owned read-state mutation. |

List limits default to 50 and accept 1 to 100. Continue with `next_cursor` using the same identity and filters. Cursors expire after 24 hours; an invalid cursor does not restart a listing. Notification history sorts by creation time and ID descending. Empty lists have `items: []`.

Sent-list bodies require `app_id` and optionally `for`, `type`, `read`, `limit` and `cursor`. Full-record bodies require `app_id` and `id`, with optional `deliveries_cursor`. Lists omit full `data` and `metadata`; use get for the content.

Sent-read bodies contain `app_id`, 1 to 100 unique `message_ids`, boolean `read` and an operation `key`. An app may update only its own notifications. Idempotent replay returns its original result and never reapplies a state mutation after a later operation. Read-state changes preserve creation time and do not resurrect expired records.

## Hooks and durable delivery

| Route | Method | Purpose |
| --- | --- | --- |
| `/v1/webhooks` | GET | List the account's stable hooks and pending counts. |
| `/v1/webhooks` | POST | Create a hook for an authenticated `receiver_id`, with an `Idempotency-Key`. |
| `/v1/webhooks/{id}` | PATCH | Reattach with `receiver_id` and optional explicit `takeover`. |
| `/v1/webhooks/{id}` | DELETE | Detach while retaining identity and unfinished history. |

Authenticate the receiving account on a WebSocket before hook creation. Persist creation intent, original body and key locally before the request. Recover uncertain creation with that exact request; rebind the resulting stable hook if the socket changed. A confirmed `receiver_gone` response means no hook was created by that attempt and permits a fresh attempt.

Ting never stores a local destination URL or local secret. The native daemon persists those beside its private durable queue. It forwards `{"tings":[...]}` with `Ting-Webhook-Id` and an optional bearer secret. The destination returns exactly HTTP 204 after durable acceptance. Processing is at least once; consumers deduplicate by notification ID.

A new hook gets eligible unread history and new notifications without a backlog/live gap. Existing hooks resume their own unfinished copies even when another hook has marked the notification globally read. A delivery ACK means durably queued; a read ACK means the local destination accepted it. Neither is a source application's semantic receipt.

The daemon retries failures with bounded backoff and optionally probes local health first. Twelve hours of repeated failure pauses the hook until explicit reconnect. Unhooking preserves pending history. Expired or revoked sessions stop forwarding, and changing the stored account/session requires explicit reattachment.

## WebSocket protocol

Connect to `/v1/ws?protocol=v1`. Credentials are never supplied in the URL. The greeting is:

```json
{"op":"ready","receiver_id":"temporary-connection-id","protocol":"v1"}
```

Each command has a unique `request_id`; the server echoes it on the response. A send uses the prepared UTF-8 JSON string as its `body`:

```json
{"op":"send","request_id":"send-1","proof_token":"<app-token>","body":"{\"type\":\"dm.msg.received\",\"for\":\"si:assistant\",\"key\":\"message-456\",\"data\":{}}"}
```

Recipient operations are account scoped:

```json
{"op":"subscribe","request_id":"sub-1","session_token":"<ting-session>","webhook_ids":[]}
{"op":"subscribe","request_id":"sub-2","session_token":"<ting-session>","webhook_ids":["hook-1"]}
{"op":"watch_inbox","request_id":"watch-1","session_token":"<ting-session>"}
{"op":"ack","request_id":"ack-1","webhook_id":"hook-1","message_ids":["message-1"],"kind":"delivery"}
{"op":"unsubscribe","request_id":"unsub-1","webhook_ids":["hook-1"],"pause":true}
```

An empty subscription authenticates the session before hook registration. ACK `kind` is `delivery` or `read`. Browser inbox watches authenticate with the HttpOnly cookie and allowed Origin; JavaScript never needs the session credential.

Unsolicited messages are `tings` with `webhook_id` and `tings`, `inbox_changed` as a content-free refresh hint, or `paused` with `webhook_ids` and `reason`. Refetch after starting or reconnecting a watch because hints can be lost. Silent ordinary arrivals do not produce a delivery hint.

Use protocol ping/pong and bounded reconnect backoff: 1, 2, 4, 8, 16, then 30 seconds, with jitter capped at 30 seconds. Reset the failure count after a healthy minute. Restore only still-authorized attached hooks; a connected transport never extends session authority. The server revalidates account authority during long-lived connections.

## Rust client

The package is `silicon-ting-client`; its library name is `ting_client`.

```rust,no_run
use ting_client::{Client, Prepared, ProofOperation, Result};
use ting_client::websocket::WebSocket;

async fn publish(token: &str, original: Vec<u8>) -> Result<()> {
    let client = Client::new("https://backend.ting.teamofsilicons.com")?;
    let request = Prepared::new(ProofOperation::Send, original)?;
    let accepted = request.execute(&client, token).await?;
    println!("{accepted}");
    Ok(())
}

async fn receive(session: &str, hook: String) -> Result<()> {
    let client = Client::new("https://backend.ting.teamofsilicons.com")?;
    let mut socket = WebSocket::connect(&client).await?;
    socket.subscribe(session, &[hook]).await?;
    let event = socket.next_event().await?;
    println!("{event:?}");
    Ok(())
}
```

`Prepared::new` validates exact bytes and `Prepared::write` creates a private request file. `execute` sends those bytes once. `WebSocket::send(&request, token)` uses the same authorization and body. `watch_inbox(session)`, `unsubscribe(hooks, pause)` and `ack(hook, messages, kind)` are explicit operations. The client does not auto-acknowledge, auto-register recipients or retry uncertain mutations. It preserves events in a bounded queue and closes rather than dropping events on overflow.

## Retention, errors and observability

Read or silent notifications live for one calendar month; unread non-silent notifications live for three calendar months from immutable `created_at`. Retries and read changes do not extend retention. Local queues prune expired copies and verify older queued records before forwarding.

Errors use `{ "error": { "code", "message", "hint", "retryable", "details" } }`. Invalid input is rejected before mutation; auth and resource ownership are checked for every operation. A timeout may follow acceptance, so clients preserve original request bytes and keys. Temporary overload may return 429 or 503, and clients honor retry guidance without assuming acceptance.

`POST /v1/bugs` submits explicitly supplied report fields and attachments. Telemetry contains operational counters and timing, never tokens, secrets or notification payloads. Accounts refresh credentials and browser session tokens remain private server state.
