# Ting API and Rust client

Ting 0.3 is a durable notification service for Carbon and Silicon accounts. Silicon Accounts verifies account identity and scoped app tokens. Silicon Apps supplies application discovery and authorship. Account resources belong to an immutable account UUID; a canonical `c:handle` or `si:handle` identifies that account publicly. A receiver session can also exist anonymously and receive notifications while its WebSocket remains active.

Production API: `https://backend.ting.teamofsilicons.com`. Browser: `https://ting.teamofsilicons.com`. All HTTP routes begin with `/v1`.

## Sign-in credentials

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

{"type":"dm.messageReceived","for":"si:assistant","key":"message-456","data":{"message_id":"dm_456"},"metadata":{}}
```

A type is exactly `<app-id>.<tingid>`. The app prefix is a Silicon Apps ID; `tingid` is a nonempty ASCII alphanumeric name describing the notification. Dots, hyphens and underscores are not allowed in `tingid`, and deeper nesting is rejected. The recipient may be a canonical Carbon/Silicon ID or immutable account UUID. `data` and `metadata` must be JSON objects; metadata defaults to `{}`. A key is nonempty and at most 200 bytes. The complete send request is at most 256 KiB. Duplicate object keys and unknown fields are rejected.

A registered type and either an active account subscription or an anonymous session registration for the app are required. `data` must validate against the type’s current JSON Schema. Preferences determine whether a notification is allowed, silent, or blocked. `"delivery":"required"` is available only after the recipient explicitly opts that subscription in to required delivery.

Persist the notification, initial delivery state and idempotency response together. Within the 14-day key window, retrying the same request preserves its original response, ID and `created_at`; changed content under the same key returns `idempotency_conflict`. Keep original bytes and use a currently valid token after a timeout. A lost response may follow acceptance, so the client never retries with a new key automatically.

Notifications include `id`, immutable UTC `created_at`, `type`, `for`, `from`, `session_id`, `key`, `data`, `metadata`, `silent` and `read`. `from` and `session_id` are optional. Internal account ownership uses UUIDs and survives canonical ID changes.

Use `for` to notify all active sessions for an account. Add `session_id` to restrict delivery to that account’s specified active session; a mismatched or lost session is rejected. With `session_id`, `for` may be omitted: a session with one attached identity resolves to that user, a session with no identity resolves anonymously, and a session with multiple identities requires `for`. Anonymous receivers explicitly register the apps they accept on their own socket; an app proof still identifies every sending application.

An app may supply `from` as a Carbon/Silicon handle or account UUID for notifications from one user to another. Ting resolves it to the immutable UUID. This is attribution asserted by the verified sending app, not separate proof that the user initiated the send. Omit `from` or set it to null for app-originated notifications. Recipient rules can block either the attributed sender or the sending app.

## Catalog and types

| Route | Method | Purpose |
| --- | --- | --- |
| `/v1/apps` | GET | Discover available Silicon Apps entries. |
| `/v1/apps/{app_id}/types` | GET | Public list of the app’s types, descriptions and schemas; no sign-in required. |
| `/v1/apps/{app_id}/types` | POST | Register `{ "type": "dm.messageReceived", "description": "...", "schema": {"type":"object"} }`. |
| `/v1/apps/{app_id}/types/{type}` | PATCH | Update `description`, `schema`, or both. |

The public type catalog supports cross-origin GET requests without credentials so other browser apps can consume it. Type writes require a Ting sign-in session and verified application authorship. A public catalog entry gives no management or send authority. Type names are immutable; descriptions contain 1 to 1000 UTF-8 bytes. Each type requires a JSON Schema object or boolean of at most 64 KiB. Schema updates validate future sends; existing history and completed idempotent receipts stay unchanged. Schemas must be self-contained; external references cannot load files or fetch URLs. Carbon and Silicon defaults are allowed.

Existing three-part type definitions and history are preserved for inspection. New registrations, edits, and sends require two-part names; legacy three-part definitions cannot be edited or used for new sends. Apps must register replacement types and update callers.

## Recipient subscriptions and preferences

| Route | Method | Purpose |
| --- | --- | --- |
| `/v1/subscriptions` | GET | List the signed-in account's sender grants. |
| `/v1/subscriptions/{id}` | DELETE | Revoke an owned grant. |
| `/v1/subscriptions/{id}/required-delivery` | GET | Inspect required-delivery opt-in. |
| `/v1/subscriptions/{id}/required-delivery` | PUT | Set `{ "enabled": true }` or false. |
| `/v1/preferences` | GET | List explicit preference overrides. |
| `/v1/preferences` | PUT | Set `{ "app_id"?, "type"?, "from"?, "mode": "allowed"|"silent"|"blocked" }`. |
| `/v1/preferences` | DELETE | Remove the app, type, or sender rule selected by query parameters. |
| `/v1/silent-schedule` | GET / PUT | Inspect or update `enabled`, `time` (HH:MM), and IANA `timezone`. |
| `/v1/sessions` | GET | List the signed-in user’s currently active receiver sessions. |

An app rule supplies `app_id`; a type rule supplies `app_id` and its `type`; a sender rule supplies `from` without app/type. Handles resolve to UUIDs. Across matching sender, app and type rules, blocked wins over silent, and silent wins over allowed. With no rule, delivery is allowed. Legacy `enabled: true/false` writes map to allowed/silent; new callers should use `mode`.

Allowed tings reach the targeted active sessions immediately. Blocked tings do not enter notification history or delivery queues; acceptance returns `status: "blocked"`. Silent tings remain pending for the daily digest. A preference does not itself grant an app permission to notify an account.

The initial silent schedule is enabled at 00:00 in the user’s detected IANA time zone. Browser and native clients send `X-Ting-Timezone` with HTTP requests; `register`, `subscribe`, and `watch_inbox` may also include `timezone`. If detection is unavailable, the fallback is 09:00 UTC. Detection initializes an untouched schedule once and never overwrites a manually chosen time, zone, or enabled setting. For example, `PUT /v1/silent-schedule` with `{"time":"18:30","timezone":"Asia/Kolkata"}` changes the daily time; `{"enabled":false}` disables it while retaining pending tings. At the scheduled time, each active eligible session receives a `silent_digest`. When there are no eligible active sessions, pending tings remain on hold until a later scheduled run. Connecting after the scheduled time does not immediately flush a missed digest. Session-targeted tings are never rerouted to another session.

Only the recipient can opt into the legacy required-delivery capability. It does not override silent or blocked preferences. Without that opt-in, a send containing `delivery: "required"` is rejected.

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

Ting never stores a local destination URL or local secret. The native daemon persists those beside its private durable queue. It forwards `{"tings":[...]}` with `Ting-Webhook-Id` and an optional bearer secret. Local records retain `for`, `from`, `session_id`, and `silent`; `silent_digest: true` identifies a record released by the daily schedule. The destination returns exactly HTTP 204 after durable acceptance. Processing is at least once; consumers deduplicate by notification ID.

A new hook gets eligible unread history and new notifications without a backlog/live gap. Existing hooks resume their own unfinished copies even when another hook has marked the notification globally read. A delivery ACK means durably queued; a read ACK means the local destination accepted it. If a preference or authority change makes a receipt invalid after local acceptance, the daemon discards that accepted local copy without retransmitting it; server read state may remain unread. Neither is a source application's semantic receipt.

The daemon retries failures with bounded backoff and optionally probes local health first. Twelve hours of repeated failure pauses the hook until explicit reconnect. Unhooking preserves pending history. Expired or revoked sessions stop forwarding, and changing the stored account/session requires explicit reattachment.

## WebSocket protocol

Connect to `/v1/ws?protocol=v1`. Credentials are never supplied in the URL. The greeting is:

```json
{"op":"ready","session_id":"temporary-session-id","receiver_id":"temporary-session-id","protocol":"v1"}
```

The connection itself creates an anonymous receiver session. Its `session_id` is its live delivery address; `receiver_id` remains an alias for hook compatibility. Register an anonymous receiver’s accepted apps:

```json
{"op":"register","request_id":"register-1","app_ids":["dm"]}
```

Supply `session_token` on `register` to attach an account and omit `app_ids` (or send an empty list); authenticated app consent still uses subscriptions. Nonempty `app_ids` is accepted only while the receiver is anonymous. An authenticated browser cookie also attaches that account on connect. A successful registration returns `op: "registered"`, `request_id`, `session_id`, `for` (the attached UUID or null), and `app_ids`. Account subscriptions still control which apps can send. `subscribe` and `watch_inbox` also attach their authenticated identities. Several active sessions may belong to the same user; the shared native daemon can attach more than one account to its connection. Sign-in credentials remain separate from ephemeral receiver sessions.

Each command has a unique `request_id`; the server echoes it on the response. A send uses the prepared UTF-8 JSON string as its `body`:

```json
{"op":"send","request_id":"send-1","proof_token":"<app-token>","body":"{\"type\":\"dm.messageReceived\",\"for\":\"si:assistant\",\"key\":\"message-456\",\"data\":{}}"}
```

Hook and inbox operations are account scoped:

```json
{"op":"subscribe","request_id":"sub-1","session_token":"<ting-session>","webhook_ids":[]}
{"op":"subscribe","request_id":"sub-2","session_token":"<ting-session>","webhook_ids":["hook-1"]}
{"op":"watch_inbox","request_id":"watch-1","session_token":"<ting-session>"}
{"op":"ack","request_id":"ack-1","webhook_id":"hook-1","message_ids":["message-1"],"kind":"delivery"}
{"op":"unsubscribe","request_id":"unsub-1","webhook_ids":["hook-1"],"pause":true}
```

An empty subscription authenticates the session before hook registration. ACK `kind` is `delivery` or `read`. Browser inbox watches authenticate with the HttpOnly cookie and allowed Origin; JavaScript never needs the session credential.

Unsolicited messages include:

- Direct delivery: `{"op":"tings","session_id":"...","tings":[...]}`.
- Daily batch: `{"op":"silent_digest","session_id":"...","digest_id":"...","tings":[...]}`. Large batches may span several events.
- Durable hook delivery: `tings` or `silent_digest` with `webhook_id`, `session_id`, and `tings`; both use the same delivery/read ACKs.
- `inbox_changed` as a content-free refresh hint, or `paused` with `webhook_ids` and `reason`.

Direct session events have no hook ACK. Refetch account history after reconnecting; durable webhooks retain their existing delivery/read ACK protocol. Silent arrivals produce no immediate delivery hint.

The server sends a protocol ping every five seconds and removes sessions that fail to pong within five seconds. Disconnect also removes the session and its anonymous app grants. Reconnecting creates a new session ID. Use bounded reconnect backoff: 1, 2, 4, 8, 16, then 30 seconds, with jitter capped at 30 seconds. Reset the failure count after a healthy minute. Restore only still-authorized attached hooks; a connected transport never extends session authority. The server revalidates account authority during long-lived connections.

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

`Prepared::new` validates exact bytes and `Prepared::write` creates a private request file. `execute` sends those bytes once. `WebSocket::send(&request, token)` uses the same authorization and body. `register(app_ids, optional_session_token)`, `watch_inbox(session)`, `unsubscribe(hooks, pause)` and `ack(hook, messages, kind)` are explicit operations. `session_id()` returns the current receiver address. The client does not auto-acknowledge, auto-register recipients or retry uncertain mutations. It preserves events in a bounded queue and closes rather than dropping events on overflow.

## Retention and errors

Read or delivered silent notifications normally live for one calendar month; unread non-silent notifications live for three calendar months from immutable `created_at`. Pending unread silent tings are retained until a scheduled delivery, including while the schedule is disabled or no eligible sessions are active. Unread digest copies awaiting hook acknowledgement are also retained. Once those exceptions end, the original creation time determines expiry. Local queues preserve old digest copies until the server confirms they are gone and recheck delivery eligibility after preference changes.

Errors use `{ "error": { "code", "message", "hint", "retryable", "details" } }`. Invalid input is rejected before mutation; auth and resource ownership are checked for every operation. A timeout may follow acceptance, so clients preserve original request bytes and keys. Temporary overload may return 429 or 503, and clients honor retry guidance without assuming acceptance.

Ting does not collect or send telemetry. Accounts refresh credentials and browser session tokens remain private server state.
