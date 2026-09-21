# Ting API — v1 implementation contract

This is the contract to build. Examples use sample IDs and timestamps. [cli.md](cli.md) defines the matching commands; [understanding.md](understanding.md) and [iam.md](iam.md) contain the original notes. The decisions here include the later product changes.

## Product rules

- Retain read or silent tings for one calendar month, and unread non-silent tings for three calendar months, measured from their original `created_at` in UTC. Older tings and their delivery records expire automatically; no per-app or per-org quota applies within those windows.
- A disconnected recipient's tings wait quietly. No delivery-failure alerts go to the sender or recipient.
- Every registered destination receives its own copy. One destination completing delivery does not complete another destination's copy.
- The sender sees `read: true` after any webhook accepts the ting, or after the carbon views it in the browser. Read state never goes backwards.
- New types are enabled by default. Existing recipient opt-outs still apply. Silent tings stay in the drawer and are never delivered automatically.
- Every ting carries `created_at`, the UTC time Ting first stored it. It stays unchanged during retries and replay. Consumers choose processing order; timestamps do not guarantee delivery order.
- A local webhook always receives `{ "tings": [...] }`, even for one ting.
- BYO is outside Ting's v1 scope.

## Common rules

HTTP uses HTTPS and JSON. WebSockets use WSS. Local development may use HTTP/WS on loopback. JSON object keys are case-sensitive. Reject unknown request fields, duplicate JSON keys, invalid UTF-8, and wrong JSON types with `400 invalid_input`; `data` and `metadata` may contain arbitrary valid JSON values inside their required outer objects. Clients must tolerate new response fields.

IDs are opaque strings. `id` identifies a ting, subscription, or webhook in its own record. Use `org_id` and `app_id` when identifying an org or app. Resolve org handles through IAM and compare/store their canonical identity; changing a display name must not change ownership. Paths must URL-encode IDs; for example, `tos>dm` becomes `tos%3Edm`.

| Value | v1 rule |
| --- | --- |
| `created_at` | RFC 3339 UTC string ending in `Z`; server-assigned acceptance time, not the originating app's event time. |
| `key` | Required string, 1–200 UTF-8 bytes, no control characters. |
| Type name | `{app_id}.{service}.{event}`; maximum 255 bytes. Service/event use lowercase letters, digits, `_` or `-`, starting with a letter. The app prefix must exactly match its registered app ID. |
| Description | Nonempty text, maximum 1,000 UTF-8 bytes. |
| Lists | One page per request, `limit` default 50, range 1–100; optional `cursor`. |
| ID lists | 1–100 IDs. Repeated IDs are collapsed. Validate the whole list before changing any record. |
| Submitted ting | Maximum 256 KiB for the complete UTF-8 JSON request body, including `org_id`. |
| Delivery batch | Maximum 100 tings and 1 MiB including the WebSocket envelope. Every accepted ting must fit in a one-ting batch. |
| Ordinary HTTP request / client WebSocket frame | Maximum 1 MiB; more specific limits take precedence. |

List responses are `{ "items": [...] }`. Include `next_cursor` only when another page exists; never return it as `null`. Tings sort by `(created_at, id)` descending for listing, independently of delivery order. Other lists sort by their stable ID/name ascending. Cursors are opaque, expire after 24 hours, and bind the authenticated data context, org, filters and last position. A changed context/filter or invalid/expired cursor returns `400 invalid_cursor`. The first page fixes an upper creation boundary; later changes to read state or permissions are evaluated when each page is fetched.

Request and batch limits bound individual operations. Retained history spans one calendar month for read or silent tings, and three months for unread non-silent tings. There is no per-day send quota in v1. Temporary overload may return `429` with `Retry-After` or `503`; neither response means a ting was accepted. A lost response is uncertain: retry with the same ting key and a fresh proof.

## Authentication and login

Two credentials have different jobs:

| Credential | Used for |
| --- | --- |
| Ting session | A carbon/silicon's own orgs, inbox, preferences, hooks and settings; app management only with current Honeycomb permission. HTTP: `Authorization: Bearer <session_token>`. |
| IAM App Proof Token | Every app send, subscription registration, and app-side subscription/status query. HTTP: `Authorization: Bearer <access_proof>`. A Ting session never replaces this proof. |

An **IAM App Proof Token** here is IAM's verified, single-use `access_proof` from its OBO exchange. It identifies the issuing app, represented actor, audience, org and exact downstream request. It is not an app secret, a login token, or an arbitrary bearer token. Verify it with the official IAM client before reading app-owned data or applying an operation.

Except for public information, login initiation/session exchange and preflight, routes require their listed credential. A valid token still needs current org membership, app permission and resource ownership. Missing/invalid/expired credentials return `401`; a valid identity without permission returns `403`. Resources owned by another recipient return `404` without exposing their contents.

### Session endpoints

| Method and path | Input | Success |
| --- | --- | --- |
| `GET /v1/iam` | None; public. | `200` app information below. |
| `GET /v1/session/login` | Browser navigation; optional local `next` path, default `/`. | `302` to the configured IAM consent page, with a server-bound login attempt. |
| `GET /v1/session/callback` | IAM callback `slt` and the login-attempt state. | Exchanges the SLT, sets the session cookie, then `303` to the saved local path. |
| `POST /v1/session` | CLI: `{ "slt": "<short-lived Ting login token>" }`; required `Idempotency-Key`. | `201` session response below; safe same-attempt replay returns `200`. |
| `GET /v1/me` | Ting session. | `200 {"id":"si_123","kind":"silicon","authenticated":true}` |
| `DELETE /v1/session` | Ting session. | `200 {"authenticated":false}` after local session revocation. |
| `GET /v1/orgs` | Ting session; no selected org required. | `200 {"items":[{"id":"tos","name":"TOS"}]}` |
| `GET /v1/orgs/{org}/apps` | Ting session; optional pagination. | `200 {"items":[{"app_id":"tos>dm","name":"DM","can_manage_tings":true}]}` |

App information:

```json
{
  "app_id": "tos>ting",
  "api_version": "v1",
  "repository_url": null,
  "docs_url": null,
  "rust_package": null
}
```

Those three publication values are release configuration, not invented URLs. They must be populated before public release. Local builds may return `null`.

CLI session response — a secret-bearing response, never logged:

```json
{
  "authenticated": true,
  "id": "si_123",
  "kind": "silicon",
  "session_token": "<opaque Ting session credential>"
}
```

Flow: CLI receives a Ting-bound IAM SLT → Ting backend exchanges it using its app secret → backend keeps IAM access/refresh tokens encrypted → CLI receives only an opaque Ting session credential. Never ship Ting's app secret or IAM refresh tokens in the CLI. The CLI prints only identity/status and saves its session credential privately.

Use IAM's official SLT exchange and rotating refresh APIs, including their idempotency support. Persist one exchange/refresh operation key before calling IAM and reuse it after an uncertain response. Serialize refreshes per session. A repeated session exchange must match the original key and SLT hash; replay the same encrypted response for at most two minutes, never create another session. After that, obtain a new SLT.

Revalidate IAM authority before protected HTTP operations and every 30 seconds for a live receiver. Refresh expired app access tokens server-side. IAM unavailability returns `503` and pauses delivery; it must not be reported as a successful logout. A definitively revoked session returns `401 session_expired`, stops its subscriptions, and requires login again. Logout invalidates the Ting session first and durably schedules IAM refresh-family revocation; it affects no other identity's session.

The browser uses a `ting_session` cookie instead of a readable token: HttpOnly, Secure, SameSite=Lax, Path `/`, with no Domain attribute. Bind the IAM callback to a random one-use state and private browser login cookie; include that state in the callback `redirect_uri` sent to IAM and expire the attempt after ten minutes. Reject callbacks without that binding and reject external `next` URLs. Accept authenticated browser mutations only from the configured frontend origin and require JSON; CORS must never allow arbitrary credentialed origins. Never put Ting sessions or IAM refresh tokens in URLs.

### Proof-bound app calls

IAM binds a proof to the exact method, registered path and SHA-256 of the body bytes. App endpoints therefore use fixed paths and put `org_id` in the JSON body:

| IAM endpoint ID | Registered path | Method |
| --- | --- | --- |
| `tings.send` | `/v1/tings` | `POST` |
| `subscriptions.register` | `/v1/subscriptions` | `POST` |
| `subscriptions.query` | `/v1/subscriptions/query` | `POST` |
| `subscriptions.revoke` | `/v1/subscriptions/revoke` | `POST` |
| `sent.query` | `/v1/sent/query` | `POST` |

Publish these in Ting's IAM OBO catalog, with empty metadata schemas and explicit `critical: true`. Calling apps declare the matching external scopes, obtain required review and user consent, then mint proofs with the official IAM SDK. Recipient registration derives consent and identity from the verified proof actor. Later app sends still require their own proof and an active stored recipient grant.

Verify audience `tos>ting`, issuing app, selected org, endpoint, exact body bytes and current IAM authorization. Do not infer permission from an unverified token payload. The issuing app must match `app_id` or the type's app prefix. Proof actor and target recipient may differ on sends; the stored app-to-recipient grant authorizes the target. On subscription registration they must match.

A proof lasts at most 60 seconds and can be consumed once. Do not retry IAM proof verification after an uncertain result. Return `503 proof_verification_uncertain` without executing the operation. A client retry needs a fresh proof over the same operation body, using the same Ting key. Authentication still runs on idempotent replays.

The Rust client exposes prepare → obtain proof → execute. Preparation returns the exact bytes, method, path and SHA-256. It performs no network mutation. The CLI's `--write-request` and `--request-file` expose that flow. Never reserialize a signed request body between preparation and submission.

## Test requests

The same endpoints and code handle tests. An explicit test request supplies:

```json
{
  "IAM_TEST_APP_SECRET": "<Ting test app secret>",
  "X-Testing-Environment-Key": "<IAM environment key>"
}
```

Both headers are required together on initial test login and proof-bound app calls. The CLI takes their values from `IAM_TEST_APP_SECRET` and `IAM_TEST_KEY`. An incomplete pair returns `400 test_context_required`. The app ID remains server-configured `tos>ting`.

Ask IAM to validate that secret and environment key, using its testing-context API. Use the verified environment UUID to partition Ting sessions, types, grants, tings, keys, preferences, hooks and local state. One deployment/database can serve them all; a test actor never accesses production records. A supplied secret is a verification override, not proof of identity or an auth bypass.

A Ting session remembers its verified test context server-side, so later session requests may omit both headers. If supplied again, both must match that session's verified environment and current credentials. Invalid or retired test credentials never fall back to production. Every send still requires its IAM App Proof Token.

WebSocket `send` and `subscribe` may carry the same header pair in `headers`. Context belongs to that request or subscription, never the whole shared socket. Other authenticated identities remain unaffected. Never echo, log, or forward either secret to a local webhook.

## Ting types

These routes require a Ting session with current Honeycomb permission to manage the named app. App visibility alone is insufficient.

| Method and path | Input | Success |
| --- | --- | --- |
| `GET /v1/orgs/{org}/apps/{app}/types` | None; view permission. | `200 {"items":[<type>]}` |
| `POST /v1/orgs/{org}/apps/{app}/types` | `type`, `description`. | `201` saved type; identical existing definition returns `200`, different definition returns `409 type_exists`. |
| `PATCH /v1/orgs/{org}/apps/{app}/types/{type}` | `description` only. | `200` updated type. |

```json
{
  "type": "tos>dm.msg.received",
  "description": "A new direct message arrived.",
  "defaults": {"carbon": true, "silicon": true}
}
```

The type name cannot change. Register a new type for another event. `defaults` is read-only and always true for both kinds of recipient. It does not grant permission to send, clear existing opt-outs, or decide the recipient. There is no type deletion endpoint in v1.

## Recipient subscriptions

A subscription is one app's permission to notify one recipient in one org and data context.

| Method and path | Authentication and input | Success |
| --- | --- | --- |
| `POST /v1/subscriptions` | IAM OBO App Proof. Body: `org_id`, `app_id`, optional `for` assertion. | `201` subscription below; an already active grant returns `200`. |
| `GET /v1/orgs/{org}/subscriptions` | Ting session; current recipient only. Optional `app_id`, `for`, pagination. | `200 {"items":[<subscription>]}` |
| `POST /v1/subscriptions/query` | App Proof. `org_id`, `app_id`; optional `for`, `limit`, `cursor`. | `200 {"items":[<subscription>]}` for the issuing app only. |
| `DELETE /v1/orgs/{org}/subscriptions/{id}` | Ting session; owning recipient only. | `200 {"id":"sub_123","active":false}` |
| `POST /v1/subscriptions/revoke` | App Proof. `org_id`, `id`; subscription must belong to the issuer. | Same result as DELETE. |

```json
{
  "id": "sub_123",
  "app_id": "tos>dm",
  "for": "si_123",
  "active": true
}
```

Registration uses the proof's issuer as the app and its represented actor as the recipient. An optional `for` must match. No second proof or body `obo_token` is needed. Store the verified grant, not the proof itself. A newly verified registration can reactivate a revoked grant using the same subscription ID.

The grant covers current and future types. Recipients may opt out by app, service or type. Revocation blocks new sends and delivery of pending tings under that grant; it preserves stored history. Reactivation resumes eligible pending deliveries. Repeated revocation is harmless. Neither revocation nor muting can retract work already accepted by a webhook.

## Send a ting

### `POST /v1/tings`

Requires an IAM App Proof Token. The signed body is:

```json
{
  "org_id": "tos",
  "type": "tos>dm.msg.received",
  "data": {"message_id": "dm_456", "text": "Hello"},
  "metadata": {},
  "for": "si_123",
  "key": "dm-456"
}
```

All fields except `metadata` are required. `data` and `metadata` are objects; omitted metadata means `{}`. `isi` is optional information, never an authentication identity. Reject caller-assigned `id`, `created_at`, `silent` or `read`.

Apps submit one ting at a time. Ting batches complete records during delivery; it never appends later events to the original ting's data or metadata.

First acceptance — `202`:

```json
{
  "id": "msg_123",
  "created_at": "2026-09-22T10:00:00Z",
  "status": "accepted",
  "key": "dm-456",
  "silent": false
}
```

Flow: verify proof → verify type ownership and recipient grant → apply preferences → atomically save ting, intended deliveries and idempotency result → return acceptance → deliver when eligible. Acceptance means durable storage, not receipt or reading. Muted tings are still accepted with `silent: true`.

### Idempotency

The key scope is `(verified environment, org, issuing app, key)`. Retain its request fingerprint and original response for **14 days from first acceptance**. Retries do not extend this window. Compare the normalized request (`metadata` omitted equals `{}`; JSON key order and whitespace do not matter). Changed recipient, type, data or metadata returns `409 idempotency_conflict`. A valid retry returns the original response with `200`, including its original timestamp and silent flag.

Keep the key record, ting and initial delivery state in one durable database transaction. Redis may cache results, but cache eviction/restarts must not shorten the guarantee. Concurrent requests with the same key cannot create two tings. If the transaction cannot be committed, do not report acceptance. After 14 days, key reuse may create a new ting with a new ID; the old ting remains stored until its applicable one- or three-month retention cutoff.

A retry still needs a fresh valid App Proof and current access to its original result. Return an existing identical accepted result before applying a now-revoked recipient grant; it creates no new send or delivery. With no existing result, an inactive grant blocks acceptance.

Delivery replay uses permanent ting IDs, not the expiring producer key. Consumers deduplicate repeated work by ting ID within their receiving context. Keep accepted-ID records for as long as a replay could occur, or make the work safe to repeat.

## Sent tings and inbox

| Method and path | Input | Success |
| --- | --- | --- |
| `POST /v1/sent/query` | App Proof. `org_id`, `app_id`; optional `for`, `type`, `read`, `limit`, `cursor`. | `200 {"items":[<ting>]}` for that issuer. |
| `POST /v1/sent/query` | App Proof. `org_id`, `app_id`, `id`; optional `deliveries_cursor`, no list filters. | `200` full ting with `deliveries`. |
| `GET /v1/orgs/{org}/inbox` | Ting session; current recipient only. Optional `app_id`, `type`, `read`, `silent`, pagination. Omit `silent` to include both kinds. | `200 {"items":[<ting>]}` |
| `GET /v1/orgs/{org}/inbox/{id}` | Ting session; owning recipient. | `200` full ting. |
| `POST /v1/orgs/{org}/inbox/read` | Ting session; `{ "message_ids": ["msg_123"] }`. | `200 {"message_ids":["msg_123"],"read":true}` |

A full ting:

```json
{
  "id": "msg_123",
  "created_at": "2026-09-22T10:00:00Z",
  "type": "tos>dm.msg.received",
  "data": {"message_id": "dm_456", "text": "Hello"},
  "metadata": {},
  "for": "si_123",
  "key": "dm-456",
  "silent": false,
  "read": false
}
```

Sent detail adds:

```json
{
  "deliveries": [
    {"webhook_id":"hook_123","delivery_acked":true,"read_acked":false}
  ]
}
```

`delivery_acked` describes the current receiver subscription's receipt; it resets on subscription replacement. `read_acked` is permanent completion for that hook. No deliveries is `[]`. A large `deliveries` list uses `deliveries_cursor` in the sent-detail request and `deliveries_next_cursor` in the result, omitted on the last page; pages contain at most 100 hooks.

`read` becomes true after any webhook read ACK or the recipient's explicit view acknowledgement. A browser calls `/inbox/read` when the carbon opens a ting or its contents become visible in the foreground drawer. Background fetch, preload, a hidden tab, or an unopened count badge does not count. The CLI exposes this as `inbox mark-read`; list/get operations never mark read by themselves. Silent tings can be viewed and marked read in the drawer.

Validate every submitted ID against the current recipient and org before applying a read request. Repeated requests are harmless. This changes overall read state, not another webhook's pending copy. Carbons may also use CLI webhooks; their webhook acceptance counts as read even if they have not viewed the browser entry. Neither form of read means the consumer finished processing.

## Notification preferences

Ting session required; all operations affect only its recipient.

| Method and path | Input | Success |
| --- | --- | --- |
| `GET /v1/orgs/{org}/preferences` | Optional `app_id`, and either `service` or `type`; pagination. | `200 {"items":[<preference>]}`; only explicit overrides. |
| `PUT /v1/orgs/{org}/preferences` | Preference object below. | `200` saved override. |
| `DELETE /v1/orgs/{org}/preferences` | Query `app_id`, optional `service` or `type`. | `200 {"app_id":"tos>dm","service":null,"type":"tos>dm.msg.received","reset":true}` |

```json
{
  "app_id": "tos>dm",
  "service": null,
  "type": "tos>dm.msg.received",
  "enabled": false
}
```

Writes require `app_id`. Set neither service nor type for an app-wide override; never set both. A type must belong to the named app. `enabled` is a boolean. Repeated reset succeeds even if no override exists.

Precedence: event override → service override → app override → enabled. New types inherit these settings; registering one never erases an opt-out. Muting stores future tings silently and pauses delivery of existing matching non-silent tings. Re-enabling can resume those non-silent pending tings. Historically silent tings remain silent forever and never auto-replay. Muting does not revoke the app's grant.

## Webhook registrations

A hook is a stable destination owned by one recipient. A receiver is one shared WebSocket connection, identified by a temporary `receiver_id`. URLs and secrets stay on the local system; the cloud stores IDs, owner and delivery progress only.

Ting session required. For a new attachment, the receiver must already have authenticated that same session/recipient using WebSocket `subscribe`. Recovering an already accepted creation result uses the retry rule below.

| Method and path | Input | Success |
| --- | --- | --- |
| `POST /v1/orgs/{org}/webhooks` | `{"receiver_id":"recv_123"}`; required `Idempotency-Key`. | `201` registration below; same creation retry returns `200`. |
| `GET /v1/orgs/{org}/webhooks` | Pagination; owning recipient only. | `200 {"items":[<webhook>]}` including disconnected, paused and detached hooks. |
| `PATCH /v1/orgs/{org}/webhooks/{id}` | `receiver_id`, optional `takeover` boolean, default false. | `200` attached registration. Explicitly reattaches a detached/paused hook. |
| `DELETE /v1/orgs/{org}/webhooks/{id}` | No body. | `200 {"id":"hook_123","removed":true}`; repeated detach is harmless. |

```json
{
  "id": "hook_123",
  "receiver_id": "recv_123",
  "for": "si_123",
  "state": "connected",
  "pending": 0
}
```

`state` is `connected`, `disconnected`, `paused`, or `detached`. Connected means authenticated and subscribed, not that the local webhook is healthy. POST/PATCH attaches the registration and subscribes it on the already authenticated receiver; a following explicit subscribe is harmless. Persistent `paused` means the local retry cutoff; temporary auth/policy invalidations use `disconnected` until a permitted resubscription. A non-connected registration has `receiver_id: null`. `pending` counts this hook's unfinished copies, including ones temporarily held by preferences or permissions; it is not an overall unread count.

One hook has one active receiver binding. A different live binding returns `409 hook_in_use` unless the owner explicitly requests `takeover: true`. Takeover atomically invalidates the old binding. ACKs from its old connection cannot change the new binding's progress. Normal reconnect may bind a disconnected hook, but may not revive a deliberately detached or paused hook.

Creation uses a client-generated idempotency key retained for 14 days within recipient/org/context. Save the key and original body before the HTTP request so a lost response cannot create duplicate destinations. Commit the creation and cached result together. Same key with a changed request returns `409 idempotency_conflict`. After recipient authentication, look up an accepted creation before checking receiver liveness: an exact retry can recover the stable hook ID even after its original receiver disconnects. Then PATCH that ID onto the current receiver. If no creation exists and the original receiver is gone, return `409 receiver_gone` without creating a hook; the caller may start a fresh creation attempt. Repeating PATCH with the same binding is harmless. Use ownership checks before returning any cached result.

New hooks get all eligible overall-unread history plus new tings. Existing hooks resume their own unfinished copies, even if another destination already made the ting globally read. Preserved hooks accumulate eligible copies during disconnection or detachment. Creating the initial backlog and assigning concurrent new sends must have no gap. Silent tings are excluded; grants and preferences govern whether pending copies may currently be forwarded.

Unhook detaches the route, retaining its ID and pending state. It invalidates any active binding and notifies its receiver with `reason: "hook_detached"`. That receiver stops forwarding and must not automatically resubscribe. Explicit PATCH reattaches it. After local disk loss, list existing hooks and reattach their IDs with newly supplied local URLs. Creating replacement IDs would not recover copies already globally read elsewhere.

Flow: save the intended local URL, secret and creation key → open socket → `subscribe` with empty hook list to authenticate → create/attach hook over HTTP → save its returned ID → receive batches. Delivery can race the HTTP response; durably queue it by hook ID until the creation result links it to its local URL, and do not forward until that link is verified. The stable hook ID survives daemon restarts and URL changes.

## WebSocket API

### `GET /v1/ws?protocol=v1`

Upgrade returns `101`. Unsupported versions return `400 unsupported_protocol` with `error.details.supported_protocols: ["v1"]`. Use one shared socket per system daemon; each identity authenticates separately. No authority is gained by opening the socket. The daemon serves one API origin while any subscriptions or requests are active. A conflicting WebSocket origin fails with `daemon_api_conflict` and cannot reconnect other identities to another server. When idle, it may close the old socket before connecting to another origin. HTTP calls may independently use another configured origin.

Server greeting:

```json
{"op":"ready","receiver_id":"recv_123","protocol":"v1"}
```

Client requests include a nonempty `request_id` of at most 100 bytes; replies repeat it. Request IDs correlate replies, not business idempotency. Each subscription is scoped to verified context, org, recipient and hook. `subscribe` replaces the listed hooks' bindings on this receiver, leaving other identities and unlisted hooks alone.

| Operation | Fields besides `op`, `request_id` | Success reply |
| --- | --- | --- |
| `subscribe` | `org_id`, `session_token`, `webhook_ids` (0–100); optional test `headers`. Empty list authenticates before registration. | `{"op":"subscribed","request_id":"req_1","for":"si_123","webhook_ids":["hook_123"]}` |
| `unsubscribe` | `org_id`, `webhook_ids` (1–100); optional `pause`, default false. `pause: true` records the local retry cutoff until explicit reattachment. | `{"op":"unsubscribed","request_id":"req_2","webhook_ids":["hook_123"]}` |
| `send` | `proof_token`, `body` (the exact prepared `/v1/tings` JSON as a string); optional test `headers`. | `{"op":"accepted","request_id":"req_3","id":"msg_123","created_at":"2026-09-22T10:00:00Z","status":"accepted","key":"dm-456","silent":false}` |
| `ack` | `org_id`, `webhook_id`, `message_ids`, `kind`: `delivery` or `read`. | `{"op":"acked","request_id":"req_4","message_ids":["msg_123","msg_124"],"webhook_id":"hook_123","kind":"delivery"}` |
| `watch_inbox` | `org_id`; browser uses its session cookie, other clients supply `session_token`. Replaces this socket's previous inbox watch. | `{"op":"watching_inbox","request_id":"req_5","org_id":"tos"}` |

For `send`, parse the `body` string without changing its original UTF-8 bytes. Verify the proof as the logical `POST /v1/tings` operation over those bytes. Use the same validation and database transaction as HTTP. This keeps proof-bound sends usable over the prewarmed socket; no extra connection is opened.

Example subscription:

```json
{
  "op": "subscribe",
  "request_id": "req_1",
  "org_id": "tos",
  "session_token": "<Ting session credential>",
  "webhook_ids": ["hook_123"]
}
```

Unsubscribe/ACK require this connection's currently authorized hook binding; knowing its ID is insufficient. Validate the whole operation before changing state. Hook IDs must belong to the authenticated recipient and org. Repeating a successful ACK is harmless. Replacing a subscription resets unfinished receipt ACKs and replays unfinished copies; it never resets completed read ACKs.

### Browser inbox updates

The browser uses one WebSocket and `watch_inbox` for its selected org. Validate the configured frontend Origin on browser upgrades and authenticate its HttpOnly session cookie; no JavaScript-readable session token is needed. A watch can only see its authenticated recipient's inbox and follows the same 30-second authority revalidation as other subscriptions.

After an eligible non-silent arrival or a read-state change, send `{"op":"inbox_changed","org_id":"tos"}`. Silent arrivals do not trigger a notification; the carbon can fetch them explicitly in the drawer. This is a refresh hint, not a ting delivery or read ACK. Unsent hints may be combined. The browser refetches the visible inbox and acknowledges only tings the carbon actually views. It also refetches after starting a watch or reconnecting, so missed hints cannot hide unread history. Switching org replaces the watch. Closing the socket removes it.

Session expiry, lost org permission or unavailable authorization stops the watch and sends `paused` with an empty webhook list. The browser retries `watch_inbox` after transient failures with the connection backoff below, refetching on success. A revoked session requires login; denied org access requires selecting an allowed org. A live socket alone must not leave a transiently paused watch stuck.

This does not create a webhook registration or block new browser updates behind unread items. CLI users receive live tings through their registered webhooks and access the same drawer/read actions through inbox commands.

### Incoming batches

This is the server-to-daemon format, not the local webhook body. It retains its routing fields:

```json
{
  "op": "tings",
  "org_id": "tos",
  "webhook_id": "hook_123",
  "tings": [
    {
      "id": "msg_123",
      "created_at": "2026-09-22T10:00:00Z",
      "type": "tos>dm.msg.received",
      "data": {"message_id": "dm_456", "text": "Hello"},
      "metadata": {},
      "for": "si_123",
      "key": "dm-456"
    },
    {
      "id": "msg_124",
      "created_at": "2026-09-22T10:00:01Z",
      "type": "tos>dm.msg.received",
      "data": {"message_id": "dm_457", "text": "Are you there?"},
      "metadata": {"isi": "planner"},
      "for": "si_123",
      "key": "dm-457"
    }
  ]
}
```

A batch is nonempty and belongs to one recipient and hook. Only one batch is active per hook; hooks progress independently. Send a ready single ting immediately, without waiting to fill a batch. Keep the remaining backlog on the server. Reconnect may group the same IDs differently. No processing order is imposed.

### The two ACKs

| Kind | When sent | Effect |
| --- | --- | --- |
| `delivery` | Daemon has durably queued every listed ting. | Suppresses server retries for those IDs while that subscription stays active. They remain unfinished. |
| `read` | Webhook returned `204` after accepting the whole local batch, and the daemon saved that result. | Permanently completes this hook's listed deliveries and sets overall read true. |

Before a delivery ACK, retry an unacknowledged batch after ten seconds. After it, the daemon owns local retry scheduling; a live socket alone is not a webhook acceptance. Only a read ACK completes delivery. ACKs may arrive out of order and affect only their listed IDs. A late delivery ACK cannot undo a read ACK. ACKs never delete tings; only the one-/three-month retention cleanup does.

Validate every ACK against the current authorized receiver binding and the hook's delivery records. A delivery ACK needs an offer on the current subscription. A read ACK may settle an ID previously offered to this same hook, including a prior subscription or a ting now muted or blocked by a revoked app grant: it records past acceptance and does not authorize another delivery. Keep that offered history until the delivery is complete or the ting reaches its applicable one- or three-month retention cutoff. Completed IDs may be acknowledged again. Unknown/unoffered IDs return `400 invalid_ack` with no partial update. Persist ACK state before replying. The daemon retains queued/accepted records until the server confirms the read ACK; a lost reply retries the ACK, not the already accepted webhook work. Old receiver bindings still cannot ACK after takeover.

Disconnect, authorization loss or subscription replacement releases unfinished receipt state for replay. The server remains authoritative if local disk is lost. On local disk write failure, do not send a delivery ACK; stop forwarding for that hook until durable storage works.

### Control and recovery

WebSocket ping every 30 seconds; close the connection if no pong within ten seconds. Reconnect using delays of 1, 2, 4, 8, 16, then 30 seconds with up to 20% jitter, capped at 30 seconds; reset after one healthy minute. A transport reconnect restores all still-authorized attached subscriptions. A user's explicit reconnect command resumes only that identity's selected-org hooks.

The daemon checks forwarding workers every five seconds. A due job more than 15 seconds late is restarted from its durable queue; scheduled retry waits do not count as a stall. A stalled hook cannot block other hooks or require resetting their socket. Replacing only its subscription can recover its server backlog if local state cannot be trusted. A process-level stall must fail the daemon health check and be restarted by the OS service manager.

Control messages use `op: "paused"`, `org_id`, `webhook_ids`, and `reason` (`session_expired`, `authorization_unavailable`, `permission_changed`, `preference_changed`, `retry_cutoff`, `binding_replaced`, or `hook_detached`). Identity-wide pauses list all affected hook IDs, split into groups of at most 100. The daemon stops new local attempts for those hooks. Already dispatched requests may finish, but must not authorize new work. A replaced or detached binding never reconnects itself.

Preference/grant changes invalidate affected active hook subscriptions and enqueue their control messages before the change operation returns. The daemon stops new attempts when it receives the invalidation, keeps completed acceptance results, drops other local offered batches, then resubscribes; the server re-evaluates eligibility. Other eligible tings on that hook continue. Revoked IAM sessions remain paused until login. If IAM revalidation is unavailable or the socket disconnects, pause local forwarding until authorization is restored. A request already handed to the webhook before the daemon observes the change cannot be recalled.

## Local webhook call

The daemon POSTs to the locally registered URL with `Content-Type: application/json` and `Ting-Webhook-Id: hook_123`. If configured, it also sends `Authorization: Bearer <webhook-secret>`. It never forwards Ting/IAM credentials. URLs and secrets never leave the machine.

```json
{
  "tings": [
    {
      "id": "msg_123",
      "created_at": "2026-09-22T10:00:00Z",
      "type": "tos>dm.msg.received",
      "data": {"message_id": "dm_456", "text": "Hello"},
      "metadata": {},
      "key": "dm-456"
    },
    {
      "id": "msg_124",
      "created_at": "2026-09-22T10:00:01Z",
      "type": "tos>dm.msg.received",
      "data": {"message_id": "dm_457", "text": "Are you there?"},
      "metadata": {"isi": "planner"},
      "key": "dm-457"
    }
  ]
}
```

`204 No Content` means every ting in the batch was durably accepted. Processing may happen later. Any other status, timeout, lost response or partial acceptance leaves the batch retryable. A receiver that already accepted an ID must safely accept it again without repeating its effects. There is no per-item HTTP response or exactly-once guarantee.

| Behavior | v1 rule |
| --- | --- |
| URL | Explicit user-supplied HTTP/HTTPS URL; no URL credentials or fragment. Localhost is the normal case. Do not follow redirects or forward secrets elsewhere. |
| Request timeout | Ten seconds, including connection and response. |
| Failed delivery | Retry after 60 seconds. Persist the first-failure time and next attempt; restart must not reset them. |
| Retry cutoff | 12 hours of continuous failure for this hook; send unsubscribe with `pause: true`. A successful payload resets the failure window. Persist the pause locally before sending it; after an offline cutoff, register the pause before any automatic resubscription. Keep every ting recoverable. No failure alerts. |
| Resume | Explicit webhook reattachment or `daemon reconnect`; resets that hook's failure window. A paused endpoint returning without registering cannot be detected after probes stop. |
| Optional health probe | User supplies `--health-url`. HEAD every five seconds during active recovery, two-second timeout, same configured secret, no redirects. |
| Probe results | Any 2xx permits a payload attempt once 60 seconds have elapsed since its last failure. Unhealthy probes replace payload retries with waiting. 405/501 disables probing and restores the 60-second payload schedule. A probe never ACKs a ting. |

Without a health URL, use the normal 60-second payload retry. Health probing stops at the 12-hour cutoff. Pause only the failing hook, not all destinations of its recipient. Local worker supervision remains responsible while server retries are suppressed.

## Bug reports

### `POST /v1/bugs`

Requires a Ting session; selected org is optional. Store an explicit `bug_report` event in Ting's backend Space Station table. Telemetry opt-out does not disable an explicitly requested report.

```json
{
  "title": "Webhook stays disconnected after restart",
  "body": "Steps to reproduce and the observed error.",
  "pr_ref": null,
  "attachments": [
    {"name":"daemon.log","encoding":"utf-8","content":"Webhook request timed out.\n"}
  ]
}
```

Success — `201`:

```json
{"id":"bug_123","submitted":true,"pr_ref":null}
```

`title` is required, 1–200 UTF-8 bytes. `body` is required nonempty UTF-8 text. Optional `pr_ref` is an absolute HTTPS pull-request URL, maximum 2,048 bytes. Attachments default to `[]`, maximum eight. Each has a basename, encoding `utf-8` or `base64`, and its actual content. Validate base64 strictly. Maximum complete report JSON is 192 KiB; reject oversized reports with `413`, never truncate them. The CLI reads all supplied files before submitting anything.

The backend adds verified reporter ID, context, app version if supplied in `Ting-Client-Version`, and a generated report ID. It must receive Space Station's durable ingest ACK for that record before returning `submitted: true`. Use the raw acknowledged ingest interface, not the telemetry helper that sanitizes/truncates values or merely queues them locally. Preserve report and attachment contents exactly within the limit. A Space Station rejection or uncertain result returns `503 report_storage_unconfirmed`; do not claim submission. Do not automatically retry a report with an uncertain result, since Space Station may already have stored it.

Automatic diagnostics exclude tokens, secrets, ting data/metadata and attachments. Profile telemetry opt-out controls that profile's CLI and attributed daemon diagnostics. Backend operational diagnostics are service-controlled; the CLI does not expose an org-wide telemetry switch in v1. Explicit bug contents are included only because the user supplied them.

## Errors

HTTP errors use the status below and one JSON body:

```json
{
  "error": {
    "code": "recipient_not_registered",
    "message": "tos>dm does not have permission to notify si_123 in tos.",
    "hint": "Register this recipient with an IAM OBO proof before sending.",
    "retryable": false
  }
}
```

`code`, `message`, `hint` and `retryable` are always present. Optional `details` carries machine-readable context such as `webhook_id` when registration succeeded but local setup failed, or `supported_protocols` for a version mismatch. A retryable error does not permit reusing a consumed proof. HTTP responses include a non-secret `Ting-Request-Id` for support. Errors must not expose credentials or another recipient's data.

WebSocket request errors use `{"op":"error","request_id":"req_1","error":{...}}`. Malformed frames without a usable request ID use `request_id: null`. Frame errors do not close other identities' valid subscriptions; oversized/non-JSON transport messages may close the connection with the standard WebSocket error code. Subscription pauses use the separate `paused` control frame above.

| HTTP | Codes / action |
| --- | --- |
| `400` | `invalid_input`, `invalid_cursor`, `invalid_ack`, `test_context_required`, `unsupported_protocol`. Correct the request. |
| `401` | `authentication_required`, `session_expired`, `invalid_proof`, `proof_expired`, `proof_consumed`. Obtain the correct credential; expired/consumed proofs need a new proof. |
| `403` | `permission_denied`, `recipient_not_registered`, `test_context_mismatch`. No side effect. |
| `404` | `not_found`. Missing or inaccessible resource. |
| `409` | `idempotency_conflict`, `type_exists`, `hook_in_use`, `receiver_gone`. Resolve the stated conflict. |
| `413` | `payload_too_large`. The operation was not accepted. |
| `429` | `temporarily_rate_limited`. Include `Retry-After` in seconds. |
| `503` | `dependency_unavailable`, `storage_unavailable`, `proof_verification_uncertain`, `report_storage_unconfirmed`. Do not report success; follow the operation's retry rule. |

## Implementation and release checks

Use a stateless Rust client for the API, a CLI backed by one system daemon, and a SolidJS browser app. Browser actions must also be available through the CLI. Identity-scoped local IPC requires that profile's session credential and validates the OS caller's profile access; a directory or identity name alone is not authorization. Do not create one daemon or network socket per `SILICON_HOME`.

The latency target is p95 below 100 ms from a proof-ready app's WebSocket send to the start of the local webhook call, with healthy prewarmed connections and no queued backlog. Include proof verification and durable acceptance in that measurement. The corresponding HTTP-send target is p95 below three seconds. Consumer processing time and disconnected recovery are separate. Record the reference deployment/network conditions when measuring these targets.

Additive response fields are compatible within v1. Removed fields, changed meanings or incompatible request shapes require a new major API/protocol version and a documented migration. Published CLI/client/server versions must have a tested compatibility matrix before Honeycomb rolls out an update.

Use the official IAM client for SLT exchange, refresh, introspection, OBO verification and test-context verification. The concrete contracts above were checked against installed IAM documentation (`iam docs client/login`, `iam docs api/obo`, `iam docs api/testing-environments`). Honeycomb supplies app visibility/management permission. When a dependency is unavailable, deny the dependent operation with a recoverable error; never assume authority. Configure Space Station's backend, CLI/daemon, browser analytics and browser events tables separately. Its current raw ingest ACK is required for explicit bug reports.

Release configuration must supply the real API/frontend origins, IAM app registration and approved scopes/OBO catalog, backend-held app credentials, Honeycomb integration, Space Station tables/keys, database and encryption keys, repository/docs URLs and published Rust package. Serve the browser and API on the same site, using custom domains or a same-origin proxy, so the SameSite=Lax session cookie works; CORS does not make cross-site cookies available. The installer and Honeycomb package must start the one system daemon and publish supported platform instructions. These are deployment bindings; no placeholder may silently point at a live service.

Before release, demonstrate:

1. Every send rejects missing, wrong-audience, expired, consumed or request-mismatched proofs over both transports; test credentials cannot access production records.
2. Concurrent same-key sends and a crash during commit produce one accepted ting within 14 days; expiry permits a new ID without deleting the old ting.
3. Disconnects before either ACK, lost ACK replies, daemon restart, worker stall, disk loss and the 12-hour cutoff all preserve unfinished copies. One failed hook cannot block another.
4. A new hook gets unread history; an old hook also gets its own copies read elsewhere. No gap occurs during registration or concurrent sends.
5. Muting/revocation pauses queued forwarding, silent tings never replay, browser preload never marks read, actual viewing does, and one destination's read never erases another's pending copy.
6. Local payloads contain only `tings`; timestamps and IDs survive rebatching; limits reject oversized requests before acceptance without imposing storage quotas.
7. CLI/API schemas, pagination and errors agree, and a bug report returns success only after Space Station acknowledges the unmodified report and attachment contents.
