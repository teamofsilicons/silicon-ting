# Ting CLI

The v1 implementation contract, based on [understanding.md](understanding.md), [iam.md](iam.md), and the latest product decisions. These commands are not implemented yet. Examples show JSON output; without `--json`, print the same information in readable text. The CLI and daemon use the stateless Rust client library.

For server requests and delivery messages, see [api.md](api.md).

## Common rules

- Every command and command group supports `--help`: purpose, examples, related commands, subcommands and flags. Help works offline.
- Every command that returns data supports `--json`. Global flags may appear before or after the command.
- Recipient and app-management requests use the saved Ting session. App-proof commands use the request/proof flow below and do not require CLI login. Local help, docs, configuration and org-selection inspection do not authenticate a server request.
- API URL selection follows `--api-url URL` → `TING_API_URL` → the published default. Supply an origin with no path prefix; route paths already include `/v1`. Use HTTPS; HTTP is allowed only for loopback development. Reject URL credentials, non-root paths, query strings and fragments. The production URL must be assigned before release; do not guess one.
- Org selection follows `--org ORG` → `SILICON_ORG` → the saved org from `ting org use`. Empty values are invalid. Org-scoped commands fail if no org is selected. Help, version, docs, IAM info, login, logout, config, bug reports and `org list` do not need a selected org.
- `--data JSON` and `--metadata JSON` accept literal JSON objects or `@PATH` to read a UTF-8 JSON file. Arrays and `null` are invalid. Metadata defaults to `{}`. No implicit `ISI` value is inserted; include it in metadata when needed.
- List commands return one page. `--limit N` defaults to `50` and accepts `1..100`; `--cursor CURSOR` continues with the same authenticated context, org and filters. Cursors expire after 24 hours; an invalid or expired cursor is an error, not a fresh first page. `next_cursor` appears only when another page exists. Empty lists return `{ "items": [] }`. `inbox --all` includes silent tings; it does not fetch every page.
- Ting lists sort by `(created_at, id)` descending; other lists sort by stable ID/name ascending. Listing order is separate from consumer-chosen processing order.
- Inbox and sent lists show summary fields; `get` returns the full ting. The API may return more fields than the CLI list displays.
- Every stored, returned, and delivered ting carries `created_at`, an immutable UTC timestamp assigned by Ting when it first stores the ting. Retries and replays keep that timestamp. Consumers choose their processing order; Ting does not promise strict delivery order.
- Success exits with `0`, invalid commands or input with `2`, and operational or API failures with `1`. With `--json`, write exactly one success value to stdout, or one error object to stderr with empty stdout. Progress and diagnostics never appear in JSON stdout.
- Foreground network requests and subscription confirmation wait at most 30 seconds. A timeout returns an operational error; it does not mean a mutation failed or authorize an automatic retry with the same proof.
- Reject unknown flags, missing required values, invalid booleans and conflicting input sources before making requests. Reject duplicate JSON keys, invalid UTF-8, unknown request fields and wrong JSON types using the API's schemas and limits. Boolean values are exactly `true` or `false`.
- Secret input flags read stdin or a UTF-8 file to EOF and remove one final LF or CRLF. Reject empty values and embedded newlines. Only one input may consume stdin. Never print tokens, webhook secrets, `IAM_TEST_APP_SECRET` or `IAM_TEST_KEY`.

Identity-specific files live inside `$SILICON_HOME/.ting/`. If `SILICON_HOME` is absent, use the real home directory: `~/.ting/`. An explicitly empty or unusable home is an error. Resolve relative file arguments against the caller's working directory. Create private directories with mode `0700` and files with `0600`, or equivalent owner-only Windows ACLs; replace settings atomically.

There is one daemon per system, managed by the platform service manager. Its discovery endpoint is independent of `SILICON_HOME`; shared state lives in the service owner's real `~/.ting-daemon/`. Concurrent CLI starts must connect to the same service, never launch a daemon per profile. Recipient IPC validates the local caller, profile access and that profile's private Ting session credential; naming another profile directory does not authenticate its identity. A proof-only send passes its supplied proof for server verification and gives no authority over recipient hooks.

The daemon uses one shared, prewarmed WebSocket and keeps each identity's permissions separate. Carbons and silicons use the same CLI and webhook commands, each managing only their own hooks, inbox and settings. A stored session is tied to its API URL and verified normal or test context; an override cannot silently reuse it against another server or context.

Active subscriptions or requests pin the shared socket to one API origin. A WebSocket operation targeting another origin fails with `daemon_api_conflict`; it never opens another socket or disrupts existing work. HTTP requests may target another origin with its matching credentials. When idle, the daemon can close the old socket before switching origins.

## Start receiving

```sh
ting login --token-stdin
ting org use tos
ting webhook http://localhost:3000/ting
ting daemon status
ting inbox list --all
```

Provide a short-lived login token from the official IAM CLI or IAM consent flow to the first command. Ting never asks for an IAM password. Complete the stdin input before running the next command.

Flow: login → select org → register a local webhook → daemon subscribes for this identity → Ting sends eligible past unread tings and new tings → daemon calls the webhook → webhook ACK completes delivery.

Use complete IAM actor IDs such as `c:alice0` or `si:assistant` for `--for`, and bare application IDs such as `dm` for `--app`. Select the organization separately; a Silicon ID no longer contains its organization. An app must also have permission to send to this identity through an OBO subscription.

After identifier migration, log out and log in again with current IAM metadata, using the same `SILICON_HOME` and API origin. Keep queued daemon deliveries, stable webhook IDs and saved exact request files intact. Reconcile uncertain operations before changing identity-bearing request bytes or retrying under a new key. An old testing selector must be refreshed for that same IAM world; never fall back to production.

## Help and app information

| Command | Output |
| --- | --- |
| `ting --help` | Root help, common flows and command groups. |
| `ting COMMAND --help` | Help for that command or group. |
| `ting --version` | Installed CLI version, for example `0.1.0`; with `--json`, `{ "version": "0.1.0" }`. |
| `ting iam --json` | `{ "app_id": "ting", "api_version": "v1", "repository_url": null, "docs_url": null, "rust_package": null }` |
| `ting docs` | Bundled usage documentation. |
| `ting docs --topic development` | Bundled API and integration documentation. |
| `ting docs --topic usage --json` | `{ "topic": "usage", "content": "..." }` |

`docs` defaults to topic `usage`; valid topics are `usage` and `development`. The JSON shape is the same for both topics. Bundled documentation works offline. Repo, online docs, Rust package and installer locations must be assigned before release. The published documentation must provide one verified `curl` and shell installation command that installs the CLI and shared service without logging anyone in. Do not publish invented URLs.

## Login

| Command | Output |
| --- | --- |
| `ting login TOKEN` | `{ "authenticated": true, "id": "si:assistant" }` |
| `ting login --token-stdin` | Same output; reads the short-lived IAM token from stdin. |
| `ting login status` | `{ "authenticated": true, "id": "si:assistant" }` |
| `ting logout` | `{ "authenticated": false }` |

Use exactly one login source: positional `TOKEN` or `--token-stdin`. Only an IAM short-lived login token can log in; a password, OBO proof or App Proof Token cannot. A different identity cannot replace an occupied profile: run `logout` first or select a separate `SILICON_HOME`.

Flow: CLI posts `{ "slt": "..." }` to `POST /v1/session` → Ting exchanges it with IAM using Ting's app secret → Ting keeps IAM access and refresh tokens on the backend → CLI privately stores the returned opaque Ting session token. Login prints only authentication status and identity. Later recipient requests use that Ting session token in `Authorization: Bearer ...`.

Before session exchange, generate and privately persist an `Idempotency-Key` for that login attempt. If the response is lost, `ting login --recover` reuses the privately saved key and exact SLT request, even after two minutes. Keep the original API and testing selector. Do not generate a new key or replace an uncertain attempt. A failed recovery remains pending; a new login does not cancel it. Logout preserves credentials until revocation is confirmed and reports `login_cleanup_pending` when an unresolved login must first be recovered. Never print the SLT, idempotent secret-bearing response or session token.

`login status` checks the saved session through `GET /v1/me` without starting the daemon. No saved or valid session returns `{ "authenticated": false, "id": null }` with exit `0`; a network or server failure returns an error, not a false logged-out result. Expired backend IAM credentials are refreshed by Ting where IAM permits; the CLI never receives them.

`logout` calls `DELETE /v1/session`, removes the local session and detaches this identity's daemon subscriptions. It does not stop the daemon, remove retained webhook registrations, or log out other identities. With no session it succeeds unchanged. If server revocation cannot be confirmed, stop local forwarding and clear the local token, then report the failure; do not claim confirmed remote revocation.

## Organisations and apps

| Command | Output |
| --- | --- |
| `ting org list` | `{ "items": [{ "id": "tos", "name": "TOS" }] }` |
| `ting org use tos` | `{ "org_id": "tos", "saved": true }` |
| `ting org current` | `{ "org_id": "tos", "source": "saved" }` |
| `ting apps list` | `{ "items": [{ "app_id": "dm", "name": "DM", "can_manage_tings": true }] }` |

Org access comes from IAM. App visibility comes from Honeycomb permissions. Seeing an app does not grant permission to change it or send its tings. `apps list` lists the selected organization’s app catalog, not all apps that can notify its recipients. `app_id` is globally unique; senders can belong to another organization.

`org current` reports the effective org and its source: `--org`, `SILICON_ORG` or `saved`; missing selection is an input error. `org use ORG` validates access to its explicit argument and saves it as the fallback. It does not change `SILICON_ORG` or override it. Use `--org` to override the environment for one command.

Changing org selection does not silently unsubscribe existing receivers in other orgs.

## Ting types

```sh
ting types register --type 'dm.msg.received' \
  --description 'A new message arrived'
```

| Command | Output |
| --- | --- |
| `ting types list --app 'dm'` | `{ "items": [{ "type": "dm.msg.received", "description": "A new message arrived", "defaults": { "carbon": true, "silicon": true } }] }` |
| `ting types register --type TYPE --description TEXT` | The registered type record shown above. |
| `ting types update --type TYPE --description TEXT` | The updated type record. |

`types list` requires `--app`. Register and update require `--type` and a nonempty `--description`; derive the app from the type's app component. Update changes only the description. The type name stays fixed. `defaults` is read-only and always true for both carbon and silicon; apps cannot change it.

Type names use `{app_id}.{service}.{past-tense-event}`. These commands use the saved Ting session; Ting checks app visibility or management permission through Honeycomb. Only recipients can turn their notifications off or override their settings. Select the app’s owning organization for type management. Select the recipient’s organization for sends, subscriptions, sent status/read updates, inboxes, preferences and webhooks. The type stays in its owner catalog; it does not need to be registered again for each recipient organization.

```sh
ting --org tos types list --app 'dm'
ting --org bricks send --type 'dm.msg.received' \
  --for si:assistant --key dm-456 --data '{"message_id":"dm_456"}' \
  --write-request send.json
```

Obtain an IAM proof bound to the prepared `bricks` request, then execute it with `ting --org bricks send --request-file send.json --proof-token-stdin`.

## Permission to receive from an app

| Command | Output |
| --- | --- |
| `ting subscriptions register --app 'dm' --for si:assistant --write-request register.json` | Request-file information, as described below. |
| `ting subscriptions register --request-file register.json --obo-stdin` | `{ "id": "sub_123", "app_id": "dm", "for": "si:assistant", "active": true }` |
| `ting subscriptions list` | `{ "items": [{ "id": "sub_123", "app_id": "dm", "for": "si:assistant", "active": true }] }` |
| `ting subscriptions revoke sub_123` | `{ "id": "sub_123", "active": false }` |

Registration uses one request-bound IAM OBO App Proof Token. It proves both the issuing app and the recipient's permission; no second app credential or saved recipient login is needed. Read it using exactly one of `--obo-stdin` or `--obo-file PATH`. The recipient comes from its verified actor; an optional prepared `--for` assertion must match. Never put the proof in the request body.

The grant covers the app's current and future ting types. New types are enabled automatically, while existing recipient app, service and event opt-outs still apply.

List accepts optional `--app APP_ID` and `--for ID` filters. Without preparation or app proof flags, list and revoke use the saved recipient session and can only act on that recipient's grants. To act as the app, prepare the fixed app route with `--write-request`, then execute with `--request-file` and exactly one of `--proof-token-stdin` or `--proof-token-file PATH`. App list preparation requires `--app`; app revoke preparation requires one subscription ID.

Revocation blocks new sends and further delivery under the grant; it cannot retract tings already accepted by a webhook.

## Prepare and authenticate app requests

IAM App Proof Tokens are bound to the exact request method, registered path and SHA-256 of the body bytes. They expire within 60 seconds and are single-use. A Ting session, login token or test secret cannot replace one.

All app-proof commands use the same two modes:

1. `--write-request PATH` builds and validates the body from flags, writes its exact UTF-8 JSON bytes to a new private file, and prints the information below. It makes no request and needs no proof or login. An existing output file is an error. Select an org through the normal org rules.
2. Obtain a proof for that exact method, path and body through the official IAM CLI or SDK, then use `--request-file PATH` with the command's proof input. Read the bytes once, validate them without changing them, and send those same bytes. Do not parse and reserialize the file.

Preparation output:

```json
{
  "method": "POST",
  "path": "/v1/tings",
  "request_file": "/work/send.json",
  "body_sha256": "<SHA-256 of the exact file bytes>"
}
```

`--write-request` and `--request-file` are mutually exclusive. Proof inputs are forbidden in preparation mode. Execution requires a request file and a fresh proof; it rejects body-building flags and positional body arguments. Global context flags, `--json`, and send's `--transport` remain allowed. The file must contain `org_id`; if an org is selected through flags, environment or saved settings, it must match. File mode can use its own `org_id` when no org is otherwise selected. Never rewrite the file's org.

| Command | Registered method and path | Body built in preparation mode |
| --- | --- | --- |
| `send` | `POST /v1/tings` | `org_id`, required `--type`, `--for`, `--key`, `--data`; optional `--metadata`, default `{}`. |
| `subscriptions register` | `POST /v1/subscriptions` | `org_id`, required `--app` as `app_id`; optional `--for`. |
| `subscriptions list` as app | `POST /v1/subscriptions/query` | `org_id`, required `--app` as `app_id`; optional `--for`, `--limit`, `--cursor`. |
| `subscriptions revoke` as app | `POST /v1/subscriptions/revoke` | `org_id`, required positional subscription ID as `id`. |
| `sent list` | `POST /v1/sent/query` | `org_id`, required `--app` as `app_id`; optional `--for`, `--type`, `--read`, `--limit`, `--cursor`. |
| `sent get` | `POST /v1/sent/query` | `org_id`, required `--app` as `app_id`, required positional ting ID as `id`; optional `--deliveries-cursor` as `deliveries_cursor`. |
| `sent mark-read` / `sent mark-unread` | `POST /v1/sent/read` | `org_id`, required `--app` as `app_id`, 1–100 positional ting IDs as `message_ids`, required `--key`; `read` is `true` / `false` respectively. |

List preparation writes its effective limit, including the default `50`; omit unused optional filters. A `get` body cannot contain list filters, `limit` or `cursor`; only its separate `deliveries_cursor` is allowed for detail pagination. Request files must match the selected command's schema. Sending body JSON is at most 256 KiB; validate size before asking IAM for a proof or sending it. File paths, tokens and proofs are never part of the body.

Do not automatically retry a request with a used proof. If the response is uncertain, obtain a fresh proof for the same body bytes. For `send`, retain the same ting key: Ting returns the original accepted ting if it already stored the request. For `sent mark-read` and `sent mark-unread`, retain the same operation key to recover the original response without overwriting a later read-state change. The caller obtains each proof; Ting never stores the sending app's secret.

## Send, inspect and update sent tings

```sh
ting send --type 'dm.msg.received' --for si:assistant --key dm-456 \
  --data @message.json --metadata @metadata.json --write-request send.json --json
# Obtain an IAM App Proof Token for the prepared method, path and body.
ting send --request-file send.json --proof-token-stdin --json
```

```json
{ "id": "msg_123", "created_at": "2026-09-22T10:00:00Z", "status": "accepted", "key": "dm-456", "silent": false }
```

Execution requires exactly one proof source: `--proof-token-stdin` or `--proof-token-file PATH`. An IAM App Proof Token is required for HTTP, WebSocket and test sends. `--transport http|websocket` defaults to `http`; preparation is identical for both.

Each send submits one ting. HTTP posts the exact file bytes to `/v1/tings`. WebSocket sends those same bytes as the frame's `body` string through the daemon's shared connection, using the same logical `POST /v1/tings` proof binding. It does not open a second socket. Both transports use the same permission checks.

Flow: validate sender and recipient permission → store ting → return its ID → deliver to active receivers if enabled. Acceptance means stored, not read.

Reuse the same key and a fresh proof when retrying the same send. Ting retains the key record for 14 days in a durable database transaction with the ting and initial delivery state. Redis may cache results, but cache eviction or restart cannot shorten the guarantee. Within that period, the same key and normalized request returns the original result; changed content produces a conflict. This limit applies only to idempotency keys: the tings themselves stay for one calendar month when read or silent, or three months while unread and non-silent, measured from their original creation time. See [api.md](api.md) for key scope and expiry behavior.

| Command | Output |
| --- | --- |
| `ting sent list --app 'dm' --write-request sent-list.json` | Request-file information. |
| `ting sent list --request-file sent-list.json --proof-token-stdin` | `{ "items": [{ "id": "msg_123", "created_at": "2026-09-22T10:00:00Z", "type": "dm.msg.received", "for": "si:assistant", "key": "dm-456", "silent": false, "read": false }] }` |
| `ting sent get msg_123 --app 'dm' --write-request sent-get.json` | Request-file information. |
| `ting sent get --request-file sent-get.json --proof-token-stdin` | The full ting record and its delivery status, shown below. |
| `ting sent mark-read msg_123 msg_124 --app 'dm' --key read-456 --write-request read.json` | Request-file information. |
| `ting sent mark-read --request-file read.json --proof-token-stdin` | `{ "message_ids": ["msg_123", "msg_124"], "read": true }` |
| `ting sent mark-unread msg_123 --app 'dm' --key unread-456 --write-request unread.json` | Request-file information. |
| `ting sent mark-unread --request-file unread.json --proof-token-stdin` | `{ "message_ids": ["msg_123"], "read": false }` |

Sent-list preparation accepts `--for ID`, `--type TYPE`, `--read true|false` and pagination flags. Each query execution needs fresh app proof; a saved recipient session cannot inspect the app's sent history. `--proof-token-file PATH` is an alternative to stdin for every sent command.

`sent mark-read` and `sent mark-unread` require an IAM `sent.read` proof over `POST /v1/sent/read`; no recipient Ting login or receiver is needed. Preparation requires `--app`, a unique operation `--key`, and 1–100 ting IDs. Duplicate IDs are collapsed. The request file's `read` value must match the selected command. Ting validates all IDs before changing any: each must still be retained and belong to the issuing app in the proof's organization and environment. Any missing, expired or out-of-scope ID returns `404` with no partial update; an `app_id` that differs from the proof issuer returns `403`.

Use the same operation key and fresh proof after an uncertain response. Ting keeps its original response for 14 days within the app/org/environment and `sent.read` operation, separately from send keys. Replaying it does not reapply the update or undo a later read-state change. Changed content with that key returns `409 idempotency_conflict`; use a new key for a new intended change. These updates never reset `created_at` or resurrect expired tings. Marking an older ting read may shorten its remaining retention to zero.

Sent detail returns at most 100 entries in `deliveries`. If more remain, preserve its `deliveries_next_cursor` in CLI output. Prepare another `sent get` request with `--deliveries-cursor CURSOR`, obtain a fresh proof and execute it to fetch the next delivery page. Omit `deliveries_next_cursor` on the final page; do not replace it with the list-page `next_cursor`.

```json
{
  "id": "msg_123",
  "created_at": "2026-09-22T10:00:00Z",
  "type": "dm.msg.received",
  "data": { "message_id": "dm_456", "text": "Hello" },
  "metadata": {},
  "for": "si:assistant",
  "key": "dm-456",
  "silent": false,
  "read": false,
  "deliveries": [
    { "webhook_id": "hook_123", "delivery_acked": true, "read_acked": false }
  ]
}
```

Overall `read` becomes true when a destination newly completes a read ACK or a carbon actually views the ting in the browser. The sending app may also set it read or unread, so the flag is not proof of recipient viewing. App changes update the recipient's browser inbox through its normal change hints; they do not complete or reset any hook's delivery/read ACKs or resend completed copies. A new valid read ACK or later recipient view can set read again; repeating a completed hook ACK cannot undo an app's unread update. New hooks still receive eligible retained overall-unread history. A webhook read ACK means acceptance, not that the silicon finished its work.

## Inbox, including silent tings

| Command | Output |
| --- | --- |
| `ting inbox list` | Non-silent tings: `{ "items": [{ "id": "msg_123", "created_at": "2026-09-22T10:00:00Z", "type": "dm.msg.received", "for": "si:assistant", "key": "dm-456", "silent": false, "read": false }] }` |
| `ting inbox list --silent` | Only silent tings, using the same list format. |
| `ting inbox list --all` | Both silent and non-silent tings, using the same list format. |
| `ting inbox get msg_123` | Full ting: `id`, `created_at`, `type`, `data`, `metadata`, `for`, `key`, `silent`, `read`. |
| `ting inbox mark-read msg_123` | `{ "message_ids": ["msg_123"], "read": true }` |

Lists accept `--app APP_ID`, `--type TYPE`, `--read true|false` and pagination flags. The default sends `silent=false`, `--silent` sends `silent=true`, and `--all` omits that filter. `--silent` and `--all` cannot be combined.

`mark-read` requires 1..100 ting IDs, removes duplicate IDs and posts them to `POST /v1/orgs/{org}/inbox/read`. All IDs must belong to the current recipient and org; validate the whole list before changing anything. Repeating the action is harmless. It marks overall read state and does not complete another webhook's pending copy. The browser performs the same action automatically for tings the carbon actually views.

Ting retains read or silent tings for one calendar month, and unread non-silent tings for three calendar months, measured from their original `created_at` in UTC. No per-app or per-org quota applies within those windows. Older tings and their pending delivery copies expire automatically. Reading the CLI output does not send a delivery or read ACK. Silent tings stay available here and are never automatically broadcast or replayed. In the browser, a carbon's ting becomes read when they actually view it; fetching it in the background does not count.

## Notification preferences

| Command | Output |
| --- | --- |
| `ting preferences list` | `{ "items": [{ "app_id": "dm", "service": null, "type": null, "enabled": false }] }` |
| `ting preferences set --app 'dm' --enabled false` | `{ "app_id": "dm", "service": null, "type": null, "enabled": false }` |
| `ting preferences set --app 'dm' --service msg --enabled false` | `{ "app_id": "dm", "service": "msg", "type": null, "enabled": false }` |
| `ting preferences set --app 'dm' --type 'dm.msg.received' --enabled true` | `{ "app_id": "dm", "service": null, "type": "dm.msg.received", "enabled": true }` |
| `ting preferences reset --app 'dm' --type 'dm.msg.received'` | `{ "app_id": "dm", "service": null, "type": "dm.msg.received", "reset": true }` |

Set and reset require `--app`; set also requires `--enabled true|false`. Optionally add either `--service` or `--type`, never both; a full type must belong to the selected app. Without either, set/reset applies to the app-level override. List accepts these optional filters and pagination; `--app` is optional for list.

Precedence: event override → service override → app override → enabled. Reset removes only that override and falls back to the next applicable setting. Resetting an absent override succeeds unchanged. New app types use these same settings, so registering a new type does not clear an existing opt-out.

Turning a preference off stores new tings silently. It does not revoke the app's permission to send.

## Webhooks and daemon

| Command | Output |
| --- | --- |
| `ting webhook http://localhost:3000/ting` | `{ "id": "hook_123", "for": "si:assistant", "url": "http://localhost:3000/ting", "state": "connected", "pending": 0 }` |
| `ting webhook URL --secret-stdin` | Same output; reads an optional webhook secret from stdin. |
| `ting webhook URL --id hook_123` | Same output; updates the URL or reattaches this existing registration and resumes delivery. |
| `ting webhook URL --id hook_123 --clear-secret` | Same output; removes that registration's local webhook secret. |
| `ting webhook URL --health-url HEALTH_URL` | Same output; enables the optional health probe described below. |
| `ting webhook URL --id hook_123 --takeover` | Same output; explicitly transfers an active registration from another receiver. |
| `ting webhook list` | `{ "items": [{ "id": "hook_123", "for": "si:assistant", "url": "http://localhost:3000/ting", "state": "connected", "pending": 0 }] }` |
| `ting unhook hook_123` | `{ "id": "hook_123", "removed": true }` |
| `ting daemon status` | `{ "running": true, "socket_connected": true, "pending": 0 }` |
| `ting daemon reconnect` | `{ "reconnected": true }` |

Webhook calls add a registration unless `--id` is supplied. Multiple registrations each receive a copy. IDs let the caller remove or update one destination without affecting others. `unhook` requires exactly one hook ID; never guess which destination to remove.

Before creating a hook, generate and durably save a client `Idempotency-Key`, its exact creation request and the intended URL, secret and health settings. Ting retains that key for 14 days in the recipient/org/context. Retry an uncertain creation with the same key and request, never a changed receiver ID. If the socket changed, authenticate the recipient, recover the cached hook with the original request, then PATCH its stable ID to the current receiver. If no creation exists and the original receiver is gone, `409 receiver_gone` confirms that attempt created no hook; only then start a new attempt with a fresh key and current receiver. After local disk loss, list existing hooks and explicitly reattach their IDs with newly supplied URLs; creating replacement IDs can miss copies already read elsewhere.

Creation and reattachment first authenticate the recipient on the shared receiver. The HTTP POST/PATCH then attaches and subscribes the hook, so delivery can arrive before its HTTP response. Durably queue early batches by hook ID, but do not forward them until the verified response associates that hook with the saved local destination. Persist that association before forwarding.

Webhook and optional health URLs must be absolute HTTP or HTTPS URLs without credentials or fragments. Localhost is common, but any explicitly supplied HTTP(S) destination is allowed. The daemon never follows redirects for delivery or health requests. No local webhook secret is required by default.

For an existing hook, omitted secret and health flags preserve its current settings. `--secret-stdin` replaces the secret; `--clear-secret` removes it and cannot be combined with `--secret-stdin`. Use `--clear-health-url` to disable a configured probe; it cannot be combined with `--health-url`. Clear flags and `--takeover` require `--id`.

A new webhook, including one on a new device, receives the recipient's past unread, non-silent tings allowed by current grants and preferences. An existing webhook resumes its own unfinished deliveries, even if another webhook already acknowledged those tings, subject to current grants and preferences. Preserved registrations also accumulate eligible pending tings while disconnected or unhooked.

`unhook` removes the active route, keeping the stable webhook ID, unfinished delivery state and stored ting history. Repeating it for an already detached owned registration succeeds unchanged. Explicitly run `ting webhook URL --id hook_123` to reattach it through the registration update API. A deliberately unhooked destination does not reconnect by itself, including during `daemon reconnect`.

A webhook ID such as `hook_123` stays stable across reconnects. The API's `receiver_id` is a temporary handle for the shared socket; it changes when that connection is replaced. The daemon manages it, so normal CLI output omits it.

The URL, health URL and secret stay local to the daemon. They are not sent to the cloud. A configured secret is sent as `Authorization: Bearer <webhook-secret>` on delivery; without one, no authentication header is added. Delivery also carries `Ting-Webhook-Id`. Secrets are never included in list output. Registrations managed elsewhere have `url: null` here.

One hook can have only one active receiver. Updating a registration attached to another active receiver returns `409` unless `--takeover` is supplied with `--id`. Takeover must verify the same recipient's ownership, revoke the former binding, attach the new one and replay unfinished deliveries. The new daemon uses the URL and local settings supplied by this command; it cannot fetch the old machine's secret. Without takeover, an active foreign binding cannot be edited. If no receiver is active, explicit `--id` can reattach the owned registration.

`webhook`, WebSocket sends and `daemon reconnect` start the shared daemon if needed. `state: connected` means the receiver connection and subscription are active, not that the local webhook just accepted a ting. Print connected success only after the verified response confirms the attachment. If a later local step fails after the ID is known, include it in `error.details.webhook_id` so the caller can resume with `--id`; never create a replacement hook automatically.

Registration states are `connected`, `disconnected`, `paused` and `detached`. Webhook lists include all four. Their `pending` counts unfinished copies, including those currently held by preferences or permissions; it is not an overall unread count. Paginate webhook lists through the normal list flags.

`daemon status` never starts the daemon. It reports process/socket status and the current identity's unfinished delivery-copy count in the selected org. If the daemon is absent, return `{ "running": false, "socket_connected": false, "pending": null }`. If the server count cannot be established, use `pending: null`, not zero.

`daemon reconnect` resumes this identity's attached or paused hooks in the selected org and returns `{ "reconnected": true }` only after reauthentication and subscription confirmation. It resets their local retry windows, but never reattaches explicitly unhooked destinations. A failed attempt returns an error. It does not reset the shared socket or interrupt other identities.

Behind the scenes:

1. The daemon authenticates this identity and announces its registrations on the shared socket.
2. Tings arrive; the daemon durably queues them before sending a **delivery ACK** for their message IDs and webhook ID. Before that ACK, the server retries after 10 seconds. After it, server retries stop while that subscription remains active on the socket.
3. The daemon posts a batch to the local webhook. The webhook durably accepts the whole batch and returns `204` within 10 seconds. The daemon durably records that acceptance before sending its **read ACK** for those same message IDs and webhook ID. On restart it can resend a recorded read ACK without calling the webhook again.
4. Failed or timed-out attempts remain in the durable queue. Retry every 60 seconds for up to 12 hours from that hook's first failure. Persist the failure window and next-attempt time across restarts; a successful delivery resets the window. At the cutoff pause only that hook, keeping its unfinished deliveries recoverable even if another destination already marked the ting read; resume with `webhook URL --id ID` or `daemon reconnect`. Other hooks and identities keep receiving.
5. With no connected recipient, Ting keeps the tings and waits. Disconnects and failed or partial batches leave unfinished deliveries recoverable with the same IDs. Consumers deduplicate by immutable ting ID and webhook ID, not the producer key, whose reuse window is only 14 days.

Keep queued and accepted records until the server confirms the read ACK or the ting reaches its applicable one- or three-month retention cutoff. A lost ACK response retries that ACK, not already accepted webhook work. After reauthenticating the current owned hook binding, saved acceptance records for previously offered IDs remain acknowledgeable even if a preference or grant changed meanwhile. Delivery ACKs apply only to the current offered batch.

The local webhook body keeps complete tings together. WebSocket delivery adds routing information; see [api.md](api.md).

```json
{
  "tings": [
    {
      "id": "msg_123",
      "created_at": "2026-09-22T10:00:00Z",
      "type": "dm.msg.received",
      "data": { "message_id": "dm_456", "text": "Hello" },
      "metadata": {},
      "key": "dm-456"
    }
  ]
}
```

`data` and `metadata` remain paired objects inside each ting. Live delivery can use a list of one immediately. A batch contains at most 100 tings and its serialized envelope is at most 1 MiB. Each hook has one active batch at a time; this does not promise delivery or processing order. Both ACK kinds use 1..100 `message_ids`, even for one ting, plus the webhook ID. Batching limits requests, never retained history or storage.

If a batch is only partly accepted, or its response is lost, retrying can repeat already accepted IDs. The receiver must durably deduplicate by ting ID within that hook or make its work safe to repeat. It returns `204` only when every item is durably accepted. Other HTTP statuses, redirects and timeouts do not count as read ACKs.

With `--health-url`, active recovery sends `HEAD` every 5 seconds with a 2-second timeout and the same configured webhook secret. While the probe is unhealthy, it replaces payload attempts. A `2xx` response permits a delivery retry only after at least 60 seconds since the last payload failure. `405` or `501` disables the probe and restores the ordinary 60-second payload retry schedule. Other probe failures keep waiting without sending ting payloads. A probe never ACKs a ting. Stop probing at the 12-hour cutoff.

The daemon checks its forwarding workers every 5 seconds. It restarts a due job more than 15 seconds late from the durable queue, without resetting the shared socket. Scheduled retry waits do not count as stalls. This preserves the server's delivery-ACK retry suppression while recovering stalled local work. The OS service manager restarts a daemon that fails its process health check.

WebSocket ping runs every 30 seconds with a 10-second pong timeout. Connection recovery backs off through 1, 2, 4, 8, 16 and then 30 seconds, with up to 20% jitter and a 30-second cap; reset the backoff after one healthy minute. Losing the socket or authorization pauses local forwarding until the identity reauthenticates; reconnect resubscribes retained, attached registrations. Explicitly unhooked hooks stay detached and hooks paused at the 12-hour cutoff require the explicit resume commands above.

A local webhook's read ACK means acceptance, including when a carbon uses the CLI webhook. Browser view acknowledgements record actual viewing; the sending app can also change the overall read flag. Neither overall read state nor webhook acceptance confirms finished processing. Delivery failures do not alert the sender or recipient; Ting waits quietly for recovery.

## Settings

| Command | Output |
| --- | --- |
| `ting config list` | `{ "telemetry.enabled": true }` |
| `ting config get telemetry.enabled` | `{ "key": "telemetry.enabled", "value": true }` |
| `ting config set telemetry.enabled false` | `{ "key": "telemetry.enabled", "value": false }` |

Telemetry is on by default. `telemetry.enabled` accepts only `true` or `false` and controls this profile's CLI telemetry and daemon events attributed to this identity. Backend operational diagnostics are service-level; this CLI exposes no org-admin switch for them. Automatic telemetry never includes ting bodies, attachment contents or secrets. Explicit bug reports remain available when telemetry is off. Unknown settings are rejected.

BYO providers are not supported by Ting in v1.

## Report a bug

```sh
ting bug report --title 'Webhook retry stops early' --body-file bug.md \
  --attach daemon.log --json
```

Output: `{ "id": "bug_123", "submitted": true, "pr_ref": null }`.

`--title` is required and must contain 1..200 UTF-8 bytes. Supply exactly one of `--body TEXT` or `--body-file PATH`; the report body must be nonempty UTF-8 text. Add `--attach PATH` for each attachment, up to eight files. Upload each basename and its actual contents: valid UTF-8 text as text, otherwise base64. The complete serialized request, including base64 expansion, must fit in 192 KiB. Read and validate all files before submitting; fail rather than truncate or skip anything. No files are attached implicitly.

`--pr URL` adds an optional absolute HTTPS pull request URL, at most 2,048 UTF-8 bytes, and returns it in `pr_ref`. Report submission uses the saved Ting session through `POST /v1/bugs`; it does not require an org. Reports are stored as Space Station events; `submitted: true` means Space Station durably acknowledged the report and unmodified attachment contents. This explicit command works even when telemetry is off. Other commands do not automatically submit bugs.

Do not automatically retry a bug report after an uncertain response: the backend does not yet deduplicate reports. Return an error explaining that the report may already have been stored, so the caller can decide whether to resubmit.

## Test mode and errors

For a test request, provide both `IAM_TEST_APP_SECRET` and `IAM_TEST_KEY` through the environment for the intended command. The CLI sends them as `IAM_TEST_APP_SECRET` and `X-Testing-Environment-Key` headers. Supplying only one or an empty value is an input error. The test app secret overrides Ting's configured app secret for that verification; neither value replaces the required login token, session or App Proof Token.

Successful login saves the verified environment context with the opaque Ting session. Later session commands use that context without persisting or replaying raw test secrets. An explicit test pair supplied alongside a session must verify to the same context; a mismatch fails. App-proof commands provide the pair for each test request. Normal and verified test environments use separate records on the same deployment and code paths.

WebSocket `send` carries the pair in its per-message `headers` object. Subscriptions authenticate with the saved `session_token` and its verified context. Never make a command's test settings the daemon's global environment. Tests do not create another shared socket or alter another identity's context. There is no `--env` selector; IAM verification determines the environment.

The client requests protocol `v1`; an incompatible server returns a clear upgrade error and supported versions. Do not silently change request formats.

Example error:

```json
{
  "error": {
    "code": "recipient_not_registered",
    "message": "dm does not have permission to send to si:assistant in tos.",
    "hint": "Register this recipient with a valid IAM OBO token first.",
    "retryable": false
  }
}
```

Errors identify the cause and the next step. Typical cases include missing login, missing org, denied permission, invalid JSON, reused key with different content, missing webhook registration and incompatible protocol version.

## Required automation delivery

Use `ting subscriptions required-delivery SUBSCRIPTION_ID` to inspect the current choice. The owning recipient can explicitly set `--enabled true` or `--enabled false`; this requires an existing active grant and never changes notification preferences. Revoking the grant clears this choice.

An app prepares an automation event with `ting send --delivery required` and its usual type, recipient, key and data flags. The exact request still needs a fresh `tings.send` proof. A recipient who has not opted in receives no required event: Ting rejects the new send instead of treating silent storage as delivery. Retention and destination acknowledgment semantics remain unchanged.
