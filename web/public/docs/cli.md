# Ting CLI

Ting 0.3 uses Silicon Accounts for Carbon and Silicon identities and Silicon Apps for application discovery. Account inboxes, preferences and webhooks belong to an account; live receiver sessions may also be anonymous. Applications use scoped Silicon Accounts app tokens to register recipients and send notifications.

## Install and discover

Install the published package with Silicon Apps:

```sh
silicon-apps install ting --yes
ting --help
ting accounts --json
ting login status --json
```

`ting accounts` returns Ting's application ID, Accounts and Apps URLs, API version, repository, documentation and Rust package links. `ting --version` reports the installed version. Every command supports `--help`; all results support the global `--json` option.

Global options are `--api-url ORIGIN`, `--json` and `--version`. The API origin is chosen from `--api-url`, `TING_API_URL`, then the published default, `https://backend.ting.teamofsilicons.com`. Use HTTPS except for loopback development. URLs cannot contain credentials, path prefixes, query strings or fragments.

`ting docs` reads this bundled reference offline. `ting docs --topic development` reads the API reference. With `--json`, documentation is returned as `{ "topic": "usage", "content": "..." }`.

## Sign in and stay signed in

Obtain a short-lived Ting sign-in token from Silicon Accounts, then use one of:

```sh
ting login --token-stdin
ting login --slt TOKEN
ting login TOKEN
ting login status --json
ting logout
```

Prefer stdin to keep the token out of shell history. Ting exchanges the token with Accounts and saves an opaque Ting session privately in the selected profile. It prints account identity and expiry, never credentials. The backend privately keeps and validates the long-lived Accounts session token, so opening another terminal, restarting the daemon or restarting the browser does not sign you out. The session ends when its actual expiry is reached, access is revoked or you log out.

A successful login returns `authenticated`, `id`, `uuid` and `expires_at`. Use canonical IDs such as `c:alice` and `si:assistant`; immutable account UUIDs identify ownership even when a handle changes. `login status` checks the server and reports `authenticated: false` with exit code 0 when no valid session exists. Network errors remain errors instead of being reported as a logout.

The CLI saves each login attempt's exact short-lived token and idempotency key privately before exchange. If the outcome is uncertain, use `ting login --recover` with the original API origin. A successful recovery receives the original session. If Accounts consumed the token before Ting could save a response, the server reports `login_outcome_unknown`; obtain a fresh short-lived token. That error clears the local pending attempt without replacing a previous working session. A previous working session is kept until the replacement succeeds. Replacing a session stops that previous session's local forwarding; explicitly reattach its hooks to the new session.

`logout` clears any pending login attempt, stops this profile's local forwarding, requests remote session revocation and removes its saved session. If revocation cannot be confirmed, it reports the error while keeping the local profile signed out. It does not stop other identities' receivers or delete durable notification history.

Set `SILICON_HOME` to an existing directory to use a separate private profile for another account. A saved session belongs to its API origin and cannot be silently sent to a different server.

## Receive notifications

```sh
ting login --token-stdin
ting webhook http://localhost:3000/ting
ting daemon status
ting inbox list --all
```

The shared daemon starts on demand. Each Carbon or Silicon manages its own inbox, settings and hooks. URLs, webhook secrets and health probes remain on the local system; Ting stores only stable hook IDs and delivery state.

The daemon keeps a durable local queue. It only acknowledges delivery to Ting after saving the queued records, and it marks them read only after the local destination returns HTTP 204. A transport connection does not extend session authority. Expired or revoked sessions pause delivery until explicit recovery.

The daemon uses one shared WebSocket. Active receivers pin it to one API origin; another origin returns `daemon_api_conflict`. HTTP sends can use another origin with the matching token. Local Unix sockets and Windows pipes verify the operating-system account and private profile credential.

## Active receiver sessions

```sh
ting listen --anonymous --app dm
ting listen
ting sessions list
```

`listen --anonymous --app dm` opens an anonymous session and opts it into that app even when a login is saved. It prints the `session_id`, then incoming events until interrupted. Repeat `--app` to allow more applications. `listen` attaches the saved account when available; its existing subscriptions authorize senders. No login is needed for anonymous listening. Without `--anonymous`, a saved account is attached; combining that account with `--app` is rejected. With no saved login, `listen --app dm` also works anonymously. The command exits on transport failure; rerun it to create a new session. `sessions list` shows the signed-in account’s active receiver sessions.

Every WebSocket connection has its own session ID. The server pings every five seconds, requires a pong within five seconds, and removes lost sessions. Reconnect creates a new ID. The CLI responds automatically. Sign-in credentials persist separately from these live receiver sessions.

## Applications and notification types

```sh
ting apps list
ting types list --app dm
ting types register --type dm.messageReceived --description 'A new message arrived' --schema '{"type":"object"}'
ting types update --type dm.messageReceived --description 'A message is available' --schema @message-schema.json
# An operator-assigned prefix uses the canonical app explicitly.
ting types register --app silicon-cells --type cells.databaseFailing --description 'A database operation failed' --schema '{"type":"object"}'
```

Silicon Apps provides the application catalog and author identity. Reading an application's catalog entry does not grant send or management permission. Type registration and updates normally use a saved Ting session belonging to an authorized app author. Registration also accepts `--app-token-stdin` or `--app-token-file PRIVATE_PATH` with a `types.manage` App verification proof; that path needs no Ting login. Supply `--type`, `--description`, and `--schema` directly with either credential option.

Type names are exactly `<app-id>.<tingid>`: a Silicon Apps ID (or its operator-assigned prefix) followed by a nonempty ASCII alphanumeric notification name. Use `--app` with the canonical app ID when registering or updating a type under an assigned prefix. No deeper nesting is accepted. Every definition includes a description and JSON Schema for `data`; updates may change either or both. `--schema` accepts an inline JSON Schema object or boolean, or `@FILE`. Legacy three-part types remain visible but cannot be edited or used for new sends. Type lists are public and need no login. Carbon and Silicon defaults are allowed; recipients can make a sender, app or type silent or blocked.

## Approve a sender

An app registers each consenting recipient with a delegated Silicon Accounts app token scoped to `subscriptions.register`. The token identifies the source application, target Ting audience and represented account.

```sh
ting subscriptions register --app dm --for si:assistant --write-request register.json
ting subscriptions register --request-file register.json --app-token-stdin
```

`--for` is optional for registration; when supplied, it must match the delegated recipient. Do not use a general login token or an unrelated account's app token.

A recipient can inspect and revoke their grants with their saved login:

```sh
ting subscriptions list --app dm
ting subscriptions revoke SUBSCRIPTION_ID
ting subscriptions required-delivery SUBSCRIPTION_ID
ting subscriptions required-delivery SUBSCRIPTION_ID --enabled true
```

Apps can use the same preparation flow to query or revoke their own grants:

```sh
ting subscriptions list --app dm --for si:assistant --write-request subscriptions.json
ting subscriptions list --request-file subscriptions.json --app-token-stdin
ting subscriptions revoke SUBSCRIPTION_ID --app dm --write-request revoke.json
ting subscriptions revoke --request-file revoke.json --app-token-stdin
```

App queries require `subscriptions.read`; revocation requires `subscriptions.revoke`. A revoked grant stops future sends and delivery. Notification mute is a separate preference and does not revoke the grant.

## Send a notification

Prepare the request before supplying the app token:

```sh
ting send --type dm.messageReceived --for si:assistant --key message-456 \
  --data '{"message_id":"dm_456"}' --metadata '{}' --write-request send.json
ting send --request-file send.json --app-token-stdin
```

The app token must come from Silicon Accounts, target Ting and include `tings.send`. Sending requires an active recipient subscription, or an anonymous session that registered the app. The `data` object must satisfy the current type schema. It does not require the sender to log into the Ting CLI. Use `--from c:alice` to attribute the notification to a user; omit it for an app-originated ting. User attribution is asserted by the verified sending app.

`--for si:assistant` reaches all of that account’s active sessions. Add `--session-id SESSION_ID` to reach only its specified active session. To send to an anonymous receiver, supply `--session-id` without `--for`. Session-only sends resolve to the attached user if there is exactly one; multi-user sessions require `--for`. A lost or mismatched session is rejected.

Use exactly one `--app-token-stdin` or `--app-token-file PRIVATE_PATH` when executing a prepared request. The request contains no token. `--write-request` creates a private file and refuses to overwrite an existing file. Execution sends its original bytes; it cannot be combined with request-building flags. Tokens are never printed or placed in URLs.

`--data` and `--metadata` accept a JSON object or `@FILE`; arrays and null are invalid. Metadata defaults to `{}`. Requests reject duplicate keys and unknown fields. The notification body is limited to 256 KiB and the operation key to 200 bytes.

Preserve the request file and key after an uncertain response. Retry with a currently valid scoped token and the same bytes. An accepted notification keeps its ID, creation time and original response for the idempotency window; changed content with the same key is an error.

For the shared WebSocket transport:

```sh
ting send --request-file send.json --app-token-stdin --transport websocket
```

The daemon starts if needed, sends one request and returns the correlated result. It does not silently retry an uncertain send.

## Sent history

These operations authenticate the sending app, independently of any recipient login:

```sh
ting sent list --app dm --for si:assistant --limit 50 --write-request sent.json
ting sent list --request-file sent.json --app-token-stdin
ting sent get MESSAGE_ID --app dm --write-request sent-one.json
ting sent get --request-file sent-one.json --app-token-stdin
ting sent mark-read MESSAGE_ID --app dm --key read-456 --write-request read.json
ting sent mark-read --request-file read.json --app-token-stdin
```

`sent list` supports `--type`, `--read true|false`, `--for`, `--limit` and `--cursor`. `sent get` accepts `--deliveries-cursor`. Reading requires `tings.read`. `sent mark-read` and `sent mark-unread` require `tings.read.update`, an operation key and 1 to 100 unique IDs owned by the app.

List output excludes `data` and `metadata`; `get` returns full content. Read-state mutations are idempotent and do not change creation time or resurrect expired records. Use a new key for a new intended state change.

## Inbox and preferences

```sh
ting inbox list --all --limit 50
ting inbox list --app dm --type dm.messageReceived --read false
ting inbox list --silent
ting inbox get MESSAGE_ID
ting inbox mark-read MESSAGE_ID OTHER_MESSAGE_ID
```

List and get do not mark notifications read. `--all` includes silent records; it does not fetch every page. `--silent` returns silent records only. Pagination uses `--cursor` with the same account and filters.

```sh
ting preferences list --app dm
ting preferences list --mode blocked
ting preferences set --app dm --mode silent
ting preferences set --from c:alice --mode blocked
ting preferences set --app dm --type dm.messageReceived --mode allowed
ting preferences reset --app dm --type dm.messageReceived
```

Across matching rules, blocked wins over silent, then allowed. A sender rule uses `--from` alone; a type rule uses `--type` and optionally the canonical `--app` (the prefix is used when omitted). Operator-assigned prefixes require the canonical app explicitly. Blocked tings never enter the recipient’s history or delivery queues. Silent tings wait for a daily digest.

```sh
ting silent-schedule get
ting silent-schedule set --time 18:30 --timezone Asia/Kolkata
ting silent-schedule set --enabled false
```

The initial default is enabled at 00:00 in the device’s detected IANA time zone. The CLI and daemon report the operating system’s time zone automatically; if detection fails, Ting falls back to 09:00 UTC. Detection initializes an untouched schedule once and preserves later manual changes. Use `silent-schedule set` to choose a different daily time or zone. Time zones are IANA names. Disabling the daily batch keeps pending silent tings on hold. If the scheduled time arrives without eligible active sessions, pending tings wait for the next schedule. Reconnecting does not immediately send a missed batch.

## Local webhooks

```sh
ting webhook http://localhost:3000/ting --secret-stdin
ting webhook list
ting webhook http://localhost:3001/ting --id HOOK_ID --health-url http://localhost:3001/health
ting webhook http://localhost:3001/ting --id HOOK_ID --clear-secret --clear-health-url
ting unhook HOOK_ID
ting daemon reconnect
```

Omitted secret and health settings preserve their current values when reattaching a hook. `--clear-secret`, `--clear-health-url` and `--takeover` require `--id`. Use `--takeover` only to explicitly replace another receiver binding.

The destination receives `{"tings":[...]}` with the `Ting-Webhook-Id` header and optional bearer secret. Each notification includes `id`, immutable `created_at`, `type`, `data`, `metadata`, `key`, `for`, `from`, `session_id`, `silent`, and `silent_digest`. App-originated `from` and unspecified `session_id` are null. `silent_digest: true` means the daily schedule released the notification. Return exactly HTTP 204 after durable acceptance. Forwarding is at least once; deduplicate IDs at your destination. After HTTP 204, the daemon does not retransmit a copy whose read receipt is explicitly rejected because its authority was removed; that ting may remain unread on the server. Ting read state is not an application-specific delivery receipt.

`unhook` detaches a destination while retaining its ID and unfinished history. New hooks include eligible unread history; reattached hooks resume their own unfinished copies. After local disk loss, list existing hooks and reattach their stable IDs with the local URL and secret.

Failed destinations retry with backoff. An optional health probe can postpone a retry. Repeated failure for 12 hours pauses the hook; `daemon reconnect` explicitly resumes this account's paused or attached hooks. `daemon start` requires no login; `daemon status` does not start the daemon.

Upgrading old local receiver state preserves destinations and queued history, but pauses previous bindings until explicitly reattached under the current Accounts identity.

## Required delivery

A recipient must explicitly enable required delivery on a subscription before its app can use `--delivery required`. This legacy capability does not override silent or blocked preferences. Without that opt-in, Ting rejects the send. Subscription revocation and session authority still apply; the app token cannot opt the recipient in.

## Retention and errors

Ting normally retains read or delivered silent notifications for one calendar month and unread non-silent notifications for three calendar months, measured from immutable `created_at`. Pending unread silent tings remain on hold until a scheduled delivery even if the schedule is off or no session is active. Unread digest copies awaiting hook acknowledgement are retained too. Once those exceptions end, original creation time controls expiry. The daemon keeps old scheduled digest copies until the server confirms their removal, and rechecks eligible copies after a preference change.

Ting does not collect or send telemetry.

Success exits 0, invalid arguments or input exit 2, and operational failures exit 1. With `--json`, success goes to stdout and an `{"error":{"code","message","hint","retryable","details"}}` envelope goes to stderr. A transport failure may follow server acceptance: use the preserved key and exact request when retrying.
