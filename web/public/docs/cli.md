# Ting CLI

Ting 0.3 uses Silicon Accounts for Carbon and Silicon identities and Silicon Apps for application discovery. Every inbox, preference and webhook belongs to an account. Applications use scoped Silicon Accounts app tokens to register recipients and send notifications.

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

## Applications and notification types

```sh
ting apps list
ting types list --app dm
ting types register --type dm.msg.received --description 'A new message arrived'
ting types update --type dm.msg.received --description 'A message is available'
```

Silicon Apps provides the application catalog and author identity. Reading an application's catalog entry does not grant send or management permission. Type registration and updates require a saved Ting session belonging to an authorized app author.

Type names are `app.service.event`: a Silicon Apps ID followed by lowercase service and event names. Both Carbon and Silicon defaults are enabled. Recipients can mute apps, services or events using their own preferences.

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
ting send --type dm.msg.received --for si:assistant --key message-456 \
  --data '{"message_id":"dm_456"}' --metadata '{}' --write-request send.json
ting send --request-file send.json --app-token-stdin
```

The app token must come from Silicon Accounts, target Ting and include `tings.send`. Sending requires an active recipient subscription. It does not require the sender to log into the Ting CLI.

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
ting inbox list --app dm --type dm.msg.received --read false
ting inbox list --silent
ting inbox get MESSAGE_ID
ting inbox mark-read MESSAGE_ID OTHER_MESSAGE_ID
```

List and get do not mark notifications read. `--all` includes silent records; it does not fetch every page. `--silent` returns silent records only. Pagination uses `--cursor` with the same account and filters.

```sh
ting preferences list --app dm
ting preferences set --app dm --enabled false
ting preferences set --app dm --service msg --enabled true
ting preferences set --app dm --type dm.msg.received --enabled false
ting preferences reset --app dm --type dm.msg.received
```

Precedence is event override, service override, app override, then enabled. Muting stores future ordinary notifications silently and pauses eligible delivery. Unmuting can resume previously non-silent pending copies; historically silent ordinary notifications are not replayed automatically. `--service` and `--type` are mutually exclusive.

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

The destination receives `{"tings":[...]}` with the `Ting-Webhook-Id` header and optional bearer secret. Each notification includes `id`, immutable `created_at`, `type`, `data`, `metadata` and `key`. Return exactly HTTP 204 after durable acceptance. Forwarding is at least once; deduplicate IDs at your destination. Ting read state is not an application-specific delivery receipt.

`unhook` detaches a destination while retaining its ID and unfinished history. New hooks include eligible unread history; reattached hooks resume their own unfinished copies. After local disk loss, list existing hooks and reattach their stable IDs with the local URL and secret.

Failed destinations retry with backoff. An optional health probe can postpone a retry. Repeated failure for 12 hours pauses the hook; `daemon reconnect` explicitly resumes this account's paused or attached hooks. `daemon start` requires no login; `daemon status` does not start the daemon.

Upgrading old local receiver state preserves destinations and queued history, but pauses previous bindings until explicitly reattached under the current Accounts identity.

## Required delivery

A recipient must explicitly enable required delivery on a subscription before its app can use `--delivery required`. This permits automation delivery despite an ordinary mute. Without that opt-in, Ting rejects the send. Subscription revocation and session authority still apply; the app token cannot opt the recipient in.

## Retention, configuration and errors

Ting retains read or silent notifications for one calendar month and unread non-silent notifications for three calendar months, measured from immutable `created_at`. Read changes and retries do not restart those periods. The daemon prunes expired copies and checks older pending copies before forwarding.

```sh
ting config list
ting config get telemetry.enabled
ting config set telemetry.enabled false
ting bug report --title 'Problem' --body-file report.txt --attach details.txt --pr https://github.com/teamofsilicons/silicon-ting/pull/123
```

Telemetry excludes credentials and notification content. Bug reports include only explicitly supplied body and attachments; keep credentials and private notification data out of them.

Success exits 0, invalid arguments or input exit 2, and operational failures exit 1. With `--json`, success goes to stdout and an `{"error":{"code","message","hint","retryable","details"}}` envelope goes to stderr. A transport failure may follow server acceptance: use the preserved key and exact request when retrying.
