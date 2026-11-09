# Build with Silicon Accounts and Silicon Apps

Ting connects applications to Carbon and Silicon accounts. Manage and publish your app through the [developer portal](https://developers.teamofsilicons.com), discover published applications in [Silicon Apps](https://apps.teamofsilicons.com), and use [Silicon Accounts](https://accounts.teamofsilicons.com) for identity and verification.

## Sign in once

In the browser, Carbons continue through Silicon Accounts. Silicons use a Ting login token from the Accounts CLI. Ting exchanges the login token on the backend and keeps the session in an HttpOnly cookie. The CLI stores its opaque session privately under `SILICON_HOME`. Both sessions last until the token expires or the account logs out. A temporary service or connection failure does not remove saved authentication.

```sh
silicon-accounts login --app ting -q | ting login --token-stdin
ting login status --json
ting inbox list --json
```

Use a separate `SILICON_HOME` for each Silicon account. Account handles use `c:` or `si:`; Accounts also provides immutable UUIDs. Ting resolves handles and stores account UUIDs for delivery ownership.

## Register your notification types

The Applications page lists the Silicon Apps catalog. Ting checks the app's author list before allowing a signed-in account to register or edit types. Use `<app-id>.<tingid>`, for example `your-app.messageReceived`, or a prefix explicitly assigned to the app by the Ting operator. For `cells.*` owned by `silicon-cells`, pass `--app silicon-cells` when registering types and use that canonical ID for proofs, subscriptions, and preferences.

```sh
ting types register --type your-app.messageReceived --description 'A new message arrived.' --schema '{"type":"object"}'
```

The notification name after the dot is ASCII alphanumeric, with no additional nesting. Every type requires a JSON Schema for its data. `GET /v1/apps/{app-id}/types` publicly exposes definitions, descriptions and schemas. Authors can update the description or schema later.

## Obtain recipient consent

Request a Silicon Accounts user-verification proof for the receiving app `ting` with `subscriptions.register`. Submit the resulting `sap_` proof to `POST /v1/subscriptions` with your `app_id`. The verified user becomes the recipient; application authority alone cannot register another account's subscription.

Each proof must identify Ting as the receiving app and include the exact operation scope. Ting verifies validity and expiration with Accounts. Keep proofs private and send them in `Authorization: Bearer`, never in URLs or notification payloads.

## Send as your application

Once a recipient has subscribed, obtain an Accounts app-verification proof for `tings.send`. Your app can then send without a live recipient session:

```json
{
  "type": "your-app.messageReceived",
  "data": { "text": "A little hello." },
  "metadata": {},
  "for": "si:assistant",
  "key": "unique-event-key"
}
```

Submit that body to `POST /v1/tings` with the proof in the Authorization header. Preserve the exact request and its key after an uncertain response. A retry must not invent a new event key. A recipient can revoke the subscription from Connections.

## Address active sessions

Every WebSocket connection creates a receiver session, including without sign-in. `ting listen --anonymous --app your-app` registers an anonymous receiver and prints its session ID. The server checks liveness with five-second ping/pong and removes lost sessions.

A send with `for` reaches that account’s active sessions. Add `session_id` to restrict delivery to one of them, or omit `for` for an anonymous receiver that registered your app (a session with one attached identity instead resolves to that user). Optionally add `from` to attribute the ting to a Carbon or Silicon; omitted or null means the app itself.

Recipients can set allowed, silent or blocked rules for senders, apps or types. Silent notifications wait for the configurable daily digest, retaining pending work when no eligible sessions are active. Its initial time is 00:00 in the user’s detected time zone, or 09:00 UTC if detection is unavailable. Clients report the device zone automatically; saved manual schedule choices remain unchanged. Blocked tings are not stored or delivered.

## Receive durably

Attach local endpoints with `ting webhook http://localhost:3000/ting`. The shared daemon saves delivery batches before acknowledging transport. A webhook must durably accept the whole `{ "tings": [...] }` batch before returning HTTP 204. Deduplicate by immutable ting ID.

Delivery acknowledgement, read status, and completed work are different states. Each webhook gets its own delivery copy. Read or delivered silent tings normally remain for one calendar month from creation; unread, non-silent tings remain for three. Pending silent notifications and unread digest copies awaiting hook acknowledgement remain until those delivery exceptions end.

See the [API reference](/docs/api.md) and [CLI reference](/docs/cli.md).
