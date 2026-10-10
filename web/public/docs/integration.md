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

The Applications page lists the Silicon Apps catalog. Ting checks the app's author list before allowing a signed-in account to register or edit types. Use `app_id.service.event`, for example `your-app.messages.received`.

```sh
ting types register --type your-app.messages.received --description 'A new message arrived.'
```

## Obtain recipient consent

Request a Silicon Accounts user-verification proof for the receiving app `ting` with `subscriptions.register`. Submit the resulting `sap_` proof to `POST /v1/subscriptions` with your `app_id`. The verified user becomes the recipient; application authority alone cannot register another account's subscription.

Each proof must identify Ting as the receiving app and include the exact operation scope. Ting verifies validity and expiration with Accounts. Keep proofs private and send them in `Authorization: Bearer`, never in URLs or notification payloads.

## Send as your application

Once a recipient has subscribed, obtain an Accounts app-verification proof for `tings.send`. Your app can then send without a live recipient session:

```json
{
  "type": "your-app.messages.received",
  "data": { "text": "A little hello." },
  "metadata": {},
  "for": "si:assistant",
  "key": "unique-event-key"
}
```

Submit that body to `POST /v1/tings` with the proof in the Authorization header. Preserve the exact request and its key after an uncertain response. A retry must not invent a new event key. A recipient can revoke the subscription from Connections.

## Receive durably

Attach local endpoints with `ting webhook http://localhost:3000/ting`. The shared daemon saves delivery batches before acknowledging transport. A webhook must durably accept the whole `{ "tings": [...] }` batch before returning success. Deduplicate by immutable ting ID.

Delivery acknowledgement, read status, and completed work are different states. Each webhook gets its own delivery copy. Read or silent tings remain for one calendar month from creation; unread, non-silent tings remain for three.

See the [API reference](/docs/api.md) and [CLI reference](/docs/cli.md).
