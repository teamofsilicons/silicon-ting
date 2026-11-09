# Understanding Ting

Ting delivers durable notifications to Carbons and Silicons. Applications define notification types, recipients approve subscriptions, and recipients choose how notifications reach them.

A Carbon can read and manage their inbox in the browser. A Silicon can do the same through the `ting` CLI or Rust client. Either can attach a Silicon Accounts identity to a live receiver session, or receive anonymously. Signed-in credentials remain valid until expiry, revocation or explicit logout. Ownership follows the immutable Accounts UUID, while `c:` and `si:` handles are used to display and look up accounts.

Sending applications use Accounts verification proofs addressed to `ting`. App verification identifies the sender; User verification identifies an app acting for an account. Ting checks the requested action scope and recipient subscription before accepting a notification. App authorship in Silicon Apps controls notification type management.

The server stores notifications and tracks delivery and read acknowledgements separately. The browser uses the API and live updates; the local daemon maintains a durable queue and forwards notifications to local webhooks. After a local webhook returns HTTP 204 for durable acceptance, the daemon explicitly sends a read acknowledgement. That read state does not assert that the source application completed any work.

Every WebSocket creates an addressable receiver session. Apps can notify a user’s active sessions, one specific session belonging to that user, or an anonymous session that has registered the app. The server pings every five seconds and removes lost sessions. An app can attribute a ting to another user so recipients can block that sender, the app, or a notification type.

Recipients choose allowed, silent or blocked. Silent notifications accumulate until the configurable daily digest, initially midnight in the detected user time zone (09:00 UTC if detection is unavailable); if no eligible session is active, they wait for a later schedule. The daily digest can be disabled without discarding pending tings. Pending silent notifications and unread digest copies awaiting hook acknowledgement are retained beyond the usual history window.

Apps publish notification definitions at a public endpoint. Each type is exactly `<app-id>.<alphanumeric tingid>`, has a description and a JSON Schema, and validates every send. Apps can update descriptions and schemas for future notifications.

One shared local daemon serves the installed CLI's accounts. Webhook addresses and secrets remain local. Ting starts the daemon on demand, and optional system service installation lets it run at boot. An account's session and pending delivery state survive ordinary process restarts.

There are no organizations or isolated testing environments. Sign-in and account preferences belong to Carbon or Silicon accounts; anonymous receiver registrations live only as long as their active session. See [Accounts](accounts.md), [API](api.md), and [CLI](cli.md) for the concrete contracts.
