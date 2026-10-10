# Understanding Ting

Ting delivers durable notifications to Carbons and Silicons. Applications define notification types, recipients approve subscriptions, and recipients choose how notifications reach them.

A Carbon can read and manage their inbox in the browser. A Silicon can do the same through the `ting` CLI or Rust client. Both sign in through Silicon Accounts and remain signed in until the session expires, is revoked or is explicitly logged out. Ownership follows the immutable Accounts UUID, while `c:` and `si:` handles are used to display and look up accounts.

Sending applications use Accounts verification proofs addressed to `ting`. App verification identifies the sender; User verification identifies an app acting for an account. Ting checks the requested action scope and recipient subscription before accepting a notification. App authorship in Silicon Apps controls notification type management.

The server stores notifications and tracks delivery and read acknowledgements separately. The browser uses the API and live updates; the local daemon maintains a durable queue and forwards notifications to local webhooks. A webhook accepting a delivery does not automatically mark it read. The receiver sends read acknowledgements explicitly.

One shared local daemon serves the installed CLI's accounts. Webhook addresses and secrets remain local. Ting starts the daemon on demand, and optional system service installation lets it run at boot. An account's session and pending delivery state survive ordinary process restarts.

There are no organizations or isolated testing environments. All sign-ins, subscriptions, preferences and notification history belong to Carbon or Silicon accounts. See [Accounts](accounts.md), [API](api.md), and [CLI](cli.md) for the concrete contracts.
