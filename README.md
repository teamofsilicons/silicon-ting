# Silicon Ting

Durable notifications for Carbons and Silicons. Ting includes a Rust API, HTTP/WebSocket client, CLI, one shared local receiver daemon, and a web inbox built with Silicon UI.

- [Web inbox and documentation](https://ting.teamofsilicons.com)
- [API](https://backend.ting.teamofsilicons.com)
- [Silicon Apps](https://apps.teamofsilicons.com) application: `ting`
- [Developer portal](https://developers.teamofsilicons.com)

## Start receiving

```sh
silicon-apps install ting
silicon-accounts login --app ting -q | ting login --token-stdin
ting webhook http://localhost:3000/ting
ting inbox list --all
```

Sign in to Silicon Accounts first. Carbons use the hosted sign-in pages; Silicons use their existing Accounts CLI sign-in to create a single-use Ting token. The token establishes a persistent Ting session. Both browser and CLI remain signed in across restarts until that session expires or the user signs out. Ting keeps Accounts refresh credentials encrypted on its server and checks their current validity without extending the session's original expiry.

Each account has an immutable Accounts UUID and a display handle such as `c:alice` or `si:assistant`. Data and access belong to the account. Handles can change. There is no organization selection or testing environment.

Applications call Ting with Silicon Accounts App verification or User verification proofs. A recipient authorizes their subscription; sending applications use the corresponding app proof and Ting checks the subscription on every send. The receiving app is `ting`, and proof scopes name the Ting action being performed. See [Accounts integration](udd/accounts.md) and the [API contract](udd/api.md).

The CLI starts its shared daemon when needed. Each account keeps local credentials under `$SILICON_HOME/.ting/` or its normal home. Webhook URLs and local webhook secrets stay on the device. [Optional service installation](installers/README.md) supports receivers that should start at boot.

## Components

| Path | Purpose |
| --- | --- |
| `crates/ting-server` | Accounts sign-in, encrypted sessions, subscriptions, preferences, durable notification storage and delivery |
| `crates/ting-client` | Rust HTTP, WebSocket and local IPC client |
| `crates/ting-cli` | `ting` command and bundled documentation |
| `crates/ting-daemon` | Shared receiver, local queue and webhook forwarding |
| `web` | Web inbox using components from [Silicon UI](https://ui.teamofsilicons.com) |
| `udd` | API, CLI and integration documentation |
| `deploy` | Production server deployment and backup configuration |

## Development

Copy `.env.example` to `.env`, fill the registered Ting app secret and encryption key, and export the values before starting the server. The server needs access to Silicon Accounts; it does not accept mock identities.

```sh
cargo run -p silicon-ting-server
cd web
npm ci
npm run dev
```

Use `cargo check --workspace`, `cargo fmt --all --check`, and `npm run build` in `web` to verify a change. The repository has no test suite or isolated identity environments.

## Releases

Current source version: `0.3.0`. [Release instructions](installers/RELEASING.md) cover the six native targets, crates.io, Silicon Apps and frontend. [Backend deployment](deploy/README.md) documents the existing AWS production service, runtime secrets, backups and rollback.

Silicon Apps validates `ting --help`, `ting accounts --json`, and `ting login status --json` in its target runners before a package can be released. Production releases install and update through `silicon-apps`.
