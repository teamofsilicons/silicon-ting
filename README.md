# Silicon Ting

Notifications for carbons and silicons. A Rust service, HTTP/WebSocket client, CLI and one shared local daemon, with a SolidJS companion inbox.

- **Web and docs:** https://ting.teamofsilicons.com
- **API:** https://backend.ting.teamofsilicons.com
- **IAM application:** `ting`

Current release: [0.1.7](https://github.com/teamofsilicons/silicon-ting/releases/tag/v0.1.7), also available through `honeycomb install 'ting'`. Previous releases [0.1.6](https://github.com/teamofsilicons/silicon-ting/releases/tag/v0.1.6), [0.1.5](https://github.com/teamofsilicons/silicon-ting/releases/tag/v0.1.5), [0.1.4](https://github.com/teamofsilicons/silicon-ting/releases/tag/v0.1.4), [0.1.3](https://github.com/teamofsilicons/silicon-ting/releases/tag/v0.1.3), [0.1.2](https://github.com/teamofsilicons/silicon-ting/releases/tag/v0.1.2), [0.1.1](https://github.com/teamofsilicons/silicon-ting/releases/tag/v0.1.1) and [0.1.0](https://github.com/teamofsilicons/silicon-ting/releases/tag/v0.1.0) remain available with their original archives and checksums. See the [verification record](deploy/verification.md) and [latency analysis](deploy/latency-analysis.md) for measured results.

## Start receiving

```sh
curl -fsSL https://ting.teamofsilicons.com/install.sh | sh
# Supply a Ting-bound short-lived token from the official IAM CLI:
ting login --token-stdin
ting org use tos
ting webhook http://localhost:3000/ting
ting inbox list --all
```

The installer downloads a checksum-verified release and registers one system daemon. Windows installation is described in [installers/README.md](installers/README.md). Each identity keeps credentials in `$SILICON_HOME/.ting/`; all identities share the daemon connection. Local URLs and webhook secrets never leave the device.

Applications need a recipient's IAM OBO grant before sending. Prepare exact request bytes, obtain a request-bound proof through IAM, then submit them:

```sh
ting send --org tos --type 'example.message.received' --for si:assistant \
  --key unique-event-key --data '{"message":"Hello"}' --write-request send.json --json
# Obtain a fresh IAM proof for the returned method, path and body SHA-256.
ting send --request-file send.json --proof-token-stdin --json
```

Actor IDs are complete IAM identities (`c:alice0`, `si:assistant`); app IDs are bare handles (`ting`, `dm`). Organization selection and authority remain separate. Existing queued requests and delivery receipts retain their exact bytes and stable IDs through migration.

Use `ting --help`, `ting docs`, [CLI reference](udd/cli.md), and [API contract](udd/api.md) for registration, preferences, proof issuance, delivery and recovery requirements.

## Retention and delivery

Read **or** silent tings expire one calendar month after their original `created_at`. Unread, non-silent tings expire after three calendar months. All dates use UTC; retries preserve creation time. Expired payloads and their delivery records are removed automatically. A read on any destination changes overall read state and therefore the applicable retention window.

Within that window, each webhook has an independent copy. The daemon durably queues before delivery ACK, and retains local acceptance until the server confirms read ACK. Webhooks return `204` only after accepting the complete `{ "tings": [...] }` batch. Consumers must deduplicate by ting ID, since transport is at least once. A failed hook retries independently for twelve hours before requiring explicit reconnection.

App send idempotency lasts fourteen days. Every replay still needs a fresh proof. Notification preferences never grant permission to send; IAM grants and current authorization are checked separately.

## Development

```sh
cargo test --workspace
cargo build --workspace
python3 crates/ting-cli/tests/smoke.py
cd web
npm ci
npm test
npm run build
```

Run the backend with the variables in [.env.example](.env.example), then `cargo run -p silicon-ting-server`. For the browser, `npm run dev` proxies `/v1` to the backend on port 8080. Use real IAM testing-environment credentials; there is no development authentication bypass.

The local daemon is installed through [platform installers](installers/README.md). Public releases include macOS, Linux and Windows on x86-64 and ARM64; native CI runs client/CLI/daemon tests on each target. The server and API protocol are v1. Additive response fields are compatible; breaking wire changes require a new major protocol.

## Deployment

AWS CloudFormation provisions a dedicated ARM64 EC2 host, encrypted retained EBS, private encrypted S3 and Secrets Manager. GitHub tests and builds releases on Amazon Linux 2023. `deploy/github-release.py` installs a checksum-verified release through SSM; systemd supervises the service and failed health checks restore the previous release. See [deployment instructions](deploy/README.md) and the [verification record](deploy/verification.md) for measured results and limitations. No SSH port is exposed.

Vercel hosts the built frontend. Caddy serves `ting.teamofsilicons.com`, proxies static frontend requests to Vercel and `/v1` to Rust. `backend.ting.teamofsilicons.com` exposes the backend directly. This keeps the browser's HttpOnly, host-only session cookie and WebSocket on one origin. Namecheap manages both DNS records.

SQLite uses WAL and `synchronous=FULL`. There is one server writer; move to PostgreSQL before adding replicas. Online encrypted snapshots run hourly and expire from S3 after seven days. Restoring a snapshot applies current notification retention before accepting traffic. Application secrets and encrypted upstream IAM tokens stay on the backend.

Space Station has separate backend, CLI/daemon, browser analytics and browser event tables. Automatic diagnostics omit notification bodies, tokens and webhook secrets. Profile telemetry can be disabled; explicitly submitted bug reports require an actual durable Space Station acknowledgment.
