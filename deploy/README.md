# Backend deployment

The backend workflow builds the ARM64 server inside Amazon Linux 2023, matching production's glibc. It separately builds the official Caddy commit and Go version pinned in `caddy-build.json`. The archive includes source provenance, licenses, configuration, services and SHA256SUMS.

Commit the release source, then push its backend tag:

```sh
release_commit=$(git rev-parse HEAD)
git push origin HEAD:main "HEAD:refs/tags/server-$release_commit"
```

After `.github/workflows/backend.yml` succeeds:

```sh
python3 deploy/github-release.py "$release_commit"
```

The deploy script resolves the existing `silicon-ting-production` CloudFormation stack in `us-east-1`, then uses SSM to download the archive on the host. It verifies SHA-256 and the embedded source commit before installation. The installer takes a deployment lock and loads runtime configuration from Secrets Manager at `silicon-ting/production/runtime`. Before switching releases, the installer stops the server and backup timer, snapshots each SQLite database and verifies its integrity. Snapshots stay in `/var/lib/ting/pre-accounts-<release>-…/` with private permissions. Failed health checks restore the previous databases, binary, runtime configuration, gateway and service files; the failed database files and sidecars are retained in the snapshot directory's `failed/` folder.

## Accounts migration

Configure `TING_ACCOUNTS_URL=https://accounts.teamofsilicons.com`, `TING_APPS_URL=https://apps.teamofsilicons.com`, the Ting app secret and Accounts webhook secret. Preserve the existing encryption key, storage path and telemetry settings. Take a consistent backup before changing the backend. The previous identity system has no trusted immutable mapping to Silicon Accounts UUIDs. Its notification history, receipts and grants remain in `legacy_*` archive tables, while new account data uses UUIDs. Those historical notifications are preserved but not automatically exposed to matching display handles. Rebinding history requires an authoritative identity migration map; ordinary sign-in cannot claim it.

Register both public backend callback URLs ending in `/v1/session/callback`. Set the webhook to `https://ting.teamofsilicons.com/v1/accounts/webhook`. Deploy the backend before the frontend so both use the same sign-in contract. See [Accounts integration](../udd/accounts.md).

## Browser origins

`TING_BROWSER_ORIGINS` lists trusted browser app origins separated by commas. The public and frontend origins remain allowed. Use exact HTTPS origins; loopback HTTP is accepted for local development. Wildcards and URL paths are refused.

The allowlist governs HTTP, WebSocket upgrades and cookie-authenticated mutations. Browser requests use `credentials: "include"`, and sockets connect to the host that issued the Ting cookie. Each account signs in to Ting separately.

## Backups

The existing systemd backup timer takes SQLite online snapshots and writes them to the stack's S3 artifact bucket. Back up the database and encrypted session store together with the preserved runtime encryption key. Do not include runtime secrets in build archives or release receipts.
