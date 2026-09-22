# Backend deployment

The `Build backend deployment` workflow tests and builds the ARM64 server inside Amazon Linux 2023, matching production's glibc 2.34. It separately builds the official Caddy commit and Go version pinned in `caddy-build.json`; that revision supports the explicit `IAM_TEST_APP_SECRET` header allowlist. The archive includes source provenance, licenses, configuration, services, and SHA256SUMS.

Commit the release source, then use the authorized GitHub release account to push its exact tag:

```sh
release_commit=$(git rev-parse HEAD)
git push origin HEAD:main "HEAD:refs/tags/server-$release_commit"
```

The tag triggers `.github/workflows/backend.yml`. Wait for all three jobs to succeed, then deploy:

```sh
python3 deploy/github-release.py "$release_commit"
```

The deployment script resolves the existing production CloudFormation stack, then uses SSM to download the public archive on the host. It verifies its SHA-256 and embedded commit before installation. No local binary upload or SSH access is needed. The installer takes the deployment lock, fetches the latest production runtime secret, preserves systemd drop-ins, and checks both the backend and HTTPS gateway. Failed updates restore the previous release, runtime configuration, Caddy binary, and service files.

Create the Git tag with the authorized release account before using a manual workflow dispatch too. GitHub's workflow token can publish assets for that existing tag; it cannot always create a tag pointing at a commit that modifies workflows. Build and publish jobs never receive AWS credentials or production secrets.

During isolated release testing only, Caddy's dedicated probe environment file and service drop-in are preserved. Remove the probe route, drop-in, environment file, and sidecar service together after testing.

## Browser integrations

Set `TING_BROWSER_ORIGINS` in the runtime secret to the comma-separated exact origins of trusted browser apps, for example `https://dm.teamofsilicons.com,https://interface.teamofsilicons.com`. The public and frontend origins remain allowed. Origins require HTTPS (HTTP is accepted only on loopback); wildcards, credentials, paths, queries and fragments are rejected at startup. Reload the server after changing runtime configuration.

The same allowlist governs HTTP, WebSocket upgrades and cookie-authenticated mutations. Permitted HTTP responses, including errors, carry credentialed CORS and `Vary: Origin`; unknown origins receive 403. Browsers must use `credentials: "include"` for HTTP and open the socket on the host that issued the Ting cookie. Each user still signs into Ting separately; DM login alone does not create a Ting session. The login return path remains local.

See [DM integration prerequisites and verification](dm-integration.md) for scope approval, environment setup and the live delivery gates.
