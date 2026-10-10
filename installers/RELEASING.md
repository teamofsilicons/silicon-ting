# Publishing Ting

Keep the workspace, four Cargo package versions, `apps.yaml` and frontend package version in sync. Synchronize bundled CLI docs before building:

```sh
cp udd/cli.md crates/ting-cli/docs/cli.md
cp udd/api.md crates/ting-cli/docs/api.md
cargo check --locked --workspace
cargo fmt --all --check
```

Publish the Rust client before the CLI so Cargo resolves the registry dependency:

```sh
cargo publish -p silicon-ting-client --locked
cargo publish -p silicon-ting-cli --locked
```

Push a version tag such as `v0.3.0` after committing to main. `.github/workflows/release.yml` builds x86_64 and ARM64 packages on Linux, macOS and Windows and publishes six archives plus `SHA256SUMS`. The version tag must match the binary version. Each archive contains `ting` and its companion `ting-daemon`.

## Silicon Apps

Sign in to `silicon-apps` as an author of `ting`. Current publication uses `si:tos`.

```sh
mkdir -p target/release-assets
gh release download v0.3.0 --repo teamofsilicons/silicon-ting --dir target/release-assets --pattern 'ting-v0.3.0-*' --pattern SHA256SUMS
python3 scripts/package-apps.py --assets target/release-assets --output target/ting-apps-0.3.0.tar.gz
silicon-apps upload ting --target linux-x86_64 target/ting-apps-0.3.0.tar.gz --json
```

Repeat upload for each available target. `silicon-apps targets --json` reports configured validation runners; the Apps capabilities endpoint checks whether they are live. Each upload validates the target's `--help`, `accounts --json` and `login status --json` commands. A target without a runner cannot currently be uploaded through the public API; keep its native GitHub archive available through the optional installer. Record each accepted package ID, then create and promote the release:

```sh
silicon-apps release ting --version 0.3.0 --package PACKAGE_ID --package ANOTHER_PACKAGE_ID
silicon-apps promote ting DEVELOPMENT_RELEASE_ID --version 0.3.0
silicon-apps readiness ting
silicon-apps publish ting
```

Include every validated package ID. Save receipts and idempotency keys outside source control. Reuse the same key and body only when retrying a mutation whose outcome is unknown.

The assembler verifies every native archive against its published checksum, accepts only the two expected regular executable files, and uses Silicon Apps' pack validation. It includes licenses and service instructions beside each target. The daemon remains a companion executable; the CLI starts it on demand.

## Backend and frontend

Use [backend deployment](../deploy/README.md) for the production AWS service. Deploy the frontend from the release source with the existing Vercel project binding after the backend is healthy:

```sh
cd web
npx vercel deploy --prod --yes --build-env VITE_SS_ANALYTICS_TABLE=tingfrontendanalytics --build-env VITE_SS_EVENTS_TABLE=tingfrontendevents
```

Verify the live sign-in, persistent browser and CLI sessions, logout, public docs and installed package version. Keep GitHub native archives available because optional system service installers download those versioned files and verify `SHA256SUMS`.
