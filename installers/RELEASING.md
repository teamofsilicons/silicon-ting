# Publishing Ting

Keep the workspace, four Cargo package versions, `apps.yaml` and frontend package version in sync. Synchronize bundled CLI docs before building:

```sh
cp udd/cli.md crates/ting-cli/docs/cli.md
cp udd/api.md crates/ting-cli/docs/api.md
cargo check --locked --workspace
cargo test --locked --workspace
cargo fmt --all --check
```

Publish the Rust client before the CLI so Cargo resolves the registry dependency:

```sh
cargo publish -p silicon-ting-client --locked
cargo publish -p silicon-ting-cli --locked
```

Push a version tag such as `v0.4.0` after committing to main. `.github/workflows/release.yml` builds x86_64 and ARM64 packages on Linux, macOS and Windows and publishes six archives plus `SHA256SUMS`. The version tag must match the binary version. Each archive contains `ting` and its companion `ting-daemon`. Before packaging, every native CI runner executes the built target’s `--help`, `accounts --json`, and `login status --json` commands with a fresh local profile. Command failures or invalid Accounts/session JSON fail the job. Both packaging paths also check the binary version against the release tag.

## Silicon Apps

Sign in to `silicon-apps` as an author of `ting`. Current publication uses `si:tos`.

```sh
mkdir -p target/release-assets
gh release download v0.4.0 --repo teamofsilicons/silicon-ting --dir target/release-assets --pattern 'ting-v0.4.0-*' --pattern SHA256SUMS
python3 scripts/package-apps.py --assets target/release-assets --output target/ting-apps-0.4.0.tar.gz
silicon-apps upload ting --target linux-x86_64 target/ting-apps-0.4.0.tar.gz --json
```

Repeat upload for both Linux targets; Silicon Apps validates these on its server-side runners. With Silicon Apps CLI 0.3.3 or newer, macOS and Windows uploads require `--confirm-platform-checks`. Use that flag only after the matching native release CI job passed its three command checks for the exact archive being uploaded:

```sh
silicon-apps upload ting --target macos-aarch64 target/ting-apps-0.4.0.tar.gz --confirm-platform-checks --json
silicon-apps upload ting --target windows-x86_64 target/ting-apps-0.4.0.tar.gz --confirm-platform-checks --json
```

Upload the remaining macOS and Windows targets with the same confirmation after their native CI checks pass. `silicon-apps targets --json` reports supported targets. Keep the six native GitHub archives available through the optional installer as well. Record each accepted package ID, then create and promote the release:

```sh
silicon-apps release ting --version 0.4.0 --package PACKAGE_ID --package ANOTHER_PACKAGE_ID
silicon-apps promote ting DEVELOPMENT_RELEASE_ID --version 0.4.0
silicon-apps readiness ting
silicon-apps publish ting
```

Include every validated package ID. Save receipts and idempotency keys outside source control. Reuse the same key and body only when retrying a mutation whose outcome is unknown.

The assembler verifies every native archive against its published checksum, accepts only the two expected regular executable files, and uses Silicon Apps' pack validation. It includes licenses and service instructions beside each target. The daemon remains a companion executable; the CLI starts it on demand.

## Backend and frontend

Use [backend deployment](../deploy/README.md) for the production AWS service. Deploy the frontend from the release source with the existing Vercel project binding after the backend is healthy:

```sh
cd web
npx vercel deploy --prod --yes
```

Verify the live sign-in, persistent browser and CLI sessions, logout, public docs and installed package version. Keep GitHub native archives available because optional system service installers download those versioned files and verify `SHA256SUMS`.
