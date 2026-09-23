# Publishing Ting

All three Cargo manifests and `honeycomb.yaml` must carry the same version. Keep the packaged CLI documentation synchronized with the source specs before committing:

```sh
cp udd/cli.md crates/ting-cli/docs/cli.md
cp udd/api.md crates/ting-cli/docs/api.md
cp scripts/install.sh web/public/install.sh
cp scripts/install.ps1 web/public/install.ps1
cargo test --locked -p silicon-ting-client -p silicon-ting-cli -p silicon-ting-daemon
python3 scripts/test-package-honeycomb.py
```

Publish the stateless Rust client before the CLI so Cargo can resolve the registry dependency. The daemon is distributed in release archives and Honeycomb; it does not need a crates.io publication.

```sh
cargo publish -p silicon-ting-client --locked
cargo publish -p silicon-ting-cli --locked
```

Before the first client publication, the CLI packaging dry run can use the local registry patch below. After publication, omit the patch to verify the actual registry dependency.

```sh
cargo publish -p silicon-ting-cli --dry-run --allow-dirty --config 'patch.crates-io.silicon-ting-client.path="crates/ting-client"'
```

Dispatch `.github/workflows/release.yml` to test native x86_64 and ARM64 builds on Linux, macOS and Windows. A `v0.1.7` tag runs the same checks and publishes six archives plus `SHA256SUMS` on the GitHub release. The workflow rejects a tag that does not match the binary version. Archives contain the CLI and shared daemon; their names match both installers.

To assemble the Honeycomb package from that completed release (Python 3.11+ and the Honeycomb CLI are required):

```sh
mkdir -p dist/native
gh release download v0.1.7 --repo teamofsilicons/silicon-ting --dir dist/native --pattern 'ting-v0.1.7-*' --pattern SHA256SUMS
python3 scripts/package-honeycomb.py --assets dist/native --output dist/ting-honeycomb-0.1.7.tar.gz
honeycomb validate dist/ting-honeycomb-0.1.7.tar.gz --json
```

The assembler verifies every archive against its published checksum, accepts only the two expected regular executable files, and runs Honeycomb's own pack validation. It requires all six real native build assets. `honeycomb.yaml` uses JSON syntax, which is valid YAML and readable without a YAML dependency. Its `bin` mappings expose both `ting` and `ting-daemon`. Honeycomb packs its manifest and target trees, so each platform directory carries `LICENSE` and `SERVICE.md`. Honeycomb cannot register system services through this manifest; the explicit installer step is documented there and in [README.md](README.md).

Fetch the current application revision immediately before the upload. Keep the generated idempotency key and use that same key if a network failure makes the result uncertain. Replace `REVISION` with the numeric `revision` from `apps get`:

```sh
honeycomb apps get 'ting' --json
python3 -c 'import uuid; print(uuid.uuid4())' > dist/honeycomb-upload-key.txt
honeycomb releases upload 'ting' dist/ting-honeycomb-0.1.7.tar.gz --channel prod --revision REVISION --idempotency-key "$(cat dist/honeycomb-upload-key.txt)" --json
honeycomb apps get 'ting' --json
honeycomb releases list 'ting' --json
```

Check the returned visibility/publication status; requesting public visibility does not itself mean an application is approved. Keep the native GitHub archives available because the system service installers download those versioned assets and verify `SHA256SUMS`.
