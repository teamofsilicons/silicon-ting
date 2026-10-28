# Notification type prefix ownership

A type label is `prefix.service.event`. By default its prefix is the canonical Silicon Apps ID. An operator can assign an unused prefix to another app through server configuration:

```sh
TING_TYPE_PREFIX_ALIASES='{"cells":"silicon-cells"}'
```

The variable contains a JSON object with at most 128 entries and 16 KiB. Keys and values follow the existing app-ID syntax: 1–80 lowercase letters, digits, underscores or hyphens, starting with a letter. Duplicate keys, self-aliases and chains/cycles are rejected. A target app can still use its own default prefix. Aliases cannot be set through an HTTP request.

For Silicon Cells, continue using the real Accounts app `silicon-cells`. An App verification proof must be issued by that app with receiving app `ting` and the appropriate Ting scope. User verification, subscription `app_id`, sent-history queries and app/service/type preferences also use `silicon-cells`; only notification labels begin `cells.`. The alias never grants the app `cells` authority over those notifications.

A signed-in author of `silicon-cells` can register or update its aliased labels:

```sh
ting types register --app silicon-cells --type cells.database.failing --description 'A database operation failed'
ting types update --app silicon-cells --type cells.database.failing --description 'A database operation needs attention'
ting preferences set --app silicon-cells --type cells.database.failing --enabled false
```

Without `--app`, type registration/update retains its previous behavior of selecting the label prefix. The Rust client and browser validate label syntax locally; the server checks actual ownership. This permits aliases without shipping an operator-specific mapping into clients.

## Persistence and deployment

At startup Ting records prefix ownership in `type_namespaces`, scoped to the existing Accounts context. Registered types and current Accounts notification history establish ownership before new aliases are claimed. Configured aliases are reserved even before their first type is registered. Registration verifies the durable claim in its SQLite write transaction, preventing an older concurrently opened server from claiming a newly reserved alias.

A prefix already owned by `cells` cannot be assigned to `silicon-cells`. Removing or reassigning an existing alias fails startup rather than transferring its historical data. Preserve the runtime setting and SQLite database together across backups and restores. There is no ownership-transfer API or implicit migration by handle. Legacy identity archives remain quarantined under the existing Accounts migration policy.

Back up the SQLite data and runtime configuration, stop every old backend process, deploy the compatible backend, set the runtime variable, and start it before registering aliased types. An alias-unaware binary must never share the live database with the new version. A failed startup leaves ownership unchanged. Do not downgrade to an alias-unaware binary against this database: restore the matching pre-change database and runtime snapshot as part of an intentional rollback. No production deployment or runtime-secret update is performed by the source change itself.

## Local acceptance

`cargo test --workspace` exercises real SQLite and loopback HTTP with mock Accounts/Apps, without production credentials. It verifies canonical proof identity, registration/update/replay, subscriptions, sent history, app/service/type preferences, queued-delivery preference checks, existing-owner conflicts, stale-process claims, and restart removal/reassignment rejection. `python3 scripts/test-prefix-aliases.py` additionally builds the real CLI and exercises token-stdin login, aliased registration/update/preferences and exact-file proof queries against the same disposable HTTP fixture. `cargo clippy --workspace --all-targets -- -D warnings` and `npm run typecheck` in `web` check the client surfaces.
