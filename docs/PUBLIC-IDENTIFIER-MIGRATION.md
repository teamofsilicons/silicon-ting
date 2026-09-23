# Ting public identifier cutover

Ting accepts complete `c:<handle>` and `si:<handle>` identities and bare application IDs, including `ting`. Organization authority and testing worlds stay explicit. The updated binary refuses legacy typed identity columns before resetting receivers or pruning history.

## Prepare the authoritative export

Use authenticated, restricted IAM tooling to export `iam_private.public_id_schema_map` from production and every testing store. Include removed/inactive principals and memberships. Translate it to this JSON format; do not derive ownership from Ting display names:

```json
{
  "worlds": ["production"],
  "organizations": [
    {"scope_key":"","org_id":"tos","id":"IAM-organization-UUID"}
  ],
  "identities": [
    {"scope_key":"","actor_type":"carbon","old_id":"alice","new_id":"c:alice","org_id":null},
    {"scope_key":"","actor_type":"silicon","old_id":"assistant:tos","new_id":"si:assistant","org_id":"tos"},
    {"scope_key":"","actor_type":"application","old_id":"tos>ting","new_id":"ting","org_id":"tos"}
  ],
  "memberships": [
    {"scope_key":"","actor_type":"carbon","id":"alice","org_id":"tos"},
    {"scope_key":"","actor_type":"silicon","id":"assistant:tos","org_id":"tos"}
  ]
}
```

IAM `scope_key=""` maps only to Ting's `production` context. A testing `scope_key` is its exact environment UUID, which must also appear in `worlds`. Include historical disabled worlds even when IAM has already purged their principals. Organization aliases reconcile IAM owner handles with Ting's stored organization UUIDs without changing those UUIDs. Memberships can use the exact mapped old or canonical identity. Carbon ownership is defined by memberships; its identity-map `org_id` is null.

An imported testing application must set `"imported":true` and match the production mapping's old ID, canonical ID and owner. Test-only applications cannot shadow a production app. Missing/ambiguous mappings, collisions, membership mismatches, wrong catalog ownership and undeclared worlds abort the transaction. The export and its SHA-256 are retained in the database for audit, never used as authentication aliases.

## Rehearse and cut over

1. Stop new writes, logins, webhooks, receiver/daemon workers and DM/Hook submissions. Back up `TING_DATABASE_PATH`, its `.auth` database and SQLite sidecars using SQLite backup/checkpoint with all writers stopped. Preserve the encryption key, old binaries, deployment configuration, daemon queues and the IAM export separately. Run the following first against restored copies.
2. Reconcile unfinished IAM login exchanges, pending refreshes/revocations and unfinished Honeycomb lifecycle operations using their original operation keys. The migrator refuses these uncertain operations. A login row with no encrypted response is unresolved even when no token payload was recorded: a crash could have occurred after IAM accepted the exchange. Do not delete such rows, invent a successful receipt, or retry under a new key to bypass the check.
3. Load the existing encryption key and select the restored database. Preview makes its changes inside a transaction and rolls them back:

   ```sh
   export TING_DATABASE_PATH=/absolute/restored/ting.sqlite
   # Load TING_ENCRYPTION_KEY from the matching secret store; do not print it.
   ting-server --migrate-public-identifiers /absolute/iam-map.json
   ting-server --migrate-public-identifiers /absolute/iam-map.json --apply
   ```

   The command starts no HTTP listener, telemetry or workers. Apply switches both SQLite files to rollback-journal mode with FULL synchronization so their attached-database transaction is crash-atomic. Normal startup restores WAL. Preserve the JSON evidence report. Repeating the identical export returns `already_applied`; a different export is rejected.
4. Update the deployment application ID to `ting` and consumers' audiences to bare IDs. Restart the compatible binary with workers still paused. All existing Ting sessions require normal login; daemon profiles must reconnect to their existing hook/resource IDs. IAM application secret values, stable session row IDs and ciphertext bytes remain unchanged.
5. Verify Carbon and Silicon registration and sends, fresh OBO proofs/current authority, cross-org and cross-world rejection, subscriptions/preferences, history, hook reattachment, delivery acknowledgements and same-key replay. Re-fetch IAM authority and registrations before resuming DM/Hook or receiver workers.

## Preservation and replay

The migration changes only typed identity/app columns and type/preference indexes. It preserves message IDs, subscription IDs, hooks, organization selectors, delivery/read acknowledgements, lifecycle generation/key fences, exact stored notification bodies, nested data/metadata, encrypted credentials, login receipts, request fingerprints, idempotency keys and accepted responses. API/history/delivery reads project current top-level `for` and `type` from the typed columns without rewriting the historical body.

Accepted Ting requests do not require waiting for their 14-day replay windows to expire. Their receipt lookup owner migrates, while their fingerprint and response remain exact. An unchanged hook creation request can recover its original receipt. A canonical send body changed under an accepted key fails `idempotency_conflict`; reconcile that original accepted message rather than minting a fresh key. New operations replay normally. Pending **unaccepted** DM/Hook signed requests must be drained/reconciled upstream; do not edit their bytes, proof, audience, key or hash. Daemon queues likewise retain their original payload and delivery identity.

Credential AES-GCM associated data is the stable session/login row ID, not an actor/application ID. The migration authenticates every retained ciphertext with that exact context and changes no ciphertext. Active sessions require a complete world/kind/actor mapping and are then revoked locally. Already-revoked sessions are historical evidence: their erased test principals need no new binding, but their ciphertext and exact declared world must still validate. Pending operations remain blockers regardless of revocation state. Completed login receipts remain immutable; replay points to an expired local session and requires normal login. All ephemeral testing receiver leases are also revoked; their original plaintext authority, token hashes and AES-GCM operation receipts (AAD `receiver:<operation-id>`) remain unchanged. Lease and operation worlds are checked and each receiver receipt is authenticated. Rebootstrap a fresh testing lease after cutover. Identity-bearing cursor/login-attempt caches are invalidated.

## Verification and recovery

```sh
cargo test -p silicon-ting-server migration::tests
cargo test --workspace
```

The populated rehearsal test includes production and two isolated testing worlds, Carbon/Silicon registrations, immutable bodies/credentials/receipts, hook and fresh-send replay, changed-send conflict, delivery identity, missing mappings, collisions, wrong ownership, unknown worlds, tampered ciphertext and rollback. Unit fixtures supplement restored-data rehearsals; they do not prove a production cutover succeeded.

Before reopening writes, rollback means stopping all upgraded services and restoring the coordinated database/configuration/key snapshots and previous binaries. Never run the old binary on canonical state or roll back only IAM/Honeycomb. After accepting new writes, stop traffic and reconcile those writes before a reverse migration, or fix forward. Retain the exact IAM export and evidence for the recovery window.

## Reconcile invalidated authentication

When original IAM operations can no longer be replayed (for example, a deleted testing world), first prove their results cannot authorize anything: revoke each surviving Ting refresh family through IAM's normal revocation API using its retained token and original revoke key, then export the IAM ledger confirming no live pre-cutover Ting access tokens or refresh families remain in any affected world. Do not revoke parent IAM sessions or sibling applications. Retain this evidence with the stopped-writer backups.

Only that verified invalidation permits an optional `authentication_invalidation` object in the mapping, containing `iam_evidence_sha256` (the evidence file's SHA-256) and `auth_state_sha256` (the exact local credential/replay-state checksum). The latter is SHA-256 over the concatenated UTF-8 results of the three `authentication_state` queries in `migration.rs`, in order. Any changed session, login or testing fence invalidates the evidence and blocks migration. This is an operator attestation backed by the restricted IAM export; the migrator does not contact IAM or independently attest the ledger.

The migration retains all original ciphertext, request hashes and receipt bytes, clears reconciled revocation work, revokes local sessions, and permanently marks every old login operation invalidated. A retry of an old login key returns `410 login_migrated` before contacting IAM. The retained refresh-operation fields are historical ciphertext and cannot be resumed through a revoked session. New login attempts require fresh IAM authorization.
