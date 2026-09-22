# DM integration deployment and verification

Checked 2026-09-23 (Asia/Kolkata). Ting **0.1.3 is published and deployed** from
`115954f074a9dfd48e3f14b39a70ecaf8cc7a6c5`. This records the fixes and rollout for
`ting-integration-issues.md`. Real DM delivery remains a separate acceptance check.

## Completed rollout and remaining gate

- [Backend deployment](backend-013-deployment-results.json) and
  [frontend deployment](frontend-release-013-results.json) succeeded. The public
  site, API documentation and installers serve 0.1.3. Both
  [Rust crates](crates-release-013-results.json), the six-platform native release
  and [Honeycomb production package](native-honeycomb-release-013-results.json)
  are published.
- [Runtime origins](ting-runtime-rollout-013.json) include DM and Interface.
  [31 public HTTP checks](public-browser-smoke-013-results.json) passed across
  the backend and frontend proxy, including actual-response credentialed CORS,
  preflight and unrelated-origin rejection.
- A [fresh official IAM login](session-origin-live-013-results.json) verified
  production session context and authenticated WebSocket `watch_inbox` from both
  allowed origins. Missing cookies returned 401 and an unrelated origin returned
  403. These are live protocol checks, not browser-navigation or DM-message tests.
  The same authorized manager registered `tos>dm.sync.changed` in production
  organization `tos`, then logged out only the new probe session.
- [DM and Honeycomb lifecycle configuration](dm-lifecycle-rollout-013.json) is
  loaded in running services. The original import completed, DM is in accepted
  imports, all five service receipts are ready, and environment
  `d70c8674-6d2e-41d4-bf8d-96ddd882edbd` has `operation_pending: false` at revision
  4/generation 1. Its pinned Ting package remains 0.1.2; publishing 0.1.3 did not
  silently change that selection. Existing DM/Honeycomb images were preserved.
- [DM's scope manifest](dm-scopes-rollout-013.json) was committed and pushed to
  DM main at `46c3b644cc8873b7475d706ed90887b87ae9c8a0`. Revision 2 was submitted
  and Ting approved both scopes. Publication
  `e13529a1-ee3d-451a-82e8-4391e74408ec` still awaits an eligible **Honeycomb
  validator**; the signed-in account cannot decide this gate. Effective DM
  revision remains 1 with no external scopes. After validator approval, finish
  configuration operation `6c3c5a5f-de11-4e00-97a6-6002a7ae555a` if still pending,
  verify revision 2 is effective, and obtain each intended actor's fresh consent.

No recipient was enrolled and no DM message or Ting notification was sent during
this rollout. The candidate DM/Interface delivery migrations were not deployed
by this Ting release. The cross-app acceptance checks below remain unproved.

## Changes in this checkout

- `TING_BROWSER_ORIGINS` adds comma-separated exact browser origins while retaining
  Ting's frontend/public origins. Allowed HTTP responses, including errors, carry
  credentialed CORS and `Vary: Origin`; browser WebSocket upgrades still require a
  Ting session cookie.
- `GET /v1/me` attests `environment: {"kind":"production"}` or
  `{"kind":"testing","id":"<IAM environment UUID>","generation":1}`. Legacy
  testing sessions without a bound generation must sign in again. Consumers must
  compare the explicit environment and generation, never treat missing fields as
  production.
- The Rust client exposes the existing WebSocket protocol for prepared publishing
  and receiving. Publishing still requires fresh actor-bound proof authority and
  the immutable original body/key when retrying an uncertain result.
- The lifecycle participant accepts Honeycomb's canonical `rotate-key` action
  (and legacy `rotate`) and rejects implicit reactivation of disabled/retired
  environments. Disabled environments require restore or purge; retired ones
  require explicit import or purge.
- Requests retain their verified testing generation and recheck local session/proof
  authority under the same gate as lifecycle changes before reading or mutating
  notification state. An IAM request that overlaps a clean cannot write using the
  old generation after cleanup.

These changes are available in the deployed backend and published 0.1.3 client.
The 0.1.2 client archive does not contain this SDK. See
[backend deployment](README.md).

Local verification: `cargo test --locked --workspace` passed 43 unit/protocol tests
and one compiling doctest; workspace build, CLI smoke, formatting, documentation
mirror and diff checks passed. Workspace Clippy completed with existing warnings.
The regressions cover exact proof bytes, canceled/lost replies, heartbeats, queue
overflow, browser CORS/origin boundaries and lifecycle generation races. No remote
acceptance claim follows from these checks.

## Before-rollout findings

Read-only checks on 2026-09-22 UTC, before the rollout above, established:

- Both Ting hosts still reject DM and Interface origins with HTTP 403. Permitted
  Ting-origin GET responses still lack credentialed CORS. Production has not loaded
  the changes above.
- [DM's accepted catalog configuration](https://backend.honeycomb.teamofsilicons.com/api/v1/apps/tos%3Edm)
  is revision 1 with `app_scope.external: []`. Its backend is
  `https://backend.dm.teamofsilicons.com`; its website is
  `https://dm.teamofsilicons.com`. The current upstream DM application manifest also
  has no external scopes; the report's candidate configuration is not live.
- Interface's [production deployment source](https://github.com/teamofsilicons/silicon-interface-web/blob/main/scripts/deploy-production.mjs)
  confirms `https://interface.teamofsilicons.com`.
- Environment `d70c8674-6d2e-41d4-bf8d-96ddd882edbd` remains at revision 4,
  generation 1, with `operation_pending: true`. DM is absent from accepted imports.
  Its import operation `bfefc652-12cb-42da-a579-7b0005bfebc2` reports
  `Protected lifecycle transport is not configured for this application`.
- DM's application secret has no Honeycomb service token; its runtime token and
  Honeycomb base URL are empty. Honeycomb's participant registry has Briefcase,
  Remind, Commit and Ting, but no DM entry or DM service token. Only presence and
  destination metadata were recorded; no credential values are included here.

## Rollout procedure

Steps 1–3 are complete. Step 4 awaits the validator gate above. Step 5's production
type setup is complete for `tos`; recipient and testing-environment setup remains
explicit. These commands document the procedure, not instructions to repeat
completed changes.

1. Deploy the reviewed Ting backend through the existing release workflow. Add
   this setting to its runtime secret, preserving all existing settings:

   ```text
   TING_BROWSER_ORIGINS=https://dm.teamofsilicons.com,https://interface.teamofsilicons.com
   ```

   The installer reloads `silicon-ting/production/runtime` in `us-east-1` and checks
   backend/gateway health. Verify both actual GET and preflight responses from each
   allowed origin, plus rejection of an unrelated origin:

   ```sh
   curl -i https://ting.teamofsilicons.com/v1/iam \
     -H 'Origin: https://dm.teamofsilicons.com'
   curl -i -X OPTIONS https://ting.teamofsilicons.com/v1/me \
     -H 'Origin: https://dm.teamofsilicons.com' \
     -H 'Access-Control-Request-Method: GET'
   ```

2. Provision one dedicated `DM_HONEYCOMB_SERVICE_TOKEN` through the service secret
   stores, with at least 32 visible ASCII characters. Put the same value in DM's
   application/runtime configuration and Honeycomb's `backend` environment map.
   Set DM's `DM_HONEYCOMB_BASE_URL` to
   `https://backend.honeycomb.teamofsilicons.com`. Append this registry entry while
   preserving every existing participant:

   ```json
   {"app_id":"tos>dm","base_url":"https://backend.dm.teamofsilicons.com","token_env":"DM_HONEYCOMB_SERVICE_TOKEN"}
   ```

   Honeycomb uses `silicon-honeycomb/production/runtime` in `us-east-2`; DM uses
   `silicon-dm/production` and `silicon-dm/runtime-production` in `us-east-1`.
   Follow [DM's Fargate deployment](https://github.com/teamofsilicons/silicon-dm/blob/main/deploy/aws/README.fargate.md):
   migration 0022 and runtime grants precede the API rollout; bootstrap copies the
   settings into the restricted runtime secret; replace API and worker tasks so
   they load the new values. Reload Honeycomb's existing deployed image/configuration
   through its [AWS deployment workflow](https://github.com/teamofsilicons/silicon-honeycomb/blob/main/deploy/aws/README.md),
   preserving its data and other participant settings. A secret-store edit alone
   does not update either running service.

3. Read the current environment revision, then retry the original pending import:

   ```sh
   honeycomb environments get d70c8674-6d2e-41d4-bf8d-96ddd882edbd --json
   honeycomb environments action d70c8674-6d2e-41d4-bf8d-96ddd882edbd retry \
     --revision CURRENT_REVISION --idempotency-key FRESH_RETRY_KEY --json
   ```

   Success requires DM in accepted imports, the original operation completed, all
   required service receipts ready and `operation_pending: false`. Top-level
   `state: ready` alone is insufficient. Do not use the configuration-operation
   retry route or substitute a user/root token for the service credential.

4. Apply DM's candidate external scopes (`tos>ting` / `subscriptions.register` and
   `tings.send`) through Honeycomb's normal configuration/review flow. Retain
   `self.identity.read` in both apps and obtain recipient consent using fresh
   eligible sessions. Private test configuration can stage the scopes in the shared
   environment; production requires its own accepted review and consent.

5. In each selected organization/environment, an authorized Ting application
   manager registers the notification type:

   ```sh
   ting --org ORG types register --type 'tos>dm.sync.changed' \
     --description 'A DM message or receipt changed; fetch its current authorized state from DM.'
   ```

   Then explicitly enroll each recipient from DM and separately authenticate the
   receiver with Ting and attach its inbox/hook. Repeat type, grant and hook setup
   after a shared clean. A DM login does not create a Ting session. Browser adapters
   must use the Ting host that issued their cookie and consume the new session
   context before presenting delivery as environment-verified.

## Lifecycle compatibility and preserved contracts

Honeycomb's current [participant adapter](https://github.com/teamofsilicons/silicon-honeycomb/blob/main/crates/server/src/participant_management.rs)
uses protected **PUT**, replays the same operation/payload and validates the exact
receipt identities, revision, generation and key version. Ting's replayed PUT
receipt is compatible; adding a GET receipt endpoint is unnecessary. Honeycomb
forwards `rotate-key`, maps `delete` to `disable`, and maps `retire` to
`retire-applications`.

The initiating account's DM session remains the selected publishing authority.
Expired/revoked authority stays pending until that same actor returns; another
actor's login cannot release it. Enrollment is an explicit action because repeating
it reactivates a revoked grant. The report's durable DM enrollment-key reservation
is a deliberate workaround, not a new Ting idempotency contract.

The 256 KiB body limit, 14-day producer deduplication window, retention periods,
silent/muted behavior and independent hook copies remain Ting policy. Send bounded
DM references, keep recipient/event-specific immutable keys, reconcile through DM
and deduplicate the DM event. Ting acceptance/read is not a DM delivered/read
receipt. A hook's HTTP 204 accepts its entire multi-app batch; a DM-only consumer
must not discard other apps' items. Inbox hints contain no DM content and do not
replace reconnect/HTTP catch-up or authorize automatic inbox acknowledgments.

## Required remote acceptance checks

- Persist a DM message/handoff, interrupt publishing, revoke its initiating
  session, restart and prove it stays pending. Another actor's login must not
  release it; the original actor's fresh eligible login must produce real Ting
  acceptance and recipient delivery.
- From both real browser origins, sign into Ting, match actor/environment/generation,
  receive a real hint, fetch authorized DM content, reconnect and recover. Reject
  wrong actors, revoked sessions and stale generations; cover silent notifications
  through HTTP reconciliation.
- With both apps imported, clean while deliveries are pending. Verify both lifecycle
  receipts complete, stale events cannot recreate DM state, and fresh type/grant/hook
  setup permits fresh delivery. Rotate credentials and reject retired/stale contexts
  without production fallback.

The rollout above changed production configuration and recovered the shared
environment import. It did not send a real DM message. These remote acceptance
checks are not passed by local compilation, fixtures, health responses or older
Ting-only lifecycle evidence.
