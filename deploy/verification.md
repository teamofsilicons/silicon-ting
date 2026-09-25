# Deployment verification

Updated 2026-09-25 UTC. Ting **0.1.9**, release source `6853b4e247f434e358f4bbd05e5d23d5ae7870cd`, is published natively, on Honeycomb and on crates.io. Backend **0.1.8**, release source `ebde4c2a824931cfcc21eb5ec3afbd366c2f2767`, remains [deployed and healthy](backend-018-deployment-results.json); the 0.1.9 backend archive is built but not yet deployed, and the frontend still serves the 0.1.8 installers. Public targets are [Ting](https://ting.teamofsilicons.com) and [the backend](https://backend.ting.teamofsilicons.com).

## Current 0.1.9 release

After a Honeycomb-only install, the first `ting webhook` starts the daemon itself, as the calling account, with no sudo, prompt, installer or service manager. The CLI connects first and starts nothing while a daemon answers. An installed system service is still preferred but is only asked with `systemctl --no-ask-password`. The sudo installer is now optional start-at-boot supervision. New `ting daemon start` needs no login and suits a liveness tick.

| Check | Evidence and scope |
| --- | --- |
| Source validation | [80 workspace unit tests and one compiling doctest passed](release-validation-019.json), including six on-demand start tests against temporary paths, plus workspace build, CLI smoke, five packaging tests, one installer test, formatting, mirrors, two frontend tests, the frontend build and Windows/Linux cross-compilation. |
| On-demand daemon acceptance | [Rows 1–10 passed in the tagged release run](native-honeycomb-release-019-results.json) on native runners, run exactly as Silicon runs `ting` (stdin null, captured output, 30-second bound): Linux x86_64 all ten rows, including an installed running and stopped systemd unit; Linux ARM64 and both macOS targets rows 1–6, 9 and 10; both Windows targets rows 1, 2, 3, 5 and 9. A new `no-systemd` job passed the same Unix rows in an `ubuntu:24.04` container as an unprivileged user. Row 5 used strace on Linux. Systemd 258+ polkit behaviour (row 10) was checked only as a terminal-attached start on systemd 255; Ubuntu 26.04 and a fresh EC2 `silicon connect` remain manual checks. |
| Native and Honeycomb | [All six native builds, the no-systemd job and publication passed](native-honeycomb-release-019-results.json). Every archive matches `SHA256SUMS`. Honeycomb production is publicly published at 0.1.9 with the new `SERVICE.md`; anonymous app and release access return 200 and older releases remain. The published macOS binary reports 0.1.9 and, beside an existing 0.1.x LaunchDaemon, only probes it. |
| Crates | [Client and CLI 0.1.9 are published and non-yanked](crates-release-019-results.json). Downloaded archive checksums and clean embedded source commits match the release. |
| Backend | [Backend workflow](https://github.com/teamofsilicons/silicon-ting/actions/runs/36125738790) passed all three jobs for `server-6853b4e247f434e358f4bbd05e5d23d5ae7870cd`. SSM deployment is pending; the server code is unchanged from 0.1.8 apart from its version. |
| Frontend | Pending: Vercel promotion of the 0.1.9 docs and installers has not run. |

## Historical 0.1.8 release

`ting login` replaces an existing valid, expired, or revoked saved session without requiring logout. Failed exchanges preserve the old session and pending recovery attempt. A successful replacement stops the old session's local webhook forwarding; callers explicitly reattach webhooks for the new session.

| Check | Evidence and scope |
| --- | --- |
| Source validation | [73 workspace unit tests and one compiling doctest passed](release-validation-018.json), plus workspace build, expanded login replacement/recovery CLI smoke, five packaging tests, one installer test, formatting and documentation/installer mirrors. |
| Native and Honeycomb | [All six native builds and publication passed](native-honeycomb-release-018-results.json). Every archive matches its checksum. Honeycomb production is publicly published at 0.1.8; anonymous app and release access return 200. The earlier public-catalog blocker is resolved. |
| Crates | [Client and CLI 0.1.8 are published and non-yanked](crates-release-018-results.json). Downloaded archive checksums and clean embedded source commits match the release. |
| Backend | [All three backend workflow jobs and SSM deployment checks passed](backend-018-deployment-results.json). The archive checksum and embedded commit were verified; public health reports 0.1.8. |
| Frontend | [Vercel production promotion and 16 public resource comparisons passed](frontend-rollout-018.json). Both public domains serve source-matching assets, login docs and 0.1.8 installers; telemetry build settings are preserved. Two frontend tests and the production build passed. |
| Public boundaries | [45 live HTTP/CORS checks passed](public-browser-smoke-018-results.json) across backend and frontend proxy without notification writes. |
| Live login replacement | [Published 0.1.8 CLI passed real IAM login and session replacement](live-login-replacement-018-results.json): valid saved credentials were replaced; a server-revoked credential remained on disk, status reported unauthenticated, and fresh login succeeded without logout. All three isolated test sessions were revoked and confirmed unauthorized afterward. Natural expiry and webhook delivery were not exercised. |

## Historical 0.1.7 release

Apps can set their own retained tings read or unread through `POST /v1/sent/read` with a fresh exact-request IAM proof for `sent.read`. Updates validate the whole batch, preserve webhook receipts and retention, and safely replay operation keys without overwriting newer state.

| Check | Evidence and scope |
| --- | --- |
| Source validation | [73 workspace unit tests and one compiling doctest passed](release-validation-017.json). Workspace build, CLI smoke, five packaging tests, one installer test, formatting and documentation mirrors passed. |
| Native and Honeycomb | [All six native platforms passed and GitHub assets are publicly available](native-honeycomb-release-017-results.json). Each downloaded archive matches its checksum. Honeycomb accepted the verified six-platform package on the production channel and reports latest version 0.1.7; public catalog access remains blocked by its review-plan error. |
| Crates | [Client and CLI 0.1.7 are published and non-yanked](crates-release-017-results.json). Downloaded checksums and clean embedded source commits match the release. |
| Backend | [All three backend workflow jobs and SSM deployment checks passed](backend-017-deployment-results.json). The archive checksum and embedded commit were verified; public health reports 0.1.7. |
| Frontend | [Vercel production promotion and public checks passed](frontend-rollout-017.json). Both domains serve source-matching JavaScript, CSS, docs and 0.1.7 installers; telemetry settings are preserved. Mocked Chrome checks verify browser refresh and repeat read after an app marks a ting unread. |
| Public boundaries | [45 live HTTP/CORS checks and the new route authentication boundary passed](public-browser-smoke-017-results.json) across the backend and frontend proxy, without recipient mutations. |
| Authenticated read/unread | [Live acceptance passed with real IAM proofs](live-sent-read-017-results.json): app read and unread appeared in sent history and recipient inbox; replay preserved newer state, changed content with the same key conflicted, and a mismatched issuer was rejected. One isolated test ting, zero production sends. The imported Ting app acted as controlled sender and audience; this is protocol evidence, not a third-party app/browser end-to-end run. |
| IAM catalog and publication | [Configuration revision 4 is effective and production IAM exposes `sent.read`](ting-config-rollout-017.json). Honeycomb public listing remains private with an upstream review-plan validation error; runtime configuration is effective independently of public listing. |

The successful acceptance environment was deleted through coordinated lifecycle operations, with all service receipts ready and no pending operation. An earlier failed cross-org test setup remains blocked from deletion by Honeycomb’s pending configure operation; its test sessions are logged out and it sent no notifications. [Cleanup evidence and required upstream resolution](live-sent-read-017-results.json).

## Historical 0.1.6 release

[The identifier cutover evidence](identifier-migration-016-results.json) records the deployed canonical actor/application identifiers, verified migration and authentication reconciliation, native/crates/Honeycomb publication, frontend promotion, protocol validation and fixture cleanup. Its local Ting delivery checks are not substituted for live 0.1.7 acceptance.

## Historical 0.1.5 release

| Check | Evidence and scope |
| --- | --- |
| Source validation | [62 workspace unit tests and one compiling doctest passed](release-validation-015.json), including cross-org recipient isolation and owner-only type management. Workspace build, CLI smoke, five packaging tests, one installer test, formatting and documentation mirrors passed. |
| Native and Honeycomb | [All six native platforms passed and the production package is published](native-honeycomb-release-015-results.json). Downloaded archives match their checksums; prior releases remain available. |
| Crates | [Client and CLI 0.1.5 are published and non-yanked](crates-release-015-results.json). Downloaded checksums and clean embedded source commits match the release. |
| Backend | [All three backend workflow jobs and SSM deployment checks passed](backend-015-deployment-results.json). The archive checksum and embedded commit were verified; public health reports 0.1.5. |
| Frontend | [Vercel production promotion and public asset checks passed](frontend-rollout-015.json). JavaScript, CSS, docs and 0.1.5 installers match the tested source/build, and telemetry configuration is preserved. Chrome UI checks cover cross-org filters/preferences and mobile layout with mocked API/WebSocket responses. |
| Public boundaries | [45 live HTTP/CORS checks passed](public-browser-smoke-015-results.json) across backend and frontend proxy. These checks require no credentials and do not mutate recipient state. |
| Cross-org delivery | [Six live acceptance groups passed](live-cross-org-015-results.json) using real IAM authority and public HTTPS/WebSocket. A recipient belonging only to a foreign org received a type registered under the app owner. Grant requirements, catalog authority, inbox filtering, receipts, read ACKs, retry dedupe, preferences and revocation were verified. Two isolated test tings, zero production sends. The task-owned environment was cleaned and deleted; all lifecycle services are ready with no pending operation. This is protocol evidence, not a Hook adapter/browser end-to-end run. |

## Historical 0.1.4 release

| Check | Evidence and scope |
| --- | --- |
| Source validation | [60 workspace tests and one compiling doctest passed](release-validation-014.json), including 12 auth tests, six receiver tests and 13 store tests. Workspace build, CLI smoke, five packaging tests, one installer test, two frontend tests, build and mocked Chrome checks passed. Clippy completed with warnings. |
| Native and Honeycomb | [All six native platform builds and publication passed](native-honeycomb-release-014-results.json). Every downloaded asset matched its checksum; the validated Honeycomb package is anonymously available as production 0.1.4. Older releases remain available. |
| Crates | [Client and CLI 0.1.4 are published and non-yanked](crates-release-014-results.json). Downloaded archive checksums and embedded source commit match the clean release commit. |
| Frontend | [Vercel production promotion and public asset checks passed](frontend-rollout-014.json). Both existing domains serve the tested JavaScript, docs and 0.1.4 installers. Required-delivery UI checks use mocked APIs; telemetry configuration is preserved. |
| Backend | [All three backend workflow jobs and deployment health checks passed](backend-014-deployment-results.json). The installer fetched the latest runtime configuration and verified archive checksum/provenance. |
| Login recovery | [Real production replay after 125.001 seconds returned the identical opaque credential](live-login-recovery-014-results.json) with HTTP 200; the original session remained valid. Changed input returned 409. Cleanup returned 200 and the revoked session returned 401. The original response was privately captured as an oracle; packet loss was not injected. |
| Public boundaries | [45 live HTTP/CORS checks passed](public-browser-smoke-014-results.json) across backend and frontend proxy, including separate full-session/receiver token boundaries and exact DM, Interface and Hook browser origins. These are protocol checks, not browser or Hook adapter end-to-end evidence. |
| Isolated Hook acceptance | [Nine live acceptance groups passed for Carbon and Silicon](hook-scopes-rollout-014.json) with real IAM proofs: Hook-only scoped bootstrap/recovery, required muted hook delivery and watch hints, separate ACKs, dedupe, opt-out and revocation. Coordinated clean rejected both fresh capabilities before expiry; the task-owned environment is deleted, all participants ready, no pending operation. Six test tings and zero production sends. This is protocol evidence, not a Hook worker/browser adapter end-to-end run. |
| Approval gates | [Ting's new production endpoint definition](ting-config-rollout-014.json) awaits Honeycomb validator approval; [Hook's external scopes and lifecycle setup](hook-scopes-rollout-014.json) track the dependent rollout. The current Carbon is not an eligible validator. See [the Hook runbook](hook-integration.md). |

## Historical 0.1.3 release

| Check | Evidence and scope |
| --- | --- |
| Source validation | 43 workspace unit/protocol tests and one compiling doctest passed. Workspace build, CLI smoke, formatting and documentation mirrors passed; Clippy completed with existing warnings. Five packaging tests, one Unix installer regression and two frontend tests/build also passed. |
| Publication | [Both crates are published and non-yanked](crates-release-013-results.json). [All six native platform builds and Honeycomb publication succeeded](native-honeycomb-release-013-results.json); the production Honeycomb archive is 0.1.3. Older versions remain available. |
| Running services | [Backend release](backend-013-deployment-results.json) passed workflow and installer health checks. [Vercel frontend](frontend-release-013-results.json) is READY, retains its telemetry configuration and serves source-matching 0.1.3 docs/installers. |
| Browser boundaries | [31 live public checks](public-browser-smoke-013-results.json) passed across both hosts. [Fresh IAM login and WebSocket checks](session-origin-live-013-results.json) verified production session context, DM/Interface authenticated inbox watch, and missing-cookie/unrelated-origin rejection. These were protocol checks, not an actual browser or DM end-to-end run. |
| DM setup and lifecycle | Production `tos>dm.sync.changed` type is registered in `tos`. [DM/Honeycomb rollout](dm-lifecycle-rollout-013.json) loaded dedicated lifecycle authority and completed the original shared import; all receipts are ready and no operation is pending. No clean/rotation or message-delivery acceptance claim follows. |
| Remaining external gate | [DM configuration revision 2](dm-scopes-rollout-013.json) has Ting's scope approval and awaits Honeycomb validator approval. Effective revision remains 1. Fresh recipient/initiator consent and the real cross-app acceptance checks in the [runbook](dm-integration.md) remain outstanding. |

## Historical 0.1.2 and earlier verification

The following measurements and checks retain their original version scope.
Backend 0.1.2 used commit `a86971a08089bd212810b2df49f3f13bd41e83ac`.
Earlier recovery and latency reports used backend
`c96cb93c3068f3577875e7bfd97f5d5601a76827` and native client/daemon 0.1.0;
these are not substituted for fresh 0.1.3 delivery or performance evidence.

| Check | Evidence and scope |
| --- | --- |
| Final 0.1.2 checks | [28 Rust tests, five packaging tests, one installer regression, two frontend tests, TypeScript/build, browser regression, installed CLI smoke, and format/syntax checks passed](release-audit-012-results.json). All 18 native archives across 0.1.0–0.1.2 were freshly downloaded and matched their published checksums. |
| Earlier workspace regressions | **25 tests passed** at source commit `e8e90005d39e5601116846892707f21494b70739`: CLI 1, client 3, daemon 6, server 15. These include expired-copy invalidation, retained unread delivery, uncertain retention checks, no empty-batch POST, Unix peer credentials, and private-directory symlink rejection. This is source-level evidence, separate from live deployment checks. |
| Backend 0.1.2 regressions | [18 server tests passed](backend-012-regression-results.json) at `a86971a08089bd212810b2df49f3f13bd41e83ac`. New tests count actual SDK requests to a local IAM HTTP fixture, reject invalid authority without changing receipts, verify periodic revocation still pauses delivery, and exercise a real local WebSocket blocked on IAM. Removing only the notification fix in a temporary copy makes that last test fail at its 500 ms deadline. The production build passed all three jobs and the checksum-verified archive was installed through SSM; the public backend reports 0.1.2. |
| Unix installation boundary | [Installer regression](../scripts/test-unix-installer.py) passed against temporary paths with a sudo stub: a pre-created symlink and a competing creation leave the target untouched; existing legitimate directories and fresh creation succeed through the directory step. No real elevation occurs in this regression. Format, shell syntax, diff checks, and public installer/source parity passed locally. |
| Public API | [12 passed groups](live-test-012-results.json), refreshed against deployed 0.1.2: real public HTTP/WebSocket requests with isolated IAM test credentials; proof integrity/reuse, idempotency, independent ACKs, reconnect, preferences, ownership, logout, and durable bug-report ingestion. |
| Request boundaries | [10 passed checks](public-smoke-012-results.json), refreshed against deployed 0.1.2: authentication, browser origin controls, duplicate JSON keys, byte limits, telemetry allowlist, and unknown routes. |
| IAM webhook signatures | [200 / 401 / 401](iam-webhook-test-results.json) for valid, altered, and unsigned envelopes through the public route. These were locally signed SDK-compatible test envelopes, not an observed IAM-originated callback. |
| Honeycomb lifecycle | [Final 0.1.2 coordinator cleanup](integration-cleanup-012-results.json) paused the receiver, revoked its session, and deleted the isolated environment at revision 17/generation 5. Temporary participant configuration and credentials were removed. [Regional benchmark cleanup](region-benchmark-012-cleanup.json) removed its container/runtime and all private S3 fixture versions. Earlier [0.1.1 lifecycle](live-lifecycle-test-results.json), [integration cleanup](integration-cleanup-results.json), and [local lifecycle tests](lifecycle-test-results.json) remain separately recorded. The older abandoned-fixture blocker is described below. |
| Live retention | [Passed against backend 0.1.1](live-retention-test-results.json): a guarded 60-day-old isolated ting became read; the other hook received `paused` immediately, inbox lookup returned 404, and both pending counts became zero. |
| Native daemon | [0.1.2 local IPC smoke](native-ipc-smoke-results.json) passed with the installed macOS ARM64 binaries and matching owner identity; it used no live IAM credentials. The [0.1.1 functional smoke](native-011-smoke-results.json) delivered one fresh ting through the real public backend; this single sample is not a benchmark. The earlier [four-check 0.1.0 run](daemon-live-test-results.json) covered SQLite commit before delivery ACK, lost read ACK recovery without a duplicate callback, independent failed-hook retry, and 30 real deliveries. Fault injection used a transparent loopback relay; measured delivery samples bypassed it. |
| macOS service | [Administrator-approved installation](macos-service-012-results.json) registered `system/com.silicon.ting`. It runs as UID 501, not root, with restart enabled, root-owned verified 0.1.2 binaries/plist, and owner-only socket/state directories. Same-owner CLI IPC passed using an isolated temporary profile and reserved loopback port; this check did not test live authentication or remote delivery. |
| Frontend | [Two unit tests, TypeScript/build, and Chrome UI checks](frontend-test-results.json) passed. Automated UI checks use deterministic mocked HTTP/WebSocket responses. A separate manual Chrome session completed real public IAM sign-in. Vercel deployment `dpl_HNLv7EN28pSRea5vVn81zEgTm1gQ` is ready; public homepage returned 200 and both public installers match source/default to **0.1.2**. Automated UI results do not establish live-backend coverage. |
| Frontend credential audit | [No credential matches found](frontend-secrets-audit.json): offline comparison of 29 known credential fingerprints against 30 historical frontend blobs, current files, and 18 live frontend resources. Fourteen source-map/config/private-path probes returned 404. [Authenticated Vercel file reads](frontend-authenticated-history-audit.json) also scanned 50 unique uploaded files across all five READY deployments, with no match. Source uses only the two telemetry-table environment variables and never exposes the full environment object. Final protected build bytes and historical injected environment values remain unavailable through these read APIs; uploaded `dist` files are not substituted for remote build output. Browser table names are public identifiers; ingest keys remain backend-only. |
| Telemetry | [Public proxy checks](telemetry-proxy-test-results.json) received `202` and `accepted: true` for frontend analytics/events. [Final storage queries](telemetry-verification.json) observed backend 839, frontend analytics 9, frontend events 8, and CLI/daemon 7 records. The [seven native entries](native-telemetry-verification.json) are `cli_command` events: two Linux 0.1.0, four macOS 0.1.0, and one macOS 0.1.1. The benchmark disables telemetry and does not verify stored webhook-delivery events. |
| Restart and backup | [Five passed checks](recovery-test-results.json): live process restart, encrypted session continuity, unchanged inbox, successful online backup, and integrity checks on both downloaded encrypted S3 SQLite snapshots. Restoration was to temporary files, not production; host-loss recovery was not simulated. |

## Measured latency

[Developer-host delivery measurements](daemon-live-test-results.json): 30 sequential, small-payload, proof-ready WebSocket sends through public TLS to AWS `us-east-1` (Northern Virginia), then back to the installed daemon and a webhook on the same developer Mac. Client city/country was not verified. Existing connections were used; proof minting and consumer processing were excluded. Callback arrival was measured with one monotonic clock.

- Delivery: **p50 490.297 ms; p95 760.482 ms**; range 448.211–761.555 ms.
- [Public WebSocket ping/pong](network-latency-results.json): 30 samples after three warmups; p50 233.784 ms, p95 307.112 ms. This measures a network/proxy floor, not delivery or proof verification.
- [HTTP acceptance on 0.1.1](live-test-results.json): five samples, p50 1012.7 ms and p95 1111.5 ms. This small functional sample is not a load benchmark.

The documented sub-100 ms WebSocket p95 is a target, not an established SLA. It was not met on either the developer-host or regional route. No production throughput or saturation claim follows from these sequential samples.

[The completed regional benchmark](region-latency-test-results.json) used native 0.1.0 binaries inside an Ubuntu 24.04 ARM64 container on the AWS `us-east-1` backend host, with public TLS and a callback on container loopback. It recorded **30 deliveries after three excluded warmups**, with three-second spacing outside each timed interval:

| Regional observation | p50 | p95 |
| --- | ---: | ---: |
| Proof-ready send → webhook arrival | 245.457 ms | 318.426 ms |
| Same send → accepted response | 240.468 ms | 313.436 ms |
| Public WebSocket ping/pong baseline | 0.649 ms | 0.726 ms |
| Callback timestamp minus accepted-response timestamp | 4.813 ms | 7.777 ms |

The last row is an observer timestamp difference, not isolated server processing time. An [earlier attempt](region-latency-partial-results.json) stopped after 21 successful samples on `dependency_unavailable`; its upstream cause was not confirmed and no rate-limit response was captured.

Five direct IAM probe pairs, recorded in the regional report, all returned 200: context validation took 33–96 ms and single-use proof verification 212–319 ms. Source inspection confirms Ting constructs one `silicon-iam-client` 3.1.0 client; credential/environment variants retain the shared `reqwest` pool, wrappers borrow it, and responses are consumed fully. No client reconstruction or redundant discovery call was found. These required upstream calls account for a substantial latency floor; neither check was bypassed.

[The subsequent performance analysis](latency-analysis.md), with [sanitized evidence](latency-analysis-evidence.json), found low CPU/disk pressure and a reused Ting-to-IAM HTTPS p95 of 3.04 ms. Existing IAM logs show successful verification p50/p95 of 210/328 ms across mixed users. Backend 0.1.2 removes duplicate live checks from ACK/periodic authority decisions and preserves receiver notifications during handler waits. This reduces unnecessary work and prevents the tested one-second scheduling delay; the [fresh regional 0.1.2 run](region-latency-012-results.json) is reported below, and no new latency SLA is claimed.

The **post-deployment 0.1.2 regional run** used the same existing host, public TLS, an isolated IAM testing fixture, and published Linux ARM64 CLI/daemon 0.1.2. All 30 deliveries passed after three warmups and with three-second spacing. Callback latency was **p50 251.517 ms / p95 329.971 ms**; acceptance was **246.306 / 324.787 ms**; paired callback-minus-acceptance was **5.294 / 6.948 ms**. The largest callback sample was 553.757 ms, of which 545.611 ms preceded acceptance. This small run does **not** demonstrate first-callback improvement over the earlier 318.426 ms p95. [Full comparison and limitations](latency-analysis.md).

A separate [local native burst reproduction](daemon-burst-latency-analysis.json) found a 945–947 ms scheduler wait when a second message arrives during the first read ACK. An isolated candidate reduced that narrow wait to 1.3–1.7 ms, but it is a future native patch, not shipped 0.1.2 behavior or a new end-to-end benchmark. Published native archives and tags remain unchanged.

## Retention and release follow-up

Retention uses rolling UTC calendar cutoffs: `now - 1 month` for read **or** silent tings and `now - 3 months` for unread non-silent tings. A timestamp equal to its cutoff is retained; older timestamps expire. Calendar subtraction clamps at month ends. Original creation time is preserved through retries. Server queries filter expired records immediately; physical cleanup runs at startup and hourly.

Source regression checks cover query/offer/prune behavior, preservation of uncertain accepted receipts, and aged pending copies that another destination has read. The daemon checks aged candidates against authenticated server state before forwarding, reloads its batch, and sends nothing when every candidate was removed. An uncertain check prevents forwarding; fresh batches add no retention HTTP request.

**0.1.1 release status:** the Rust client and CLI crates and [native release artifacts](https://github.com/teamofsilicons/silicon-ting/releases/tag/v0.1.1) are published. The [native workflow](https://github.com/teamofsilicons/silicon-ting/actions/runs/35706612610) passed client/CLI/daemon tests and release builds on macOS, Linux, and Windows, each on x86-64 and ARM64. The [backend build](https://github.com/teamofsilicons/silicon-ting/actions/runs/35706545340) passed and commit `397feeab9aadbae110a915a4c59e3af8c367c485` was deployed successfully through SSM, with healthy HTTPS. Release directory: `397feeab9aadbae1-62a9df2975c6`; archive SHA-256: `62a9df2975c66ae62cf1743a0e56a9c73d585d83918aa39859223bfd8a371ffe`.

**Client/CLI/daemon 0.1.2 is published and installed**, from commit `e8e90005d39e5601116846892707f21494b70739`. Its [six-platform native workflow](https://github.com/teamofsilicons/silicon-ting/actions/runs/35708888149) and publish job passed; all six archives were checksum-verified. [Distribution evidence](distribution-012-results.json) confirms both Rust crates are published, Honeycomb accepted the 0.1.2 archive with HTTP 201, and the effective local CLI and daemon match the published native hashes. Older GitHub releases and crates remain available and were not yanked. Honeycomb's [public catalog publication is complete](honeycomb-012-publication-status.json): the external validator approved revision 2, activation completed automatically, and `tos>ting` is public with 0.1.2 current. Its existing 0.1.0 package remains available.

The native patch verifies the Unix socket peer's effective UID before sending credentials, matching Windows SID verification. It rejects symlink/foreign-owned IPC directories before privileged installation, creates missing directories atomically as the service owner, and validates runtime directories through `O_DIRECTORY | O_NOFOLLOW`, descriptor ownership, and descriptor-based permissions. Backend 0.1.2 is a separate source change at `a86971a08089bd212810b2df49f3f13bd41e83ac`; its [production rollout succeeded](backend-012-deployment-results.json). The 12 real-IAM protocol groups were repeated on deployed 0.1.2. Earlier retention and native-delivery evidence remains explicitly attributed to its tested version.

[Final temporary probe cleanup is complete](integration-cleanup-012-results.json), and [benchmark cleanup is complete](region-benchmark-012-cleanup.json). The working fixture is recoverably deleted under Honeycomb's normal retention window. A separate earlier abandoned fixture remains blocked upstream: IAM rejected its mismatched test organization, but Honeycomb retains a pending configure operation and exposes no supported cancellation. Official deletion rejects that pending operation. No database workaround or independent IAM deletion was performed.

The earlier 0.1.0 recovery/performance runs remain separately identified; they are not substituted for the later release checks. The developer Mac now has the administrator-approved 0.1.2 system service running. Platform CI executes native code tests; full authenticated end-to-end runs recorded here cover macOS ARM64 and Linux ARM64, not every operating system/service installation combination.
