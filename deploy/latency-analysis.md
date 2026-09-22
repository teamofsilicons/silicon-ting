# Delivery latency analysis

The regional p95 of **318.4 ms is dominated by IAM verification**, rather than Ting delivery or network distance. The deployed backend 0.1.2 eliminates duplicate ACK validation and missed receiver wake-ups. Neither should be presented as a large reduction in the first-callback benchmark; reducing its main cost requires focused IAM profiling. More hardware is not currently justified.

The original analysis uses the [30-sample regional benchmark](region-latency-test-results.json), which ran Ting server `c96cb93c` and native clients 0.1.0. A fresh 0.1.2 benchmark is recorded below; the original measurements remain attributed to their tested versions. The additional IAM diagnostics below were read-only; their sanitized measurements and command IDs are in [latency-analysis-evidence.json](latency-analysis-evidence.json).

| Measurement | Median / p95 | Interpretation |
| --- | --- | --- |
| Regional send → native callback | 245.5 / 318.4 ms | Existing sockets, proof already minted, small messages, three seconds between samples; excludes callback ACK. |
| Same send → accepted response | 240.5 / 313.4 ms | Almost all the measured wait occurs before durable acceptance. |
| Paired callback timestamp minus acceptance timestamp | 4.8 / 7.8 ms | Observer difference on the same host, not an isolated internal server stage. |
| Regional WebSocket ping | 0.65 / 0.73 ms | Network/proxy floor for Ting. |
| Ting host → public IAM `/healthz`, reused HTTPS | 2.68 / 3.04 ms | 20 samples after three warm-ups. Initial DNS/TCP/TLS setup was 19.4 ms; the SDK already reuses its client pool. |
| IAM loopback API `/healthz` | 0.83 / 1.22 ms | 20 samples after three warm-ups. |
| Successful IAM proof verification, existing server logs | 210 / 328 ms | 87 requests during 08:25–09:00 UTC. Includes mixed IAM users, not only Ting. |
| Successful IAM testing-context lookup, same logs | 29 / 85 ms | 531 requests; this extra RPC is used for testing environments. |
| Successful IAM introspection, same logs | 29 / 56 ms | 2,824 requests; relevant to ACK and receiver revalidation costs. |

The independent five-pair regional component probe also measured verification at 212–319 ms and context lookup at 33–96 ms. These samples and percentiles are not synchronized stage measurements and must not be added as a precise p95 budget. At the median, however, roughly 210 ms verification, 29 ms testing-context work and a few milliseconds of delivery are consistent with the observed 245 ms total.

Ting and IAM run on `t4g.small` instances in `us-east-1a`. IAM's production and testing PostgreSQL databases are also in that availability zone, on `db.t4g.small` and `db.t4g.micro`. Their VPCs differ, so Ting uses IAM's existing public Elastic IP/nginx ingress. The measured network floor makes VPC networking changes a low priority.

During the three-hour metrics window, IAM EC2 CPU averaged 4.0% and its credit balance stayed at 576. Production/testing database CPU averaged 6.1%/4.6%, with credits essentially full. Average storage write latency was approximately 0.97/1.26 ms and disk queues were low. The testing database has less spare memory, but these measurements do not show CPU-credit or storage saturation. Increasing instance size would not remove serialized validation work.

The deployed IAM revision is `ae6ceb3b8b05134bf16232151d68d380b01eeabe`; the examined proof/security/context implementations match that revision. Verification uses HMAC and constant-time comparison, not a deliberately slow password hash. Its request path performs a rate-limit write, application-secret authentication and activity updates, live parent/consent/epoch/endpoint checks, atomic one-use consumption, and audit/outbox writes. Testing also checks generation fences and updates activity in the control and testing databases. The successful authorization snapshot contains substantial joins and locking reads. These are stronger profiling candidates than network transport, but no positive-request per-statement timings are available because `pg_stat_statements` is unavailable.

An earlier IAM migration bounded join planning inside a different membership helper and substantially improved its disposable concurrency fixture. That result is **not a Ting gain**. The new read-only check exercised the exact OBO current-context helper with nonexistent identities and zero returned rows. Alternating transaction-local `join_collapse_limit` values of 8 and 1 changed production median execution from 8.42 to 7.63 ms; warmed testing samples changed from about 10.5 to 9.0 ms. One initial testing sample took 53 ms. This small no-row result does not justify changing IAM's production planner settings or explain the successful verification path's remaining cost.

Changes shipped and remaining priorities:

1. **Shipped: one fresh authorization snapshot per ACK/revalidation decision.** The previous ACK path authenticated the session and then loaded the organization through another live authentication. Removing that duplicate retains freshness and roughly halves those validation calls: production goes from two introspections to one; testing goes from two context lookups plus two introspections to one of each. A rough expectation is one introspection's latency saved per decision, plus one context lookup in testing—not a measured post-fix gain. This helps batch progress and rate-limit pressure; first callback arrival excludes these ACKs.
2. **Shipped: preserve receiver wake-ups while a handler is busy.** The missed-notification case can otherwise wait for the one-second fallback timer. This is an avoidable tail-latency risk, even though the regional callback-after-acceptance measurements were already fast. A loopback WebSocket regression directly verifies this race; a separate native burst limitation is documented below.
3. **Profile successful IAM verification in a disposable fixture.** Time secret authentication, current-context validation, authorization-snapshot loading, proof consumption, audit/outbox work and commit separately. Preserve all current checks and one-use consumption. Optimize only the measured expensive statement—for example, a function-local planner bound with unchanged SQL/security properties, or fewer SQL round trips inside the same transaction. A claim such as 100 ms saved is premature without that profile and positive/revocation/concurrency tests.
4. **Keep the current hardware and network topology initially.** Reusing the daemon's callback HTTP client may help repeated callbacks, particularly where connection setup matters, but the observed local delivery remainder is only a few milliseconds. Extra VMs, larger database pools or broader authentication caches are not supported by this measurement.

The existing log window contained three testing-context and sixteen introspection 429 responses across all IAM traffic. They cannot be attributed to the earlier failed regional run without request correlation, but they strengthen the case for removing duplicate validation calls before adding capacity. The successful benchmark used three-second spacing and is not a throughput or burst-load test.

Production sends omit the separate testing-context RPC, so they should avoid that work; no production positive-send benchmark was run, and this report does not subtract testing percentiles to invent one. Expect the first-callback result to remain in the hundreds of milliseconds until IAM's positive verification path is optimized. The immediate Ting changes should improve ACK progress, avoid occasional long waits and reduce unnecessary IAM load while preserving the existing security contract.

## Post-deployment 0.1.2 measurement

The [fresh regional run](region-latency-012-results.json) used backend `a86971a`, the published 0.1.2 Linux ARM64 CLI/daemon, and a restored isolated IAM testing fixture on the same existing EC2 host. All 30 deliveries succeeded after three excluded warmups, with three-second spacing, public TLS, existing sockets and loopback callbacks, matching the earlier methodology. Proof minting and callback acknowledgements remain outside the timed interval.

| Observation | Original p50 / p95 | 0.1.2 p50 / p95 |
| --- | --- | --- |
| Proof-ready send → callback | 245.457 / 318.426 ms | 251.517 / 329.971 ms |
| Send → acceptance | 240.468 / 313.436 ms | 246.306 / 324.787 ms |
| Callback timestamp minus acceptance | 4.813 / 7.777 ms | 5.294 / 6.948 ms |
| WebSocket ping/pong | 0.649 / 0.726 ms | 0.772 / 0.912 ms |

**This run does not show an improvement in first-callback latency.** Its largest delivery sample was 553.757 ms, with 545.611 ms already spent waiting for acceptance. These small sequential runs, taken at different times and fixture generations, cannot establish a statistically significant regression or a throughput ceiling. They do confirm that acceptance remains the dominant cost and that the shipped ACK/wake-up fixes should not be advertised as a reduction of the original 318 ms result. The next substantial first-callback gain still requires profiling successful IAM verification; no hardware increase or sub-100 ms target is justified by this evidence.

## Remaining native burst delay

A [local reproduction using the released native 0.1.2 source](daemon-burst-latency-analysis.json) found a separate daemon scheduling delay: a second ting queued while the first callback awaits its read ACK can consume the worker wake-up while that worker is still busy. When the ACK completes, the second callback waits for the one-second fallback timer. Two loopback runs measured **947 and 945 ms after ACK release**. The earlier three-second-spaced regional benchmark did not exercise this case.

An isolated candidate that observes worker completion and resumes eligible pending work reduced that specific wait to **1.7 and 1.3 ms**; its regression and all six existing daemon tests passed. It preserves backoff, avoids empty-queue loops, and matches task identity before removing a job. This is a next-native-release option, not a shipped change or an end-to-end latency claim. Published 0.1.2 assets remain unchanged. The linked evidence includes the exact fixture, candidate diff, logs and replay command; no additional hardware is needed for this scheduling improvement.
