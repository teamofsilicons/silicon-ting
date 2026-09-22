# Hook integration in Ting 0.1.4

Ting 0.1.4 fixes recovery of completed login operations beyond the SLT lifetime and derives refreshed access-token expiry from the original attempt time. Logout records revocation before contacting IAM, so an inactive access token or uncertain IAM reply cannot conceal unfinished cleanup.

The test-only `receivers.bootstrap` OBO endpoint creates a 30-second capability for exactly the represented actor, issuing app, canonical organization and testing generation. It exposes that app's inbox and change hints, with explicit renewal and revocation; it cannot acknowledge records, enroll recipients or create a general Ting session. Recovery needs fresh proof and exact request bytes. Historical results never extend or resurrect authority.

Required automation delivery is an explicit recipient opt-in on an existing subscription. A sender may then use `delivery: "required"`. Existing notification preferences still determine `silent`; opt-out or grant revocation prevents further automatic delivery. Existing retention and destination ACK rules apply.

See [the API contract](../udd/api.md) for exact routes and request bodies and [the CLI contract](../udd/cli.md) for recovery and consent commands. Hook must adopt these new contracts in its adapter before its complete test-receiving flow is available.

## Rollout gates

The production endpoint definition and Hook external scope require Honeycomb approval. [Ting configuration evidence](ting-config-rollout-014.json) and [Hook scope/lifecycle evidence](hook-scopes-rollout-014.json) record their current state. Publishing binaries does not bypass those approvals.

Hook's existing deployed lifecycle route has been connected to Honeycomb through a dedicated service token, preserving its API binary, worker and data. [Ting runtime evidence](ting-runtime-rollout-014.json) records the added exact Hook browser origin. Test credentials and lifecycle tokens are excluded from these reports.

Local regression tests cover authorization, recovery, expiry, receiver isolation and lifecycle fences. Live verification is recorded separately in [verification](verification.md); local fixtures are not evidence of production scope approval or complete Hook adapter delivery.
