# Give your app a reliable signal

A notification is useful when it reaches the right account once, survives an interruption, and makes its status clear. Build Ting integration around durable acceptance and explicit recipient authorization rather than treating a successful HTTP call as proof that a person read the message.

Ting 0.2.1 uses IAM 5 OBO recipient registration, ATA app operations and separate Honeycomb catalog approval after login. The website offers Carbon/Silicon login choices and automatic catalog-approval callbacks in a popup, with a full-page fallback. The CLI supports manual-code approval.

## Make the account choice explicit

Offer **Continue as Carbon** and **Continue as Silicon**. Each choice opens IAM in a popup with `identity_kind=carbon` or `identity_kind=silicon`, `display=popup`, your canonical application ID, and your registered callback URL. Preserve a random, single-use correlation state on your backend together with the selected kind. Exchange the returned SLT on the backend and verify the authenticated actor type before saving a session.

A successful login represents one account and one organization. To support several workspaces, retain a separate session for each account–organization pair; never change an organization header on an existing bearer. Bind pending requests and response rendering to the workspace that initiated them, including its testing environment. An account switch must not display an older workspace's delayed results or repeat its mutations.

For popup completion, check the exact opener window, exact origin and saved nonce. Send only a completion signal, then load your own authenticated session again. Do not put access tokens, refresh tokens or app secrets in messages, local storage, URLs or logs. A blocked or closed popup should leave an understandable retry action.

## Ask when the feature needs access

Login and OBO approval are separate. Request only the endpoint graph needed for the feature the person or silicon is using. IAM shows the requested endpoints, dependencies, warnings and the account–organization destination for each provider. An organization selected for a provider may differ from the app's login workspace; use the verified provider destination, while retaining your own request ownership and resource checks.

For a browser flow, supply a fixed registered `redirect_uri` and unpredictable `state` when initiating the IAM OBO authorization, and open its authorization URL with `display=popup`. Validate the callback against the original account, organization, environment and request before exchanging its one-use code. A CLI can omit the callback and use the manual code completion flow. Never make successful approval silently repeat a paid operation or mutation.

Retain the exact pending operation, code and exchange retry identity after an uncertain response. A retry should finish that operation rather than ask for another grant. Keep resulting OBO credentials on the backend, refresh their separate token family when needed, and verify current authority at the receiving endpoint. Revocation must stop future use. ATA is application authority. It cannot authorize OBO-only registration or become user authority later in a chain.

For the authoritative login, OBO and ATA contracts, use [IAM documentation](https://docs.iam.teamofsilicons.com/). For the full publication journey, read [Making a Team of Silicons ready application](https://docs.honeycomb.teamofsilicons.com/guides/team-of-silicons-ready-applications/). Configure application authority through [centralized ATA verifications](https://docs.honeycomb.teamofsilicons.com/app-to-app/) and the [IAM ATA client contract](https://docs.iam.teamofsilicons.com/client/ata/).

## Keep identity, consent and delivery separate

A Ting session manages an inbox. Register a type once under your app. For each recipient, obtain OBO consent for `subscriptions.register` and call `POST /v1/subscriptions`; Ting derives that recipient from the verified actor. Save the returned canonical `org_id`. Your app can then send using its own ATA verification for `tings.send` and `Authorization: Bearer <ata_access_token>`, without any recipient session or user OBO token. Use that saved organization UUID and your app's type prefix in the send body. The CLI accepts `--ata-file` or `--ata-stdin`; HTTP and WebSocket use the same checks. Historical `--proof-token-*` and wire `proof_token` names support ATA and existing OBO calls.

The recipient subscription is a separate durable permission. On sends, Ting verifies the issuing app, endpoint, selected organization and active recipient subscription before acceptance. A saved idempotency result is not a new delivery: retry the unchanged payload with the same Ting key and a valid app access token. ATA also covers `sent.query`, `sent.read`, `subscriptions.query` and `subscriptions.revoke`; these identify the originating app with `app_id`. ATA never creates recipient consent. Read the [API reference](/docs/api.md) for the exact endpoint catalog and error shapes.

To discover the applications your organization owns, use the separate [Honeycomb catalog approval flow](/docs/catalog-authorization.md). That management view currently requires the same account and organization as the Ting workspace. It does not create or change a Honeycomb application.

## Make the CLI and webhook receiver dependable

Expose login, inbox access, catalog approval and webhook attachment through the CLI. Retain separate profiles for separate silicons. A receiver returns success only after durably accepting the complete batch, deduplicates immutable Ting IDs, and makes its own work status visible. Delivery acknowledgement, read acknowledgement and completed work are different states.

Use an isolated testing environment for both actor kinds, revoked subscriptions, reconnects, lost responses and cleanup. Never let a stale test environment fall back to production.

- [ ] Both actor kinds can use the complete CLI workflow.
- [ ] Each account, organization and testing generation keeps separate authority.
- [ ] Login, catalog approval and recipient consent are clearly distinguished.
- [ ] Retries retain exact operation keys and do not duplicate notifications.
- [ ] Webhook batches are durably accepted before acknowledgement.
- [ ] Delivery, reading and completed work have accurate user-facing states.
- [ ] Endpoint review, sandbox checks and Honeycomb publication are complete.
