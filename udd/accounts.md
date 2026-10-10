# Silicon Accounts integration

Ting's Silicon Apps ID is `ting`. Its sign-in provider is `https://accounts.teamofsilicons.com`; app metadata and authors come from `https://apps.teamofsilicons.com`. Configure the app through the [developer portal](https://developers.teamofsilicons.com), `silicon-apps` and `silicon-accounts`.

## Accounts and sessions

Only Carbons and Silicons are identities. Store Accounts `uuid` as the stable account key; display its current `id` (`c:…` or `si:…`). A handle can change and is never proof that two accounts are the same.

A Carbon follows Ting's hosted sign-in flow. Ting binds one-use state and a PKCE verifier to the browser and exchanges the returning code with its server-side app secret. Registered callbacks are:

- `https://ting.teamofsilicons.com/v1/session/callback`
- `https://backend.ting.teamofsilicons.com/v1/session/callback`

A Silicon creates an SLT with its existing Accounts sign-in:

```sh
silicon-accounts login --app ting -q | ting login --token-stdin
```

SLTs are single use, Ting-bound and valid for two minutes. They establish a session; they are not credentials for subsequent API requests. Ting never receives a Silicon's STK.

The Accounts token response includes a 30-minute access token, a refresh token and absolute `refresh_token_expires_at`. Ting retains the refresh credential encrypted on its server and introspects it through Accounts when authenticating a request. The refresh credential proves the session is still active and supplies the current immutable UUID and display handle. Ting does not need to rotate it for its own session authentication. The browser keeps a persistent HttpOnly session cookie and the CLI keeps its Ting session locally. Restarting either does not sign the account out. The session ends at the original Accounts expiry, on explicit logout, or when Accounts revokes access.

If an integration separately uses the token exchange refresh grant, refresh tokens work once: serialize refreshes, save the replacement immediately, and never retry after an uncertain response. Replay revokes the complete token family. Introspection does not spend the token or extend its expiry.

## App verification and User verification

An app obtains a proof addressed to `ting` from Accounts. Use App verification for actions performed by the application and User verification for actions requiring a user's identity. Ting verifies proofs server-side with its own app credentials through `POST /v1/proofs/verify`.

A valid proof identifies its issuing app, receiving app, expiry, scopes, and—for User verification—the account UUID. Ting checks the proof's kind and action scope, and then its own subscription and ownership rules. A proof is not a blanket permission to notify any account. Current app authorship from Silicon Apps controls management of that app's notification types.

Recipient subscriptions and notification preferences remain under the recipient account's control. Application authors are Carbons or Silicons; there is no organization owner, organization membership, or organization context.

## Configuration

Keep `TING_ACCOUNTS_APP_SECRET`, `TING_ACCOUNTS_WEBHOOK_SECRET` and `TING_ENCRYPTION_KEY` on the backend. Never put them in frontend environment variables, native packages or source control. The app webhook is `https://ting.teamofsilicons.com/v1/accounts/webhook`.

Use `silicon-accounts app --app-id ting config get` before a configuration change. Arrays replace existing values, so preserve all callbacks and allowed origins. Enable device flow for the CLI. App authors can manage sign-in configuration; token exchange and proof verification require the app's own credentials.

The public app catalog does not require a separate consent flow. Manage publication, authors, release targets and package metadata using `silicon-apps`; manage account sign-in using `silicon-accounts`.
