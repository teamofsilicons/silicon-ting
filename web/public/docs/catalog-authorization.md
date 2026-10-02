# Honeycomb catalog access

> **Integration preview for Ting 0.2.0 / IAM 5.0.0.** Documentation is published before the coordinated runtime rollout. The new catalog authorization routes require the matching deployed Ting and Honeycomb services.

Ting asks separately before reading the applications owned by your organization
from Honeycomb. Signing into Ting does not approve this feature. The required
endpoint is `honeycomb.apps.list`; IAM shows its current endpoint details and any
dependencies before you decide.

In the Applications page, choose **Review access in IAM**, approve the request,
then paste the single-use code into Ting. Completing approval reloads the catalog;
it does not create or change an application. For this management view, select the
same account and organization in Honeycomb as your current Ting workspace.

The CLI exposes the same flow:

```sh
ting --org tos apps authorize start --key catalog-review-1
ting --org tos apps authorize status AUTHORIZATION_ID
ting --org tos apps authorize complete AUTHORIZATION_ID \
  --state STATE_FROM_START --code-file /private/path/approval-code
ting --org tos apps list
```

Keep the same organization and testing-environment selection throughout. Retrying
the same start operation uses the same `--key`. The completion checks the request
ID, state, signed-in account, organization and environment. Codes are read from a
file so they do not appear in process arguments. API equivalents are
`POST /v1/orgs/{org}/catalog-authorizations`,
`GET /v1/orgs/{org}/catalog-authorizations/{id}`, and
`POST /v1/orgs/{org}/catalog-authorizations/{id}/complete`.

Access and refresh credentials remain encrypted on the Ting server. Catalog
pagination reuses the approved access token; Honeycomb rechecks authority on
every page. Refresh retries retain their mutation identity and are serialized per
account, organization and testing generation. Ordinary logout preserves consent.
Revoke the grant in IAM to stop access; a denied or revoked grant requires a new
explicit approval. Test-world cleanup removes its saved requests and grants.

This release pins the official IAM 5.0.0 SDK at `f1e9c4768029aacabe337ca41be52e05023d1631`. Deploy the matching IAM and Honeycomb
reusable-token contracts, register the catalog endpoint and dependencies, preserve
Ting's encryption key, and verify real approval, pagination, refresh and revocation
before enabling it in production.

## Operator migration

Ting creates additive `catalog_authorizations` and `catalog_grants` SQLite tables at startup. Preserve the existing authentication encryption key and take consistent backups of each SQLite database before upgrading. A rollback can retain these unused tables; do not delete them or rotate the encryption key to recover an old binary. Never promote a consent grant across an account, organization or test generation.
