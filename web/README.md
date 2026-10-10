# Ting browser workspace

SolidJS and TypeScript with the [Silicon UI](https://ui.teamofsilicons.com) foundation and native controls adapted from its button and input styles. The copied MIT-licensed foundation and attribution live in `src/silicon-ui/`.

```sh
npm ci
npm run dev
npm run build
```

The development server proxies `/v1` and WebSockets to `127.0.0.1:8080`. Set `TING_DEV_API` to change that address. The production origin must route `/v1/*`, including WebSocket upgrades, to the backend and other paths to the frontend.

Carbon sign-in opens Silicon Accounts with a secure popup and full-page fallback. Silicons can paste a login token from `silicon-accounts login --app ting -q`. The backend exchanges credentials and sets a persistent, HttpOnly, host-only `ting_session` cookie. Credentials are never saved to browser storage. Sessions remain active until token expiry or logout; connection errors show a retry state without clearing identity. Account switching clears cached account data before loading new results.

All application, inbox, preference, subscription and webhook requests are account-scoped. Silicon Apps supplies the catalog; app authors can manage notification types. The developer portal manages app configuration and publication.

Documentation is available at `/docs` and `/docs/api.md`, `/docs/cli.md`, `/docs/integration.md`, and `/docs/understanding.md`. Installers are served at `/install.sh` and `/install.ps1`.

Browser diagnostics use the same-origin `/v1/telemetry` endpoint when `VITE_SS_ANALYTICS_TABLE` and `VITE_SS_EVENTS_TABLE` are configured. Ingestion credentials remain on the backend. The browser preference is stored locally as `ting.telemetry.enabled`. Payload bodies and credentials are excluded from telemetry.
