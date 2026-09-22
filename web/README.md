# Ting browser workspace

SolidJS + TypeScript. Uses the same-origin API and its HttpOnly `ting_session` cookie; no client credentials, fake data, or development authentication bypass.

```sh
npm ci
npm run dev # proxies /v1 and its WebSocket to 127.0.0.1:8080
npm run build
npm test
npm run test:browser # while the dev server is running; requires Chrome
```

Set `TING_DEV_API` before starting Vite to change the development API. The browser smoke check intercepts the API in its isolated Chrome context only; fixtures are never bundled into the app.

Production frontend assets are hosted on Vercel. The canonical public origin routes `/v1/*` (including WebSocket upgrades) to the backend, and all other paths to this Vercel deployment. Direct Vercel preview URLs are frontend previews; authentication requires the canonical same-origin routing. Do not split browser API and WebSocket traffic onto different hosts: the session cookie is intentionally host-only.

Docs are available at `/docs`; raw API/CLI contracts at `/docs/api.md` and `/docs/cli.md`. The deployment provides `/install.sh`. Browser telemetry preference is stored locally as `ting.telemetry.enabled` (default enabled); Set `VITE_SS_ANALYTICS_TABLE` and `VITE_SS_EVENTS_TABLE` to the actual provisioned Space Station tables to enable the official browser SDK. The backend provides `/v1/telemetry`, validates allowed table IDs, adds server-held ingest keys, and forwards the SDK `{ table, events }` envelope. No keys are included in browser assets. Telemetry uses the original fetch transport, waits one minute after an ingestion failure, and excludes extension runtime errors and rejection events without source attribution. Application runtime errors from this origin remain observable.
