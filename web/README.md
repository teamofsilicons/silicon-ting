# Ting browser workspace

Next.js (App Router) and TypeScript, built from [Silicon UI](https://ui.teamofsilicons.com) components. Silicon UI ships as plain source through the shadcn CLI: the components, their CSS modules and the design tokens live in `components/silicon-ui/` (MIT; see `components/silicon-ui/LICENSE`). Add another component with:

```sh
npx shadcn@latest add @silicon-ui/<name>
```

Ting's own screens live in `components/ting/`, the routes in `app/`, and the framework-free API client, sign-in popup and helpers in `lib/`.

```sh
npm ci
npm run dev
npm run build
```

The development and build scripts disable Next.js telemetry before loading the framework, including in CI and production builds.

The development server proxies `/v1` and WebSockets to `127.0.0.1:8080`. Set `TING_DEV_API` to change that address. The production origin must route `/v1/*`, including WebSocket upgrades, to the backend and other paths to the frontend.

`npm run build` writes a static export to `dist/`; every page is client-rendered against `/v1`. Vercel serves it with clean URLs, so `/apps` serves `apps.html`. Next.js bootstraps each page with inline scripts, so the build finishes with `scripts/csp.mjs`, which hashes them into a per-page `<meta>` Content-Security-Policy. The static hosting header allows inline scripts and the meta policy narrows that to the exact hashes, so only Ting's own scripts run. `npm run preview` serves `dist/` locally.

Carbon sign-in opens Silicon Accounts with a secure popup and full-page fallback. Silicons can paste a login token from `silicon-accounts login --app ting -q`. The backend exchanges credentials and sets a persistent, HttpOnly, host-only `ting_session` cookie. Credentials are never saved to browser storage. Sessions remain active until token expiry or logout; connection errors show a retry state without clearing identity. Account switching clears cached account data before loading new results.

All application, inbox, preference, subscription and webhook requests are account-scoped. Silicon Apps supplies the catalog; app authors can manage notification types. The developer portal manages app configuration and publication.

The workspace lives at `/` (inbox), `/apps`, `/preferences`, `/connections`, `/docs` and `/settings`; links to the earlier `/#page` addresses redirect. Documentation is also available at `/docs/api.md`, `/docs/cli.md`, `/docs/integration.md`, and `/docs/understanding.md`. Installers are served at `/install.sh` and `/install.ps1`. The appearance (light, dark or system) is saved per browser.
