import type { NextConfig } from 'next';
import { PHASE_DEVELOPMENT_SERVER } from 'next/constants';

// Production is a static export served by Vercel; the origin routes /v1, including WebSockets, to the backend.
// The development server proxies /v1 to a local backend instead.
export default function config(phase: string): NextConfig {
  const turbopack = { root: process.cwd() };
  if (phase === PHASE_DEVELOPMENT_SERVER) {
    const api = process.env.TING_DEV_API || 'http://127.0.0.1:8080';
    return { turbopack, async rewrites() { return [{ source: '/v1/:path*', destination: `${api}/v1/:path*` }]; } };
  }
  return { turbopack, output: 'export', distDir: 'dist', poweredByHeader: false };
}
