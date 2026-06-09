// @ts-check

// The frontend always calls /api/* and Next.js rewrites those to the dashboard
// backend (cmd/dashboard-backend, default 127.0.0.1:8089). This keeps the
// backend address server-side (no NEXT_PUBLIC_ leak), avoids CORS, and lets the
// app be served from any host that can reach the backend.
//
// NOTE: Next.js 14.2.x does not support a TypeScript next.config (that landed in
// Next 15). Since this app is pinned to 14.2.x, the config is authored as ESM
// JavaScript with a JSDoc type annotation for editor/type safety.

/** @type {import('next').NextConfig} */
const config = {
  output: 'standalone',
  poweredByHeader: false,
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.DASHBOARD_BACKEND_URL ?? 'http://127.0.0.1:8089'}/api/:path*`,
      },
    ];
  },
};

export default config;
