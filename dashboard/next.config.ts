// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import type { NextConfig } from "next";

// H11: defense-in-depth security headers.
// Client-side requests only ever hit the dashboard's own /api/* BFF routes -
// the browser never talks to the WrapSec API directly - so 'self' is enough
// for connect-src. The BFF handlers forward to NEXT_PUBLIC_API_URL server-side.
const CONNECT_SRC = ["'self'"].join(" ");

// Next.js hydration and the App Router runtime both require inline scripts
// and inline styles. Wiring per-request nonces requires threading them
// through every layout and Server Component and is out of scope for a
// security hotfix. 'unsafe-inline' is documented here as an accepted
// tradeoff pending a proper nonce rollout.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  `connect-src ${CONNECT_SRC}`,
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");

const SECURITY_HEADERS = [
  { key: "Content-Security-Policy",   value: CSP },
  { key: "X-Frame-Options",           value: "DENY" },
  { key: "X-Content-Type-Options",    value: "nosniff" },
  { key: "Referrer-Policy",           value: "no-referrer" },
  { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
  { key: "Permissions-Policy",        value: "camera=(), microphone=(), geolocation=(), payment=()" },
];

const nextConfig: NextConfig = {
  output: "standalone",
  devIndicators: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: SECURITY_HEADERS,
      },
    ];
  },
};

export default nextConfig;
