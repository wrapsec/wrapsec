// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import type { NextConfig } from "next";
import createNextIntlPlugin from "next-intl/plugin";

// next-intl (cookie mode): resolution stays in WrapSec; this plugin only wires
// the message pipeline. Config lives in ./i18n/request.ts.
const withNextIntl = createNextIntlPlugin("./i18n/request.ts");

// M4: fail the production build if NEXT_PUBLIC_API_URL is unset. Every BFF
// route falls back to http://localhost:8000, which is only safe in dev.
// In prod that fallback either points at nothing (5xx storm) or - worse -
// at a locally-running attacker service if the container image is reused
// in an unexpected environment.
//
// L2: block secret-looking NEXT_PUBLIC_* names. Anything the Next runtime
// treats as NEXT_PUBLIC_* gets inlined into the client JS bundle at build
// time. A dev accidentally naming an API secret NEXT_PUBLIC_FOO_KEY would
// ship it to every browser session.
const IS_PROD_BUILD = process.env.NODE_ENV === "production";

if (IS_PROD_BUILD && !process.env.NEXT_PUBLIC_API_URL) {
  throw new Error(
    "NEXT_PUBLIC_API_URL must be set for production builds. " +
    "Do not rely on the http://localhost:8000 fallback.",
  );
}

const SECRET_HINTS = ["secret", "password", "token", "apikey", "api_key", "privkey", "private_key"];
const publicSecretLeaks = Object.keys(process.env).filter(name => {
  if (!name.startsWith("NEXT_PUBLIC_")) return false;
  const lower = name.toLowerCase();
  return SECRET_HINTS.some(h => lower.includes(h));
});
if (publicSecretLeaks.length > 0) {
  throw new Error(
    "Refusing to build: NEXT_PUBLIC_* variables with secret-like names " +
    "will be inlined into the client bundle. Rename or move server-side:\n" +
    publicSecretLeaks.map(n => `  - ${n}`).join("\n"),
  );
}

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

export default withNextIntl(nextConfig);
