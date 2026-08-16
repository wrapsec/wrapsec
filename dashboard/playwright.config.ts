// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { defineConfig, devices } from "@playwright/test"

// E2E runs against a REAL, already-running stack (browser -> Next dashboard ->
// /api/proxy BFF -> FastAPI -> Postgres/Redis). The base URL is env-driven and
// NEVER hardcoded, so CI can point the same specs at an isolated ephemeral stack
// (e.g. http://localhost:3001) by changing PLAYWRIGHT_BASE_URL only.
const BASE_URL = process.env.PLAYWRIGHT_BASE_URL || "http://localhost:3000"

export default defineConfig({
  testDir:  "./tests/e2e",
  testMatch: "**/*.spec.ts",
  // A real stack has real latency; keep generous but bounded timeouts.
  timeout:  30_000,
  expect:   { timeout: 10_000 },
  fullyParallel: false,        // shared stack + shared e2e-admin session -> serialize
  workers:  1,
  forbidOnly: !!process.env.CI,
  retries:  process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: BASE_URL,
    trace:   "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    // Logs in once and writes playwright/.auth/admin.json.
    { name: "setup", testMatch: /.*\.setup\.ts/ },
    // Journey specs start already authenticated (reused session); auth/logout and
    // the VIEWER spec opt out per-file with an empty storageState.
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], storageState: "playwright/.auth/admin.json" },
      dependencies: ["setup"],
    },
  ],
})
