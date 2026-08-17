// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Dedicated E2E configuration for CI. Extends the local config (same testDir,
// projects, storageState, serialized single-worker run against the real stack)
// and layers CI-only concerns: an extra retry for stack-warmup flake, a JUnit
// report for CI annotations, and failure artifacts (trace + screenshot + video)
// written to well-known folders the workflow uploads. The workflow runs it with
// `npx playwright test --config playwright.ci.config.ts`.
import { defineConfig } from "@playwright/test"
import base from "./playwright.config"

export default defineConfig({
  ...base,
  forbidOnly: true,
  retries:    2,
  outputDir:  "test-results",
  reporter: [
    ["list"],
    ["html",  { open: "never", outputFolder: "playwright-report" }],
    ["junit", { outputFile: "test-results/junit.xml" }],
  ],
  use: {
    ...base.use,
    trace:      "retain-on-failure",
    screenshot: "only-on-failure",
    video:      "retain-on-failure",
  },
})
