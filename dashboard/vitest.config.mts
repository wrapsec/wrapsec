// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { defineConfig } from "vitest/config"
import react from "@vitejs/plugin-react"

// Unit + component tests. jsdom for component rendering; resolve.tsconfigPaths
// resolves the "@/..." alias the app uses (native Vite, no plugin needed). E2E
// (Playwright) is a separate, later phase.
export default defineConfig({
  plugins: [react()],
  resolve: { tsconfigPaths: true },
  test: {
    environment: "jsdom",
    globals:     true,
    setupFiles:  ["./vitest.setup.ts"],
    // Tests live under tests/{unit,integration,e2e}; source dirs stay test-free.
    include:     ["tests/**/*.{test,spec}.{ts,tsx}"],
    exclude:     ["node_modules/**", ".next/**", "tests/e2e/**"],
    // The default 5s is too tight for the tests that drive a form through
    // simulated typing: the slowest sits near 2.2s unloaded, and running the
    // suite in parallel on a busy machine pushed one past the limit. That is a
    // timing failure reported as a test failure, which is worse than useless.
    // A hung test still fails, just later.
    testTimeout: 15000,
    coverage: {
      provider:  "v8",
      reporter:  ["text", "html"],
      // Measure the first-party source we test. Excludes: tests themselves, the
      // Next routing/layout shells and config, generated/vendor, and pure type
      // decls (no runtime to cover).
      include:   ["app/**", "components/**", "lib/**", "hooks/**", "contexts/**", "middleware.ts"],
      exclude:   [
        "tests/**",
        "**/*.d.ts",
        "lib/types.ts",
        "app/layout.tsx",
        "**/loading.tsx", "**/error.tsx", "**/not-found.tsx",
        "next.config.ts", "eslint.config.mjs", "vitest.config.mts", "vitest.setup.ts",
      ],
      // RATCHETING floor: set just under the current baseline so coverage cannot
      // regress, and RAISE these as more of the page/component layer is tested.
      // Never lower them to make a drop pass (same discipline as the backend's
      // coverage fail_under). It is a regression guard, not a release gate.
      // Raised from 13/12/10/13, then 20/18/18/21, against a measured
      // 25.02/22.23/22.56/25.91.
      //
      // Each floor keeps roughly a point of slack rather than sitting flush
      // against the measurement. Statements is the reason: 0.02 of a percent is
      // less than ONE of the 3592 statements, so a flush floor would fail on any
      // change that adds an uncovered line, and a floor that fails on ordinary
      // work gets lowered -- which is the one thing this must not invite.
      //
      // The data, analytics and settings pages remain the largely uncovered
      // part, deliberately behind the security-critical and primary-journey work.
      thresholds: {
        statements: 24,
        branches:   22,
        functions:  22,
        lines:      25,
      },
    },
  },
})
