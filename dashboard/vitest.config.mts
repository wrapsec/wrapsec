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
      // coverage fail_under). Baseline at introduction: 13.56/12.84/10.94/14.08.
      thresholds: {
        statements: 13,
        branches:   12,
        functions:  10,
        lines:      13,
      },
    },
  },
})
