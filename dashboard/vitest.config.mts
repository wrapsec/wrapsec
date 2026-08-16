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
  },
})
