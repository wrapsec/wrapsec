// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Journey 1 (smoke): login -> dashboard. Validates the whole real chain --
// browser -> Next dashboard -> /api/proxy BFF -> FastAPI -> Postgres/Redis.
import { test, expect } from "@playwright/test"
import { login } from "./helpers/auth"

// These specs test the login flow itself -> start UNAUTHENTICATED (no reused session).
test.use({ storageState: { cookies: [], origins: [] } })

test("login lands on the dashboard", async ({ page }) => {
  await login(page)

  // We are on the dashboard (root), not the login page.
  await expect(page).toHaveURL(/\/$/)
  await expect(page.getByRole("link", { name: "Overview" })).toBeVisible()
  // The session cookie is httpOnly -> never exposed to client JS.
  const jwtVisibleToJs = await page.evaluate(() => document.cookie.includes("wrapsec_jwt"))
  expect(jwtVisibleToJs).toBe(false)
})

test("bad credentials are rejected and stay on login", async ({ page }) => {
  await page.goto("/login")
  await page.locator('input[type="email"]').fill("e2e-admin@wrapsec-e2e.com")
  await page.locator('input[type="password"]').fill("wrong-password")
  await page.getByRole("button", { name: "Sign in", exact: true }).click()

  await expect(page.getByText(/invalid email or password/i)).toBeVisible()
  await expect(page).toHaveURL(/\/login/)
})
