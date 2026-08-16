// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Journey 2: logout -> protected route redirects to login. The middleware guard
// is UX only; real access control stays on the backend/BFF.
import { test, expect } from "@playwright/test"
import { login, logout } from "./helpers/auth"

// These specs exercise login/logout + the unauthenticated guard -> start fresh.
test.use({ storageState: { cookies: [], origins: [] } })

test("logout returns to the login page", async ({ page }) => {
  await login(page)
  await logout(page)
  await expect(page).toHaveURL(/\/login/)
})

test("an unauthenticated protected route redirects to login", async ({ page }) => {
  // Fresh context (no session cookie) -> middleware bounces to /login.
  await page.goto("/settings/keys")
  await expect(page).toHaveURL(/\/login/)
})

test("after logout, a protected route redirects to login", async ({ page }) => {
  await login(page)
  await logout(page)
  await page.goto("/settings/keys")
  await expect(page).toHaveURL(/\/login/)
})
