// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Journeys 10-11: API failure -> controlled UI error, and session expiry -> login.
import { test, expect } from "@playwright/test"

test("a backend 500 shows a controlled error, not a crash", async ({ page }) => {
  // Force the key-list request to fail.
  await page.route("**/api/proxy/v1/keys*", (route) =>
    route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "SYSTEM_ERROR", message: "boom" } }),
    }))

  await page.goto("/settings/keys")
  // The page renders a controlled load-error surface (not a blank page / crash).
  await expect(page.getByText("Failed to load API keys")).toBeVisible()
})

test("a network failure is handled gracefully", async ({ page }) => {
  // Abort the request entirely (network down).
  await page.route("**/api/proxy/v1/keys*", (route) => route.abort())

  await page.goto("/settings/keys")
  await expect(page.getByText("Failed to load API keys")).toBeVisible()
})

test("session expiry redirects to login", async ({ page, context }) => {
  // Simulate an expired session: drop the access-token (wrapsec_jwt) and the
  // refresh_token, but keep the middleware session indicator so the page still
  // loads -- the first API call then 401s, the silent refresh fails, and the
  // client redirects to /login.
  const cookies = await context.cookies()
  const session = cookies.find((c) => c.name === "wrapsec_session")
  await context.clearCookies()
  if (session) await context.addCookies([session])

  await page.goto("/settings/keys")
  await expect(page).toHaveURL(/\/login/, { timeout: 15_000 })
})
