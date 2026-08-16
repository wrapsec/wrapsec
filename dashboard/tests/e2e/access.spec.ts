// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Journeys 8-9: unauthorized -> denied, and cross-tenant/unknown-id -> 404. The
// backend stays authoritative; the frontend is never the security boundary.
import { test, expect } from "@playwright/test"
import { loginAs, e2eName, E2E_VIEWER_EMAIL } from "./helpers/auth"

// v1 is single-tenant per deployment (no org switcher), so "cross-tenant access"
// is exercised as URL-id manipulation: an id the caller cannot see returns 404
// (masking), never another tenant's data. Runs as the reused admin session.
test("an unknown/other resource id returns not-found (404 masking)", async ({ page }) => {
  const fakeId = "00000000-0000-0000-0000-000000000000"

  await page.goto(`/departments/${fakeId}`)
  await expect(page.getByText("Department not found.")).toBeVisible()

  await page.goto(`/applications/${fakeId}`)
  await expect(page.getByText("Application not found.")).toBeVisible()
})

test.describe("VIEWER role", () => {
  // A different identity than the reused admin session -> start unauthenticated.
  test.use({ storageState: { cookies: [], origins: [] } })

  test("a VIEWER cannot create an API key (backend denies the write)", async ({ page }) => {
    await loginAs(page, E2E_VIEWER_EMAIL)
    await page.goto("/settings/keys")

    // The UI lets a JWT user open the create modal, but the backend requires ADMIN.
    await page.getByRole("button", { name: "Create key" }).first().click()
    await page.getByPlaceholder(/finance-bot/i).fill(e2eName("key"))
    await page.getByRole("combobox").first().selectOption({ index: 1 })
    await page.getByRole("button", { name: "Create key" }).last().click()

    // Denied: no one-time secret is ever revealed, the modal stays on the form.
    await expect(page.getByText(/will not be shown again/i)).toHaveCount(0)
    await expect(page.getByRole("button", { name: "Create key" }).last()).toBeVisible()
  })
})
