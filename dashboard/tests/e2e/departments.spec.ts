// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Journey 4: department create -> update (threshold override) -> delete.
// Self-cleaning: the department carries an e2e- prefix and this test deactivates
// only the one it created; no other data is touched.
import { test, expect } from "@playwright/test"
import { login, e2eName } from "./helpers/auth"

test("department create, update override, then deactivate", async ({ page }) => {
  await login(page)
  await page.goto("/departments")

  const name = e2eName("dept")

  // --- Create ---
  await page.getByRole("button", { name: "Add department" }).click()
  await page.getByPlaceholder("Finance Department").fill(name)   // slug auto-derives
  // Leave contact_email BLANK on purpose: it is UI-optional and the form must omit
  // it (not send ""), so an empty optional email still creates successfully.
  await page.getByRole("button", { name: "Create", exact: true }).click()

  // Appears in the list (scope via search).
  await page.getByPlaceholder("Search departments...").fill(name)
  await expect(page.getByText(name).first()).toBeVisible()

  // --- Update: set a threshold override on the detail page ---
  await page.getByRole("link", { name: "Manage" }).click()
  await expect(page).toHaveURL(/\/departments\/[0-9a-f-]+$/)
  await page.getByRole("button", { name: "Edit" }).first().click()   // thresholds section
  await page.getByRole("spinbutton").first().fill("0.85")            // block threshold
  await page.getByRole("button", { name: "Save overrides" }).click()

  // Persisted: reload and confirm the override value shows in the read-only view.
  await page.reload()
  await expect(page.getByText("0.85")).toBeVisible()

  // --- Delete (self-cleanup) ---
  await page.goto("/departments")
  await page.getByPlaceholder("Search departments...").fill(name)
  await expect(page.getByText(name).first()).toBeVisible()
  await page.getByRole("button", { name: "Deactivate", exact: true }).click()
  await page.getByRole("button", { name: "Confirm deactivation" }).click()

  await expect(page.getByText(name)).toHaveCount(0)
})
