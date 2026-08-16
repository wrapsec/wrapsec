// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Journey 5: application create -> update (threshold override) -> delete.
// Self-cleaning: e2e- prefixed; deactivates only the app it created.
import { test, expect } from "@playwright/test"
import { login, e2eName } from "./helpers/auth"

test("application create, update override, then deactivate", async ({ page }) => {
  await login(page)
  await page.goto("/applications")

  const name = e2eName("app")

  // --- Create (name + slug auto + department required) ---
  await page.getByRole("button", { name: "Add application" }).click()
  await page.getByPlaceholder("Finance Bot").fill(name)
  await page.getByRole("combobox").first().selectOption({ index: 1 })   // department
  // Leave owner_email BLANK: optional -> the form must omit it, not send "".
  await page.getByRole("button", { name: "Create", exact: true }).click()

  // Appears in the list.
  await page.getByPlaceholder("Search applications...").fill(name)
  await expect(page.getByText(name).first()).toBeVisible()

  // --- Update: threshold override on the detail page ---
  await page.getByRole("link", { name: "Manage" }).click()
  await expect(page).toHaveURL(/\/applications\/[0-9a-f-]+$/)
  await page.getByRole("button", { name: "Edit" }).first().click()
  await page.getByRole("spinbutton").first().fill("0.85")
  await page.getByRole("button", { name: "Save overrides" }).click()

  await page.reload()
  await expect(page.getByText("0.85")).toBeVisible()

  // --- Delete (self-cleanup) ---
  await page.goto("/applications")
  await page.getByPlaceholder("Search applications...").fill(name)
  await expect(page.getByText(name).first()).toBeVisible()
  await page.getByRole("button", { name: "Deactivate", exact: true }).click()
  await page.getByRole("button", { name: "Confirm deactivation" }).click()

  await expect(page.getByText(name)).toHaveCount(0)
})
