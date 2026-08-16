// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Journey 3: API key lifecycle -- create (one-time secret reveal) then revoke.
// Self-cleaning: the key carries an e2e- prefix and is revoked by the same test;
// nothing else is touched.
import { test, expect } from "@playwright/test"
import { login, e2eName } from "./helpers/auth"

test("API key create then revoke", async ({ page }) => {
  await login(page)
  await page.goto("/settings/keys")

  const keyName = e2eName("key")

  // --- Create ---
  // The page action button opens the modal (only one "Create key" until it opens).
  await page.getByRole("button", { name: "Create key" }).first().click()
  await page.getByPlaceholder(/finance-bot/i).fill(keyName)
  // First combobox is the department selector; pick the first real department.
  await page.getByRole("combobox").first().selectOption({ index: 1 })
  // Now two "Create key" buttons exist; the modal submit is the later one.
  await page.getByRole("button", { name: "Create key" }).last().click()

  // One-time secret reveal, then dismiss.
  await expect(page.getByText(/will not be shown again/i)).toBeVisible()
  await page.getByRole("button", { name: "Done" }).click()

  // --- The new key is listed ---
  await page.getByPlaceholder("Search keys...").fill(keyName)
  await expect(page.getByText(keyName)).toBeVisible()

  // --- Revoke (self-cleanup) ---
  // Search filtered to just this key, so Revoke is unambiguous.
  await page.getByRole("button", { name: "Revoke" }).click()
  await page.getByRole("button", { name: "Confirm revocation" }).click()

  // Gone from the active list.
  await expect(page.getByText(keyName)).toHaveCount(0)
})
