// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Keyboard navigation + focus for critical workflows (the manual-check items,
// automated where practical): keyboard-only login, and Escape dismissing a modal.
import { test, expect } from "@playwright/test"
import { E2E_EMAIL, E2E_PASSWORD } from "./helpers/auth"

test.describe("keyboard: login", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("can sign in using only the keyboard", async ({ page }) => {
    await page.goto("/login")

    // The email input auto-focuses; type it, Tab to password, submit with Enter.
    const email = page.locator('input[type="email"]')
    await email.focus()
    await page.keyboard.type(E2E_EMAIL)
    await page.keyboard.press("Tab")
    // Focus moved to the password field.
    await expect(page.locator('input[type="password"]')).toBeFocused()
    await page.keyboard.type(E2E_PASSWORD)
    await page.keyboard.press("Enter")

    await expect(page.getByRole("link", { name: "Overview" })).toBeVisible()
  })
})

test("Escape closes the create-key modal (focus/keyboard dismissal)", async ({ page }) => {
  // Reused admin session.
  await page.goto("/settings/keys")
  await page.getByRole("button", { name: "Create key" }).first().click()
  await expect(page.getByText("Create API Key")).toBeVisible()

  await page.keyboard.press("Escape")
  await expect(page.getByText("Create API Key")).toHaveCount(0)
})
