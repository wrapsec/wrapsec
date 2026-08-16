// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Journey 7: settings update -> effective configuration. Changes the block
// threshold, confirms it persists (the resolved/effective value on reload), then
// RESTORES the original so dev configuration is never left modified.
import { test, expect, type Page } from "@playwright/test"
// authenticated via storageState (playwright.config setup project)

async function openThresholds(page: Page) {
  await page.goto("/settings")
  await page.getByRole("button", { name: "Thresholds", exact: true }).click()
  // The block threshold is the first number input of the ThresholdForm.
  return page.getByRole("spinbutton").first()
}

async function saveThresholds(page: Page) {
  await page.getByRole("button", { name: "Save thresholds" }).click()
  await expect(page.getByText("Saved successfully")).toBeVisible()
}

test("update the block threshold and see it take effect (then restore)", async ({ page }) => {

  let original = ""
  try {
    const block = await openThresholds(page)
    original = await block.inputValue()
    // Pick a distinct, still-valid value (block must stay > sanitize=0.4).
    const next = original === "0.75" ? "0.65" : "0.75"

    await block.fill(next)
    await saveThresholds(page)

    // Effective config: the resolved value survives a reload (came from the DB).
    await page.reload()
    await expect(await openThresholds(page)).toHaveValue(next)
  } finally {
    // Restore the original block threshold no matter what.
    if (original) {
      const block = await openThresholds(page)
      await block.fill(original)
      await saveThresholds(page)
    }
  }
})
