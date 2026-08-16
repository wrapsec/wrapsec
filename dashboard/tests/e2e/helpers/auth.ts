// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { expect, type Page } from "@playwright/test"

// Credentials for the dedicated E2E admin (seeded via scripts/seed_e2e_user.py).
// Overridable by env so CI can inject its own without touching the specs.
export const E2E_EMAIL    = process.env.E2E_ADMIN_EMAIL    || "e2e-admin@wrapsec-e2e.com"
export const E2E_PASSWORD = process.env.E2E_ADMIN_PASSWORD || "E2eAdmin!Pass123"

/** Log in through the real credentials flow and land on the dashboard. */
export async function login(page: Page): Promise<void> {
  await page.goto("/login")
  await page.locator('input[type="email"]').fill(E2E_EMAIL)
  await page.locator('input[type="password"]').fill(E2E_PASSWORD)
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
  // The authenticated shell renders the Overview nav item.
  await expect(page.getByRole("link", { name: "Overview" })).toBeVisible()
}

/** Log out via the user menu and confirm the redirect to /login. */
export async function logout(page: Page): Promise<void> {
  // The user-menu trigger's accessible name includes the logged-in email.
  await page.getByRole("button", { name: E2E_EMAIL }).click()
  await page.getByRole("button", { name: "Sign out" }).click()
  await expect(page).toHaveURL(/\/login/)
}

/** Unique e2e- prefixed name so created resources are identifiable + self-cleaned. */
export function e2eName(kind: string): string {
  return `e2e-${kind}-${Date.now()}-${Math.floor(Math.random() * 1000)}`
}
