// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { expect, type Page } from "@playwright/test"

// Credentials for the dedicated E2E admin (seeded via scripts/seed_e2e_user.py).
// Overridable by env so CI can inject its own without touching the specs.
export const E2E_EMAIL        = process.env.E2E_ADMIN_EMAIL    || "e2e-admin@wrapsec-e2e.com"
export const E2E_PASSWORD     = process.env.E2E_ADMIN_PASSWORD || "E2eAdmin!Pass123"
export const E2E_VIEWER_EMAIL = process.env.E2E_VIEWER_EMAIL   || "e2e-viewer@wrapsec-e2e.com"

/** Log in as a specific user through the real credentials flow -> dashboard. */
export async function loginAs(page: Page, email: string, password = E2E_PASSWORD): Promise<void> {
  await page.goto("/login")
  await page.locator('input[type="email"]').fill(email)
  await page.locator('input[type="password"]').fill(password)
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
  await expect(page.getByRole("link", { name: "Overview" })).toBeVisible()
}

/** Log in as the E2E admin (the default identity for most journeys). */
export async function login(page: Page): Promise<void> {
  await loginAs(page, E2E_EMAIL, E2E_PASSWORD)
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
