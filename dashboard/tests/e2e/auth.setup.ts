// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Authenticates ONCE and saves the session so journey specs reuse it instead of
// logging in per test -- faster, and avoids the backend login rate limit (10/min
// per IP) that a fresh login in every test would trip.
import { test as setup } from "@playwright/test"
import { login } from "./helpers/auth"

const adminFile = "playwright/.auth/admin.json"

setup("authenticate as admin", async ({ page }) => {
  await login(page)
  await page.context().storageState({ path: adminFile })
})
