// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Automated accessibility (axe) on the important pages. Runs WCAG 2.0/2.1 A + AA
// rules and gates on CRITICAL and SERIOUS violations (color-contrast is
// "serious"); moderate/minor are reported for follow-up, not gated yet.
import { test, expect } from "@playwright/test"
import AxeBuilder from "@axe-core/playwright"

async function audit(page: import("@playwright/test").Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze()

  const by = (impact: string) => results.violations.filter((v) => v.impact === impact)
  const summary = results.violations
    .map((v) => {
      // Log element targets for the non-contrast (structural) violations.
      const targets = v.id === "color-contrast" ? "" :
        "\n      " + v.nodes.slice(0, 6).map((n) => n.target.join(" ")).join("\n      ")
      return `  [${v.impact}] ${v.id} (${v.nodes.length}) - ${v.help}${targets}`
    })
    .join("\n")
  console.log(`axe: ${results.violations.length} violation type(s)\n${summary}`)

  // Gate: no CRITICAL or SERIOUS violations (color-contrast lives at "serious").
  // Moderate/minor are reported above for follow-up, not gated yet.
  expect(by("critical"), `critical a11y violations:\n${summary}`).toEqual([])
  expect(by("serious"), `serious a11y violations:\n${summary}`).toEqual([])
}

// Authenticated key pages (reused admin session).
const PAGES = [
  { name: "dashboard",    url: "/" },
  { name: "requests",     url: "/requests" },
  { name: "scanner",      url: "/scanner" },
  { name: "settings",     url: "/settings" },
  { name: "api keys",     url: "/settings/keys" },
  { name: "applications", url: "/applications" },
  { name: "departments",  url: "/departments" },
]

for (const p of PAGES) {
  test(`a11y: ${p.name}`, async ({ page }) => {
    await page.goto(p.url)
    // Let the authenticated shell + data settle before auditing.
    await expect(page.getByRole("link", { name: "Overview" })).toBeVisible()
    await audit(page)
  })
}

test.describe("login page a11y", () => {
  test.use({ storageState: { cookies: [], origins: [] } })
  test("a11y: login", async ({ page }) => {
    await page.goto("/login")
    await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeVisible()
    await audit(page)
  })
})
