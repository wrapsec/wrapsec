// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * Shared SWR cache keys.
 *
 * Scope (intentionally minimal): only the entity-list keys that are fetched
 * from more than one page under the same cache entry. Using one constant means
 * a typo cannot silently fragment the shared cache -- e.g. `"departments"` is
 * loaded by five pages and they must all hit the same SWR entry.
 *
 * NOT centralized here: single-use, page-local keys (settings tabs, overview-*,
 * analytics-* tuples). Those are scoped to one component and mutated via the
 * bound `mutate` from their own `useSWR`, so there is no cross-file drift risk
 * to guard against. Deliberately page-scoped keys (`overview-depts`,
 * `departments-list`) are separate caches by design and must stay separate.
 */

export const swrKeys = {
  departments:  "departments",
  applications: "applications",
} as const
