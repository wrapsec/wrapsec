import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // No-new-hardcoded-strings guard, SCOPED to the localized (migrated) pilot
  // pages only (the list pages). As each further page migrates to the catalog,
  // add it here. Bare JSX text must go through next-intl t(); only punctuation/
  // markers are allowed. (The [id] detail pages are not migrated yet.)
  {
    files: [
      "app/departments/page.tsx",
      "app/applications/page.tsx",
      "components/layout/**/*.tsx",
      "components/ui/**/*.tsx",
      "app/page.tsx",
      "components/overview/**/*.tsx",
      "app/requests/page.tsx",
      "components/requests/RequestFilters.tsx",
      "components/requests/RequestsTable.tsx",
      "components/requests/SecurityOverview.tsx",
      "components/requests/Pagination.tsx",
      "components/requests/RequestDetail.tsx",
      "app/analytics/page.tsx",
      "app/scanner/page.tsx",
      "components/scanner/**/*.tsx",
      "app/sources/page.tsx",
      "app/profile/page.tsx",
      "app/system/page.tsx",
      "app/users/page.tsx",
      "app/settings/keys/page.tsx",
      "components/settings/ApiKeyTable.tsx",
      "components/settings/CreateKeyModal.tsx",
      "app/settings/integrations/page.tsx",
      "components/settings/IntegrationsTable.tsx",
      "components/settings/CreateIntegrationModal.tsx",
      "components/settings/TestResultModal.tsx",
      "app/settings/page.tsx",
      "components/settings/ThresholdForm.tsx",
      "components/settings/LayerToggles.tsx",
      "components/settings/TenantSettings.tsx",
      "components/settings/RateLimitSettings.tsx",
      "components/settings/AdminLimitsForm.tsx",
      "components/settings/RetentionSettings.tsx",
      "components/settings/LLMSettings.tsx",
      "components/settings/ProxySettings.tsx",
      "components/admin/ListCells.tsx",
      "app/departments/*/page.tsx",
      "app/applications/*/page.tsx",
      "app/agent-runs/*/page.tsx",
      "app/login/page.tsx",
      "app/setup/page.tsx",
      "app/change-password/page.tsx",
    ],
    rules: {
      "react/jsx-no-literals": ["error", {
        noStrings:      true,
        ignoreProps:    true,
        allowedStrings: ["*", "-", "--", "...", "/", ".", ":", "·", "○", "‹", "›", "%", "ms", "s", "req", "->"],
      }],
    },
  },
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
]);

export default eslintConfig;
