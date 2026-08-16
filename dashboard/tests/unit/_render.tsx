// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// Shared render helper for component tests: wraps the tree in the real next-intl
// provider with the actual en.json catalog, so translated text (useTranslations /
// useLocale / useFormat) resolves exactly as it does in the app. Named _render.tsx
// (underscore) so the test glob does not treat it as a spec file.
import type { ReactElement } from "react"
import { render } from "@testing-library/react"
import { NextIntlClientProvider } from "next-intl"
import { SWRConfig } from "swr"
import messages from "@/messages/en.json"

export function renderWithIntl(ui: ReactElement, locale = "en") {
  // A fresh SWR cache per render isolates useSWR data between tests (SWR's cache
  // is a module singleton keyed by the SWR key, so it otherwise leaks across tests).
  const wrap = (node: ReactElement) => (
    <SWRConfig value={{ provider: () => new Map() }}>
      <NextIntlClientProvider locale={locale} messages={messages}>
        {node}
      </NextIntlClientProvider>
    </SWRConfig>
  )
  const result = render(wrap(ui))
  return {
    ...result,
    // Re-render inside the same intl provider (RTL's raw rerender drops the wrapper).
    rerender: (node: ReactElement) => result.rerender(wrap(node)),
  }
}

export * from "@testing-library/react"
