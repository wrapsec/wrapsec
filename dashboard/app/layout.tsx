// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import type { Metadata } from "next"
import { NextIntlClientProvider } from "next-intl"
import { getLocale, getMessages } from "next-intl/server"
import "./globals.css"
import { SidebarProvider } from "@/contexts/SidebarContext"
import localeConfig from "@/messages/locale-config.json"

// Text direction is per-locale metadata from the canonical _meta.json (via the
// generated locale-config.json), never re-derived here. Unknown locales fall to
// the LTR floor -- matching services.localization.locale_direction on the backend.
const DIRECTIONS = localeConfig.directions as Record<string, "ltr" | "rtl">

export const metadata: Metadata = {
  title:       "WrapSec - AI Security Gateway",
  description: "AI Security Gateway for Intelligent Applications",
  icons: {
    icon:      "/wrapsec-logo.svg",
    shortcut:  "/wrapsec-logo.svg",
  },
}

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  // Locale + messages come from ./i18n/request.ts (validated cookie -> generated
  // catalog). The provider makes them available to every client component.
  const locale   = await getLocale()
  const messages = await getMessages()
  const dir      = DIRECTIONS[locale] ?? "ltr"
  return (
    <html lang={locale} dir={dir}>
      <body>
        <NextIntlClientProvider locale={locale} messages={messages}>
          <SidebarProvider>
            {children}
          </SidebarProvider>
        </NextIntlClientProvider>
      </body>
    </html>
  )
}
