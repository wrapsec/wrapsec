// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import type { Metadata } from "next"
import { NextIntlClientProvider } from "next-intl"
import { getLocale, getMessages } from "next-intl/server"
import "./globals.css"
import { SidebarProvider } from "@/contexts/SidebarContext"

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
  return (
    <html lang={locale}>
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
