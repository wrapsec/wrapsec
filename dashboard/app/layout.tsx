// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import type { Metadata } from "next"
import "./globals.css"
import { SidebarProvider } from "@/contexts/SidebarContext"

export const metadata: Metadata = {
  title:       "WrapSec — AI Security Gateway",
  description: "AI Security Gateway for Intelligent Applications",
  icons: {
    icon:      "/wrapsec-logo.svg",
    shortcut:  "/wrapsec-logo.svg",
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>
        <SidebarProvider>
          {children}
        </SidebarProvider>
      </body>
    </html>
  )
}
