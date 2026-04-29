import type { Metadata } from "next"
import "./globals.css"
import { SidebarProvider } from "@/contexts/SidebarContext"

export const metadata: Metadata = {
  title: "WrapSec - AI Security Gateway",
  description: "AI Security Gateway for Intelligent Applications",
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
