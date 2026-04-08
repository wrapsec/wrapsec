import type { Metadata } from "next"
import "./globals.css"

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
      <body>{children}</body>
    </html>
  )
}
