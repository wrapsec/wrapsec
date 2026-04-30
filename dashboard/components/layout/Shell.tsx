"use client"

import { Sidebar } from "./Sidebar"
import { TopBar } from "./TopBar"
import { useInactivityTimer } from "@/hooks/useInactivityTimer"
import { InactivityWarning } from "./InactivityWarning"

interface ShellProps {
  title:    string
  children: React.ReactNode
}

export function Shell({ title, children }: ShellProps) {
  const { showWarning, secondsRemaining, resetTimer, logoutNow } = useInactivityTimer()

  return (
    <div className="flex h-screen" style={{ background: "var(--page-bg)" }}>
      {showWarning && (
        <InactivityWarning
          secondsRemaining={secondsRemaining}
          onStay={resetTimer}
          onLogout={logoutNow}
        />
      )}
      <Sidebar />
      <div className="flex flex-col flex-1 min-w-0 min-h-0">
        <TopBar title={title} />
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
