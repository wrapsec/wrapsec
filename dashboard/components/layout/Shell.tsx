import { Sidebar } from "./Sidebar"
import { TopBar } from "./TopBar"

interface ShellProps {
  title: string
  children: React.ReactNode
}

export function Shell({ title, children }: ShellProps) {
  return (
    <div className="flex h-screen bg-slate-50">
      <Sidebar />
      {/* No ml-56 — Sidebar renders its own spacer div that transitions with it */}
      <div className="flex flex-col flex-1 min-w-0 min-h-0">
        <TopBar title={title} />
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  )
}