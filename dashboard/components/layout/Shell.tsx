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
      <div className="flex flex-col flex-1 ml-56 min-h-0">
        <TopBar title={title} />
        <main className="flex-1 overflow-y-auto p-6">
          {children}
        </main>
      </div>
    </div>
  )
}