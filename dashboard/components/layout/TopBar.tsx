"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { StatusDot } from "@/components/ui/StatusDot"
import { getHealth } from "@/lib/api"
import { logout } from "@/lib/auth"

export function TopBar({ title }: { title: string }) {
  const [status, setStatus] = useState<"ok" | "degraded" | "down">("ok")
  const router = useRouter()

  useEffect(() => {
    const check = async () => {
      try {
        const health = await getHealth()
        const allOk = Object.values(health.checks).every(v => v === "ok")
        setStatus(allOk ? "ok" : "degraded")
      } catch {
        setStatus("down")
      }
    }
    check()
    const interval = setInterval(check, 30000)
    return () => clearInterval(interval)
  }, [])

  const handleLogout = async () => {
    await logout()
    router.push("/login")
  }

  return (
    <header className="h-14 bg-white border-b border-slate-200 flex items-center justify-between px-6 flex-shrink-0">
      <h1 className="text-base font-semibold text-slate-900">{title}</h1>
      <div className="flex items-center gap-5">
        <StatusDot
          status={status}
          label={
            status === "ok"       ? "All systems operational" :
            status === "degraded" ? "Degraded" :
                                    "API unavailable"
          }
        />
        <button
          onClick={handleLogout}
          className="text-xs text-slate-500 hover:text-slate-900 transition-colors"
        >
          Sign out
        </button>
      </div>
    </header>
  )
}