"use client"

import { useState, FormEvent } from "react"
import { useRouter } from "next/navigation"
import { changePassword, logout, AuthError } from "@/lib/auth"

const REQUIREMENTS = [
  { label: "At least 8 characters", test: (p: string) => p.length >= 8 },
  { label: "One uppercase letter",  test: (p: string) => /[A-Z]/.test(p) },
  { label: "One lowercase letter",  test: (p: string) => /[a-z]/.test(p) },
  { label: "One digit",             test: (p: string) => /\d/.test(p) },
]

export default function ChangePasswordPage() {
  const router = useRouter()

  const [current, setCurrent] = useState("")
  const [next,    setNext]    = useState("")
  const [confirm, setConfirm] = useState("")
  const [error,   setError]   = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)

  const reqsMet        = REQUIREMENTS.every(r => r.test(next))
  const passwordsMatch = next === confirm && next.length > 0

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)

    if (!reqsMet) {
      setError("New password does not meet requirements.")
      return
    }
    if (!passwordsMatch) {
      setError("Passwords do not match.")
      return
    }

    setLoading(true)
    try {
      await changePassword(current, next)
      setSuccess(true)
      // All sessions invalidated — must log in again
      setTimeout(async () => {
        await logout()
        router.replace("/login")
      }, 2000)
    } catch (err) {
      if (err instanceof AuthError) {
        if (err.code === "INVALID_PASSWORD") {
          setError("Current password is incorrect.")
        } else {
          setError(err.message || "Password change failed.")
        }
      } else {
        setError("Something went wrong. Please try again.")
      }
    } finally {
      setLoading(false)
    }
  }

  if (success) {
    return (
      <div className="min-h-screen bg-slate-50 flex items-center justify-center">
        <div className="w-full max-w-sm bg-white border border-slate-200 rounded-xl p-8 shadow-sm text-center">
          <div className="flex justify-center mb-4">
            <div className="h-12 w-12 rounded-full bg-green-100 flex items-center justify-center">
              <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
          </div>
          <h2 className="text-base font-semibold text-slate-900 mb-1">Password changed</h2>
          <p className="text-sm text-slate-500">All sessions signed out. Redirecting to login…</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center">
      <div className="w-full max-w-sm">

        <div className="flex flex-col items-center mb-8">
          <div className="h-12 w-12 rounded-xl bg-blue-800 flex items-center justify-center mb-4">
            <svg className="h-7 w-7 text-white" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-xl font-bold text-slate-900">WrapSec</h1>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-8 shadow-sm">
          <h2 className="text-base font-semibold text-slate-900 mb-1">Change password</h2>
          <p className="text-sm text-slate-500 mb-6">
            Choose a new password to continue.
          </p>

          {error && (
            <div className="mb-4 px-3 py-2 text-xs text-red-700 bg-red-50 border border-red-200 rounded-lg">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Current password
              </label>
              <input
                type="password"
                value={current}
                onChange={e => setCurrent(e.target.value)}
                required
                disabled={loading}
                autoComplete="current-password"
                className="w-full h-10 px-3 text-sm rounded-lg border border-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-800 disabled:opacity-50"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                New password
              </label>
              <input
                type="password"
                value={next}
                onChange={e => setNext(e.target.value)}
                required
                disabled={loading}
                autoComplete="new-password"
                className="w-full h-10 px-3 text-sm rounded-lg border border-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-800 disabled:opacity-50"
              />
              {next.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {REQUIREMENTS.map(r => (
                    <li key={r.label} className={`flex items-center gap-1.5 text-xs ${r.test(next) ? "text-green-600" : "text-slate-400"}`}>
                      <span>{r.test(next) ? "✓" : "○"}</span>
                      {r.label}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700 mb-1.5">
                Confirm new password
              </label>
              <input
                type="password"
                value={confirm}
                onChange={e => setConfirm(e.target.value)}
                required
                disabled={loading}
                autoComplete="new-password"
                className={`w-full h-10 px-3 text-sm rounded-lg border focus:outline-none focus:ring-2 focus:ring-blue-800 disabled:opacity-50 ${
                  confirm.length > 0 && !passwordsMatch
                    ? "border-red-400"
                    : "border-slate-200"
                }`}
              />
              {confirm.length > 0 && !passwordsMatch && (
                <p className="mt-1 text-xs text-red-500">Passwords do not match</p>
              )}
            </div>

            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={logout}
                disabled={loading}
                className="flex-1 h-10 border border-slate-200 text-sm font-medium text-slate-700 rounded-lg hover:bg-slate-50 disabled:opacity-50 transition-colors"
              >
                Sign out
              </button>
              <button
                type="submit"
                disabled={loading || !reqsMet || !passwordsMatch}
                className="flex-1 h-10 bg-blue-800 text-white text-sm font-medium rounded-lg hover:bg-blue-900 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {loading ? "Saving…" : "Change password"}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}
