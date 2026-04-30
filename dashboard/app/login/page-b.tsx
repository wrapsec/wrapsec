"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { login, loginWithCredentials, AuthError } from "@/lib/auth"

type Tab = "credentials" | "apikey"

export default function LoginPage() {
  const router = useRouter()

  const [tab,      setTab]      = useState<Tab>("credentials")
  const [email,    setEmail]    = useState("")
  const [password, setPassword] = useState("")
  const [apiKey,   setApiKey]   = useState("")
  const [loading,  setLoading]  = useState(false)
  const [error,    setError]    = useState<string | null>(null)

  async function handleCredentials() {
    setError(null)
    setLoading(true)
    try {
      const result = await loginWithCredentials(email.trim().toLowerCase(), password)
      if (result.force_password_change) {
        router.replace("/change-password")
      } else {
        router.replace("/")
        router.refresh()
      }
    } catch (err) {
      if (err instanceof AuthError) {
        if (err.code === "ACCOUNT_LOCKED") {
          setError("Account locked after too many failed attempts. Try again later.")
        } else if (err.code === "ACCOUNT_DISABLED") {
          setError("This account has been disabled. Contact your administrator.")
        } else {
          setError("Invalid email or password.")
        }
      } else {
        setError("Something went wrong. Please try again.")
      }
    } finally {
      setLoading(false)
    }
  }

  async function handleApiKey() {
    if (!apiKey.trim()) return
    setError(null)
    setLoading(true)
    try {
      const success = await login(apiKey.trim())
      if (success) {
        router.push("/")
        router.refresh()
      } else {
        setError("Invalid API key.")
      }
    } catch {
      setError("Invalid API key or API unavailable.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center">
      <div className="w-full max-w-sm">

        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="h-12 w-12 rounded-xl bg-blue-800 flex items-center justify-center mb-4">
            <svg className="h-7 w-7 text-white" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <h1 className="text-xl font-bold text-slate-900">WrapSec</h1>
          <p className="text-sm text-slate-500 mt-0.5">AI Security Gateway</p>
        </div>

        <div className="bg-white border border-slate-200 rounded-xl p-8 shadow-sm">
          <h2 className="text-base font-semibold text-slate-900 mb-4">Sign in</h2>

          {/* Tabs */}
          <div className="flex rounded-lg border border-slate-200 p-1 mb-6">
            <button
              onClick={() => { setTab("credentials"); setError(null) }}
              className={`flex-1 text-xs font-medium py-1.5 rounded-md transition-colors ${
                tab === "credentials"
                  ? "bg-blue-800 text-white"
                  : "text-slate-500 hover:text-slate-700"
              }`}
            >
              Email / Password
            </button>
            <button
              onClick={() => { setTab("apikey"); setError(null) }}
              className={`flex-1 text-xs font-medium py-1.5 rounded-md transition-colors ${
                tab === "apikey"
                  ? "bg-blue-800 text-white"
                  : "text-slate-500 hover:text-slate-700"
              }`}
            >
              API Key
            </button>
          </div>

          {error && (
            <div className="mb-4 px-3 py-2 text-xs text-red-700 bg-red-50 border border-red-200 rounded-lg">
              {error}
            </div>
          )}

          {/* Email / password form */}
          {tab === "credentials" && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1.5">
                  Email
                </label>
                <input
                  type="email"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && handleCredentials()}
                  placeholder="you@example.com"
                  autoFocus
                  autoComplete="email"
                  disabled={loading}
                  className="w-full h-10 px-3 text-sm rounded-lg border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800 disabled:opacity-50"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1.5">
                  Password
                </label>
                <input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && handleCredentials()}
                  placeholder="••••••••"
                  autoComplete="current-password"
                  disabled={loading}
                  className="w-full h-10 px-3 text-sm rounded-lg border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800 disabled:opacity-50"
                />
              </div>
              <button
                onClick={handleCredentials}
                disabled={!email.trim() || !password || loading}
                className="w-full h-10 bg-blue-800 text-white text-sm font-medium rounded-lg hover:bg-blue-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
              >
                {loading && (
                  <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                )}
                {loading ? "Signing in…" : "Sign in"}
              </button>
            </div>
          )}

          {/* API key form */}
          {tab === "apikey" && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1.5">
                  API Key
                </label>
                <input
                  type="password"
                  value={apiKey}
                  onChange={e => setApiKey(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && handleApiKey()}
                  placeholder="wrapsec_admin_key or wsk_live_..."
                  autoFocus
                  disabled={loading}
                  className="w-full h-10 px-3 text-sm rounded-lg border border-slate-200 bg-white text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:border-blue-800 disabled:opacity-50"
                />
              </div>
              <button
                onClick={handleApiKey}
                disabled={!apiKey.trim() || loading}
                className="w-full h-10 bg-blue-800 text-white text-sm font-medium rounded-lg hover:bg-blue-900 focus:outline-none focus:ring-2 focus:ring-blue-800 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
              >
                {loading && (
                  <svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                )}
                {loading ? "Verifying…" : "Sign in"}
              </button>
            </div>
          )}
        </div>

        <p className="text-center text-xs text-slate-400 mt-6">
          WrapSec v1.2 — AI Security Gateway
        </p>
      </div>
    </div>
  )
}
