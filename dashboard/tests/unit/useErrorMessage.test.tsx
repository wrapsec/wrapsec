// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
//
// The client half of the NOT_FOUND resource contract.
//
// The API sends a machine token (`proxy_provider`). Turning it into a word the
// reader understands is this hook's job, and it is the only place that happens
// -- so an English label reaching a German reader is a bug that exists here or
// nowhere. The tests render against the REAL catalogs (en.json / de.json), not
// a fixture, because the defect being guarded is a missing or untranslated
// entry in those files.
import { describe, it, expect } from "vitest"
import { renderHook } from "@testing-library/react"
import { NextIntlClientProvider } from "next-intl"
import type { ReactNode } from "react"
import { useErrorMessage } from "@/hooks/useErrorMessage"
import { ApiError } from "@/lib/apiError"
import en from "@/messages/en.json"
import de from "@/messages/de.json"

const CATALOGS: Record<string, typeof en> = { en, de: de as unknown as typeof en }

function resolverFor(locale: "en" | "de") {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <NextIntlClientProvider locale={locale} messages={CATALOGS[locale]}>
      {children}
    </NextIntlClientProvider>
  )
  return renderHook(() => useErrorMessage(), { wrapper }).result.current
}

function notFound(resource: string) {
  return new ApiError({
    status:   404,
    message:  `${resource} not found.`,   // the server's English convenience string
    code:     "NOT_FOUND",
    key:      "errors.NOT_FOUND",
    params:   { resource },
    severity: "WARNING",
    traceId:  "req_abc",
  })
}

describe("useErrorMessage resource localization", () => {
  it("renders the English label for every public token", () => {
    const { resolve } = resolverFor("en")
    expect(resolve(notFound("proxy_provider")).message).toBe("proxy provider not found.")
    expect(resolve(notFound("request")).message).toBe("request not found.")
    expect(resolve(notFound("interaction")).message).toBe("interaction not found.")
    expect(resolve(notFound("application")).message).toBe("application not found.")
    expect(resolve(notFound("department")).message).toBe("department not found.")
  })

  it("renders the German label for every public token", () => {
    const { resolve } = resolverFor("de")
    expect(resolve(notFound("proxy_provider")).message).toBe("Proxy-Anbieter nicht gefunden.")
    expect(resolve(notFound("request")).message).toBe("Anfrage nicht gefunden.")
    expect(resolve(notFound("interaction")).message).toBe("Interaktion nicht gefunden.")
    expect(resolve(notFound("application")).message).toBe("Anwendung nicht gefunden.")
    expect(resolve(notFound("department")).message).toBe("Abteilung nicht gefunden.")
  })

  it("never leaves the raw token in a rendered message", () => {
    // The failure this whole change exists to prevent: the token, or an English
    // word, surviving into German output.
    const { resolve } = resolverFor("de")
    for (const token of ["proxy_provider", "request", "interaction", "application", "department"]) {
      const { message } = resolve(notFound(token))
      expect(message).not.toContain(token)
      expect(message).not.toContain("_")
    }
  })

  it("falls back to the raw token when the catalog does not know it", () => {
    // A server that adds a resource before the catalog does must still produce a
    // readable sentence -- one untranslated word, not a blank or a crash.
    const { resolve } = resolverFor("de")
    expect(resolve(notFound("quantum_widget")).message).toBe("quantum_widget nicht gefunden.")
  })

  it("leaves other params untouched", () => {
    const { resolve } = resolverFor("de")
    const rateLimited = new ApiError({
      status:   429,
      message:  "Too many requests.",
      code:     "RATE_LIMIT_EXCEEDED",
      key:      "errors.RATE_LIMIT_EXCEEDED",
      params:   { retry_after: 60 },
      severity: "WARNING",
    })
    expect(resolve(rateLimited).message).toContain("60")
  })

  it("carries the severity through unchanged", () => {
    const { resolve } = resolverFor("en")
    expect(resolve(notFound("request")).severity).toBe("WARNING")
  })
})
