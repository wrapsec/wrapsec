// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect } from "vitest"
import { renderWithIntl, screen } from "./_render"
import { EmptyState } from "@/components/ui/EmptyState"
import { ErrorState } from "@/components/ui/ErrorState"

describe("EmptyState", () => {
  it("renders the title alone", () => {
    renderWithIntl(<EmptyState title="No results" />)
    expect(screen.getByText("No results")).toBeInTheDocument()
  })

  it("renders an optional message and action", () => {
    renderWithIntl(
      <EmptyState title="No keys" message="Create one to begin" action={<button>Add</button>} />
    )
    expect(screen.getByText("Create one to begin")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Add" })).toBeInTheDocument()
  })

  it("omits the message paragraph when none is given", () => {
    renderWithIntl(<EmptyState title="Only title" />)
    expect(screen.queryByText("Create one to begin")).not.toBeInTheDocument()
  })
})

describe("ErrorState", () => {
  it("renders a default title when none is passed", () => {
    renderWithIntl(<ErrorState />)
    expect(screen.getByText("Something went wrong")).toBeInTheDocument()
  })

  it("renders a caller-supplied (already-localized) message", () => {
    renderWithIntl(<ErrorState title="Load failed" message="Backend unavailable" />)
    expect(screen.getByText("Load failed")).toBeInTheDocument()
    expect(screen.getByText("Backend unavailable")).toBeInTheDocument()
  })

  it("colors the title by severity", () => {
    const { rerender } = renderWithIntl(<ErrorState title="Err" severity="ERROR" />)
    expect(screen.getByText("Err").className).toContain("text-red-700")

    rerender(<ErrorState title="Warn" severity="WARNING" />)
    expect(screen.getByText("Warn").className).toContain("text-amber-700")

    rerender(<ErrorState title="Info" severity="INFO" />)
    expect(screen.getByText("Info").className).toContain("text-sky-700")
  })

  it("renders an optional action (e.g. retry)", () => {
    renderWithIntl(<ErrorState title="Err" action={<button>Retry</button>} />)
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument()
  })
})
