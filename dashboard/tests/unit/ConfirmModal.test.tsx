// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen } from "./_render"
import { ConfirmModal } from "@/components/ui/ConfirmModal"

function setup(props: Partial<Parameters<typeof ConfirmModal>[0]> = {}) {
  const onConfirm = vi.fn()
  const onClose   = vi.fn()
  renderWithIntl(
    <ConfirmModal
      title="Delete key"
      message="This cannot be undone."
      onConfirm={onConfirm}
      onClose={onClose}
      {...props}
    />
  )
  return { onConfirm, onClose, user: userEvent.setup() }
}

describe("ConfirmModal render", () => {
  it("renders the title, message, and Cancel/Confirm buttons", () => {
    setup()
    expect(screen.getByText("Delete key")).toBeInTheDocument()
    expect(screen.getByText("This cannot be undone.")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Cancel" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Confirm" })).toBeInTheDocument()
  })

  it("uses a custom confirm label when provided", () => {
    setup({ confirmLabel: "Yes, delete" })
    expect(screen.getByRole("button", { name: "Yes, delete" })).toBeInTheDocument()
  })

  it("shows an inline error message when passed", () => {
    setup({ error: "Server refused" })
    expect(screen.getByText("Server refused")).toBeInTheDocument()
  })
})

describe("ConfirmModal actions", () => {
  it("calls onConfirm when Confirm is clicked", async () => {
    const { onConfirm, user } = setup()
    await user.click(screen.getByRole("button", { name: "Confirm" }))
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })

  it("calls onClose when Cancel is clicked", async () => {
    const { onClose, user } = setup()
    await user.click(screen.getByRole("button", { name: "Cancel" }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it("closes on the Escape key", async () => {
    const { onClose, user } = setup()
    await user.keyboard("{Escape}")
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})

describe("ConfirmModal in-flight (loading) guard", () => {
  it("does NOT close on Escape while an action is loading", async () => {
    const { onClose, user } = setup({ loading: true })
    await user.keyboard("{Escape}")
    expect(onClose).not.toHaveBeenCalled()
  })

  it("disables Cancel while loading", () => {
    setup({ loading: true })
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled()
  })
})
