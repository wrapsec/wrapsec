// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen } from "./_render"
import { Pagination } from "@/components/requests/Pagination"

describe("Pagination visibility", () => {
  it("renders nothing when there is a single page or fewer", () => {
    const { container } = renderWithIntl(
      <Pagination total={20} offset={0} limit={20} onChange={() => {}} />
    )
    expect(container).toBeEmptyDOMElement()
  })

  it("renders controls when there is more than one page", () => {
    renderWithIntl(<Pagination total={100} offset={0} limit={20} onChange={() => {}} />)
    expect(screen.getByRole("button", { name: "First" })).toBeInTheDocument()
    expect(screen.getByText("1 / 5")).toBeInTheDocument()
  })
})

describe("Pagination edge disabling", () => {
  it("disables First/Previous on the first page", () => {
    renderWithIntl(<Pagination total={100} offset={0} limit={20} onChange={() => {}} />)
    expect(screen.getByRole("button", { name: "First" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "Next" })).toBeEnabled()
    expect(screen.getByRole("button", { name: "Last" })).toBeEnabled()
  })

  it("disables Next/Last on the last page", () => {
    renderWithIntl(<Pagination total={100} offset={80} limit={20} onChange={() => {}} />)
    expect(screen.getByText("5 / 5")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "Last" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "First" })).toBeEnabled()
  })
})

describe("Pagination navigation callbacks", () => {
  it("computes the right offset for each control from a middle page", async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    // page 3 of 5: offset 40, limit 20, total 100.
    renderWithIntl(<Pagination total={100} offset={40} limit={20} onChange={onChange} />)
    expect(screen.getByText("3 / 5")).toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: "First" }))
    expect(onChange).toHaveBeenLastCalledWith(0)

    await user.click(screen.getByRole("button", { name: "Previous" }))
    expect(onChange).toHaveBeenLastCalledWith(20)

    await user.click(screen.getByRole("button", { name: "Next" }))
    expect(onChange).toHaveBeenLastCalledWith(60)

    await user.click(screen.getByRole("button", { name: "Last" }))
    expect(onChange).toHaveBeenLastCalledWith(80)   // (totalPages-1)*limit = 4*20
  })
})
