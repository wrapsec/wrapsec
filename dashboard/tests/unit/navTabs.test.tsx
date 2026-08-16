// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com
import { describe, it, expect, vi } from "vitest"
import userEvent from "@testing-library/user-event"
import { renderWithIntl, screen } from "./_render"
import { Tabs, type TabDef } from "@/components/ui/Tabs"
import { RangeTabs } from "@/components/ui/RangeTabs"

function tab(id: string, body: string, visible?: boolean): TabDef {
  return { id, label: `${id} label`, render: () => <div>{body}</div>, visible }
}

describe("Tabs (uncontrolled)", () => {
  it("renders the first visible tab's panel by default", () => {
    renderWithIntl(<Tabs tabs={[tab("a", "Panel A"), tab("b", "Panel B")]} />)
    expect(screen.getByText("Panel A")).toBeInTheDocument()
    expect(screen.queryByText("Panel B")).not.toBeInTheDocument()
  })

  it("respects initialId", () => {
    renderWithIntl(<Tabs tabs={[tab("a", "Panel A"), tab("b", "Panel B")]} initialId="b" />)
    expect(screen.getByText("Panel B")).toBeInTheDocument()
  })

  it("switches the panel when another tab is clicked", async () => {
    const user = userEvent.setup()
    renderWithIntl(<Tabs tabs={[tab("a", "Panel A"), tab("b", "Panel B")]} />)
    await user.click(screen.getByRole("tab", { name: "b label" }))
    expect(screen.getByText("Panel B")).toBeInTheDocument()
    expect(screen.getByRole("tab", { name: "b label" })).toHaveAttribute("aria-selected", "true")
  })

  it("hides tabs with visible:false", () => {
    renderWithIntl(<Tabs tabs={[tab("a", "Panel A"), tab("b", "Panel B", false)]} />)
    expect(screen.getByRole("tab", { name: "a label" })).toBeInTheDocument()
    expect(screen.queryByRole("tab", { name: "b label" })).not.toBeInTheDocument()
  })
})

describe("Tabs (controlled)", () => {
  it("shows the activeId panel and calls onChange without owning state", async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    renderWithIntl(
      <Tabs tabs={[tab("a", "Panel A"), tab("b", "Panel B")]} activeId="a" onChange={onChange} />
    )
    // Controlled: clicking b calls onChange but the panel stays on the parent-owned activeId.
    await user.click(screen.getByRole("tab", { name: "b label" }))
    expect(onChange).toHaveBeenCalledWith("b")
    expect(screen.getByText("Panel A")).toBeInTheDocument()   // still A until parent updates activeId
  })
})

describe("RangeTabs", () => {
  const opts = ["24h", "7d", "30d"] as const

  it("renders one button per option and marks the active one selected", () => {
    renderWithIntl(<RangeTabs options={opts} value="7d" onChange={() => {}} />)
    for (const o of opts) expect(screen.getByRole("button", { name: o })).toBeInTheDocument()
    // active pill carries font-semibold; assert the class marker.
    expect(screen.getByRole("button", { name: "7d" }).className).toContain("font-semibold")
    expect(screen.getByRole("button", { name: "24h" }).className).toContain("font-normal")
  })

  it("calls onChange with the clicked option", async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    renderWithIntl(<RangeTabs options={opts} value="7d" onChange={onChange} />)
    await user.click(screen.getByRole("button", { name: "30d" }))
    expect(onChange).toHaveBeenCalledWith("30d")
  })

  it("applies a custom format function to the labels", () => {
    renderWithIntl(
      <RangeTabs options={opts} value="24h" onChange={() => {}} format={(o) => `Last ${o}`} />
    )
    expect(screen.getByRole("button", { name: "Last 24h" })).toBeInTheDocument()
  })
})
