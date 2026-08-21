// SPDX-License-Identifier: MIT
// Copyright (c) 2026 WrapSec. All rights reserved.
// WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

/**
 * Checks an operator's source-network entries before they are sent.
 *
 * The server is authoritative and validates the same rules; this exists so a
 * typo is caught while the operator is still looking at the field, rather than
 * after a round trip.
 *
 * Deliberately errs toward accepting: anything this misses is refused by the
 * server with a clear message, whereas anything this wrongly rejects is a valid
 * network an operator cannot enter. A false accept costs a round trip; a false
 * reject costs them the feature.
 */

/** One entry, as typed, with the problem found in it (if any). */
export interface EntryCheck {
  value:  string
  error:  EntryError | null
}

export type EntryError = "malformed" | "allows_everything"

const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
// Loose on purpose: exact IPv6 grammar is the server's job. This rejects
// obvious nonsense (letters outside hex, wrong separators) and lets real
// addresses through in every form, compressed or not.
const IPV6 = /^[0-9a-fA-F:]+$/

/** Split a textarea's contents into entries, one per line, blanks dropped. */
export function parseEntries(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
}

function checkOne(entry: string): EntryError | null {
  const [address, prefixText, ...extra] = entry.split("/")
  if (extra.length > 0) return "malformed"

  const isV6 = address.includes(":")
  const isV4 = IPV4.test(address)

  if (isV4) {
    const octets = address.split(".").map(Number)
    if (octets.some((o) => o > 255)) return "malformed"
  } else if (!isV6 || !IPV6.test(address)) {
    return "malformed"
  }

  if (prefixText === undefined) return null

  // A prefix has to be a plain number in range; "10.0.0.0/" and "10.0.0.0/x"
  // are both mistakes worth catching here.
  if (!/^\d+$/.test(prefixText)) return "malformed"
  const prefix = Number(prefixText)
  const max    = isV4 ? 32 : 128
  if (prefix > max) return "malformed"

  // A zero prefix covers every address, so it is a restriction that restricts
  // nothing. The server refuses it; saying so here avoids a round trip to learn
  // that the safest-looking entry is the one that turns the control off.
  if (prefix === 0) return "allows_everything"

  return null
}

/** Check every entry, preserving order so errors line up with what was typed. */
export function checkEntries(entries: string[]): EntryCheck[] {
  return entries.map((value) => ({ value, error: checkOne(value) }))
}

/** True when nothing in the list would be refused. */
export function entriesAreValid(entries: string[]): boolean {
  return checkEntries(entries).every((c) => c.error === null)
}

/**
 * Coverage: would this list still admit an address the credential already uses?
 *
 * This is the opposite judgement call from validation above, so it errs the
 * other way. Validation errs toward accepting because the server has the last
 * word; coverage errs toward warning, because the thing it is protecting
 * against is an operator saving a list that locks out production. An address
 * this cannot parse is reported as uncovered: a warning that turns out to be
 * unnecessary costs a moment's thought, a missing one costs an outage.
 */

function v4Bytes(address: string): number[] | null {
  const m = IPV4.exec(address)
  if (m === null) return null
  const bytes: number[] = []
  for (let i = 1; i <= 4; i++) {
    const octet = Number(m[i])
    if (octet > 255) return null
    bytes.push(octet)
  }
  return bytes
}

function v6Bytes(address: string): number[] | null {
  const halves = address.split("::")
  if (halves.length > 2) return null

  const split = (part: string) => (part === "" ? [] : part.split(":"))
  const head  = split(halves[0])
  const tail  = halves.length === 2 ? split(halves[1]) : []

  // A dual-stack host often reports its address in the mapped form, so the
  // trailing dotted-quad is worth understanding rather than warning about.
  const groups = halves.length === 2 ? tail : head
  const last   = groups[groups.length - 1]
  if (last !== undefined && last.includes(".")) {
    const v4 = v4Bytes(last)
    if (v4 === null) return null
    const pair = [
      ((v4[0] << 8) | v4[1]).toString(16),
      ((v4[2] << 8) | v4[3]).toString(16),
    ]
    groups.splice(groups.length - 1, 1, ...pair)
  }

  const missing = 8 - (head.length + tail.length)
  if (halves.length === 1 ? missing !== 0 : missing < 0) return null

  const full = [
    ...head,
    ...(halves.length === 2 ? Array<string>(missing).fill("0") : []),
    ...tail,
  ]

  const bytes: number[] = []
  for (const group of full) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null
    const value = parseInt(group, 16)
    bytes.push(value >> 8, value & 0xff)
  }
  return bytes
}

/** An address as its bytes: four for IPv4, sixteen for IPv6, or null. */
function toBytes(address: string): number[] | null {
  return address.includes(":") ? v6Bytes(address) : v4Bytes(address)
}

/** True when the entry admits the address. Unparseable either side means no. */
export function entryCovers(entry: string, address: string): boolean {
  const [network, prefixText, ...extra] = entry.split("/")
  if (extra.length > 0) return false

  const net  = toBytes(network)
  const addr = toBytes(address)
  // A length mismatch is a family mismatch: comparing the numbers alone would
  // let an IPv6 network appear to cover an IPv4 address.
  if (net === null || addr === null || net.length !== addr.length) return false

  const width = net.length * 8
  // A missing prefix means the single address. An EMPTY one ("10.0.0.0/") is a
  // typo, and reading it as zero would make it cover every address and silence
  // the warning this exists to raise -- so it is refused rather than guessed at.
  if (prefixText !== undefined && !/^\d+$/.test(prefixText)) return false
  const prefix = prefixText === undefined ? width : Number(prefixText)
  if (prefix > width) return false

  for (let i = 0; i < net.length; i++) {
    const bits = Math.min(8, Math.max(0, prefix - i * 8))
    if (bits === 0) break
    const mask = (0xff << (8 - bits)) & 0xff
    if ((net[i] & mask) !== (addr[i] & mask)) return false
  }
  return true
}

/**
 * Which of these addresses the list would turn away.
 *
 * An empty list is no restriction at all, so nothing is turned away.
 */
export function uncoveredAddresses(entries: string[], addresses: string[]): string[] {
  if (entries.length === 0) return []
  return addresses.filter((address) => !entries.some((entry) => entryCovers(entry, address)))
}

/** The narrowest entry that admits exactly this address. */
export function suggestEntry(address: string): string {
  return `${address}/${address.includes(":") ? 128 : 32}`
}
