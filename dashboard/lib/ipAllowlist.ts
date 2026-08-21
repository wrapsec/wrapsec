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
