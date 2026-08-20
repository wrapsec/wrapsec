# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Decide whether a source address may use a credential.

A credential can carry a list of networks it is valid from, so a leaked key is
only usable from the places its owner operates. Entries are CIDR blocks or bare
addresses, IPv4 or IPv6, and the two families may be mixed on one credential.

The feature is opt-in per credential: an absent or empty list allows every
address. Treating "no list configured" as "deny everything" would reject every
existing credential the moment the column ships, turning a security improvement
into an outage.

Matching only ever answers a question about the address. It performs no lookup,
consults no request state, and cannot be influenced by anything the caller sends
except the address itself, which the caller does not choose.
"""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger("wrapsec.security.ip_allowlist")


def normalize_entries(entries: list[str] | None) -> list[str]:
    """
    Validate and canonicalise allowlist entries, dropping anything unusable.

    A bare address becomes a single-host network, so `10.0.0.1` and
    `10.0.0.1/32` mean the same thing. Returned in canonical form so that what
    is stored is what was understood, rather than whatever the operator typed.

    Raises ValueError when an entry cannot be parsed, so a typo is rejected at
    configuration time rather than silently widening or narrowing access later.
    """
    if not entries:
        return []

    normalized: list[str] = []
    for entry in entries:
        text = (entry or "").strip()
        if not text:
            continue
        try:
            # strict=False accepts 10.0.0.1/24, treating it as the 10.0.0.0/24
            # network rather than rejecting a host address with a prefix.
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(f"'{entry}' is not a valid IP address or CIDR block") from exc

        # A zero-prefix network covers every address, so accepting it would
        # store a restriction that restricts nothing. A credential that looks
        # restricted but is not is worse than one that is openly unrestricted:
        # leave the list empty to allow everything, and mean it.
        if network.prefixlen == 0:
            raise ValueError(
                f"'{entry}' allows every address, which is not a restriction. "
                f"Leave the allowlist empty to permit all addresses."
            )

        normalized.append(str(network))

    return normalized


def is_allowed(client_ip: str | None, entries: list[str] | None) -> bool:
    """
    True when the address may use the credential.

    An empty or absent list allows everything: the control is off for that
    credential.

    A configured list with an unusable address fails CLOSED. Once an operator
    has stated where a credential may be used, an address that cannot be
    established is not one of those places.

    An unparseable ENTRY is skipped rather than failing the whole list, so one
    bad row cannot lock a credential out of every network it was granted. Entries
    are validated on write, so this is a defence against data that predates
    validation rather than a normal path.
    """
    if not entries:
        return True

    if not client_ip:
        logger.warning("Allowlist check with no client address; denying")
        return False

    try:
        address = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        logger.warning("Allowlist check with unparseable client address %r; denying", client_ip)
        return False

    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            logger.warning("Skipping unparseable allowlist entry %r", entry)
            continue
        # Networks of the other family never match, and comparing across
        # families raises, so the family is checked first.
        if address.version == network.version and address in network:
            return True

    return False
