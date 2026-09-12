# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Tool definitions, inspected before they enter the agent's context.

A tool definition is instructions the model reads and acts on. It arrives from a
downstream server the gateway does not control, and the agent treats it as
trusted context simply because it came through the tool channel. That is the
whole attack: text placed in a description is read by the model with the
authority of the tool list, not with the suspicion given to a document.

So the definition is scanned before it is published, and a definition that is
refused is withheld rather than published with a warning attached -- an agent
that can see a blocked description has already read it.

WHAT IS SCANNED. The parts a model actually reads: the name, the title, the
description, and the human-readable text inside the input schema (property
descriptions, titles, enum descriptions). Schema structure -- types, required
lists, formats -- is not prose and is not sent.

FINGERPRINTS. Each published definition is hashed over its security-relevant
content. A later listing that differs is a definition that CHANGED underneath an
agent that had already been told what the tool does, which is worth recording
even when the new text is clean. V1 does not block on change alone: it records
the change and re-inspects the new text, and blocks only on what the scan says.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from mcp_gateway.decision import Refusal
from mcp_gateway.scanner import SOURCE_TOOL_DEFINITION, ScannerProtocol

logger = logging.getLogger(__name__)

# Schema keys whose values are prose a model reads. Everything else in a schema
# is structure, and sending structure to a prose detector produces noise, not
# signal.
_PROSE_KEYS = ("description", "title")


class ToolDefinitionScanner:
    """Scans tool definitions and tracks what each server published.

    One instance per gateway process, which is one agent connection: the
    fingerprints it remembers describe what THIS agent was told, and must not be
    shared with another connection that was told something else.
    """

    def __init__(self, scanner: ScannerProtocol, *, enabled: bool = True) -> None:
        self._scanner = scanner
        self._enabled = enabled
        # (server, tool) -> the fingerprint last judged, and what was decided.
        # The DECISION is remembered as well as the fingerprint: identical
        # content must keep its verdict, so a definition that was withheld stays
        # withheld on the next listing without being scanned again.
        self._seen:    dict[tuple[str, str], tuple[str, bool]] = {}
        self._changes: list[dict[str, str]] = []

    async def inspect(
        self, *, server_name: str, definition: Any, trace_id: str,
        turn_index: int | None = None,
    ) -> tuple[Any | None, Refusal | None]:
        """Return the definition to publish, or (None, refusal) to withhold it."""
        if not self._enabled:
            return definition, None

        name = getattr(definition, "name", "") or ""
        text = definition_text(definition)

        fingerprint = fingerprint_of(definition)
        key         = (server_name, name)
        remembered  = self._seen.get(key)
        previous    = remembered[0] if remembered else None

        if remembered is not None and previous == fingerprint:
            # Unchanged since it was judged, so the earlier decision stands and
            # no scan is issued. The fingerprint covers the content that was
            # judged, so identical content cannot have a different verdict; and
            # an agent that lists tools every turn would otherwise pay a scan per
            # tool per turn, in its own latency path.
            published = remembered[1]
            if published:
                return definition, None
            return None, Refusal(
                reason   = "TOOL_DEFINITION_BLOCKED",
                trace_id = trace_id,
                detail   = f"tool definition {name!r} from server {server_name!r} "
                           f"was withheld earlier and is unchanged",
            )

        if previous is not None and previous != fingerprint:
            # Recorded whether or not the new text turns out to be clean. A tool
            # whose description changes after an agent has been told what it does
            # is a fact an operator wants, and the change is what prompts the
            # re-inspection below rather than a cached verdict.
            logger.warning(
                "tool definition changed: server=%s tool=%s (trace %s)",
                server_name, name, trace_id,
            )
            self._changes.append({
                "server": server_name, "tool": name,
                "before": previous, "after": fingerprint, "trace_id": trace_id,
            })

        verdict = await self._scanner.scan(
            text, source=SOURCE_TOOL_DEFINITION, trace_id=trace_id,
            turn_index=turn_index,
        )

        if verdict.blocked:
            # Withheld entirely. Publishing it with the description removed would
            # still put an attacker-chosen NAME into the context, and publishing
            # a placeholder would tell the agent a tool exists that it cannot use.
            logger.warning(
                "withholding tool %s from server %s: %s (trace %s)",
                name, server_name, verdict.reason, verdict.trace_id,
            )
            self._seen[key] = (fingerprint, False)
            return None, Refusal(
                reason   = verdict.reason,
                trace_id = verdict.trace_id,
                detail   = f"tool definition {name!r} from server {server_name!r}",
                failed   = verdict.failed,
            )

        self._seen[key] = (fingerprint, True)
        return definition, None

    @property
    def changes(self) -> tuple[dict[str, str], ...]:
        """Definition changes seen in this session, oldest first."""
        return tuple(self._changes)

    def fingerprint_for(self, server_name: str, tool_name: str) -> str | None:
        remembered = self._seen.get((server_name, tool_name))
        return remembered[0] if remembered else None


def definition_text(definition: Any) -> str:
    """The prose a model would read, as one block for the detector.

    Parts are joined with newlines rather than concatenated, so an injection
    cannot be assembled across a boundary that did not exist in the original.
    """
    parts: list[str] = []
    for attr in ("name", "title", "description"):
        value = getattr(definition, attr, None)
        if isinstance(value, str) and value:
            parts.append(value)

    schema = getattr(definition, "input_schema", None)
    parts.extend(_schema_prose(schema))
    return "\n".join(parts)


def _schema_prose(node: Any, depth: int = 0) -> list[str]:
    """Every human-readable string inside a JSON schema.

    Walks nested objects and arrays, because a description three levels down is
    read by the model exactly as one at the top. Bounded depth: a schema is
    caller-supplied, and a self-referential one would otherwise recurse forever.
    """
    if depth > 12 or node is None:
        return []

    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _PROSE_KEYS and isinstance(value, str) and value:
                found.append(value)
            elif isinstance(value, (dict, list)):
                found.extend(_schema_prose(value, depth + 1))
    elif isinstance(node, list):
        for item in node:
            found.extend(_schema_prose(item, depth + 1))
    return found


def fingerprint_of(definition: Any) -> str:
    """A stable hash over the security-relevant parts of a definition.

    Covers the name and the whole input schema, not only the prose: a parameter
    that changes type, or a new required field, changes what the tool does even
    when every description stays identical.

    The schema is serialised with sorted keys so an equivalent definition that
    merely reorders its keys does not read as a change. Otherwise every listing
    from a server that iterates a dict in a different order would look like
    tampering, and a real change would be lost among the noise.
    """
    material = {
        "name":        getattr(definition, "name", None),
        "title":       getattr(definition, "title", None),
        "description": getattr(definition, "description", None),
        "schema":      getattr(definition, "input_schema", None),
    }
    encoded = json.dumps(material, sort_keys=True, default=str, ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
