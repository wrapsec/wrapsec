# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""Identifiers that let one agent's activity be reconstructed afterwards.

Four of them, each answering a different question:

  session_id  which agent connection was this
  run_id      which gateway execution was this
  turn_index  where in that run did it happen
  trace_id    which single security decision was it

WHY THE GATEWAY ASSIGNS THEM. They are not read from the protocol. The newest
protocol revision has no session at all, so anything derived from protocol state
would work on one connection and produce nothing on another. Assigning them here
makes the trail identical whatever revision an agent negotiates.

WHY SESSION AND RUN ARE SEPARATE despite being the same span today. On stdio one
client is one process, so a connection and an execution coincide. They are still
distinct values, because the fields mean different things to the timeline that
reads them: a run groups one execution, a session groups runs that belong to one
conversation. If a network transport later multiplexes connections, or one
connection spans several runs, the records already say the right thing and
nothing has to be reinterpreted after the fact.

WHY A TURN IS AN AGENT REQUEST rather than a scan. One request can produce
several decisions -- a call is judged on its arguments and again on its result --
and they belong together. Sharing an index is what lets a timeline read "turn 3:
call to files__read, arguments allowed, result blocked" instead of leaving an
investigator to re-associate rows by hand.

NEVER AN AUTHORIZATION INPUT. These are correlation metadata. Nothing decides
what a caller may do on the strength of them, and nothing here is trusted from
outside: every value is minted in this process.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field


def _identifier(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


@dataclass
class Correlation:
    """The correlation scope of one gateway process.

    One instance per process, which on stdio is one agent connection. Parallel
    agents run in separate processes and therefore hold separate scopes, so their
    activity cannot merge into one timeline -- the isolation comes from the
    runtime model rather than from bookkeeping here.
    """

    session_id: str = field(default_factory=lambda: _identifier("mcpsess"))
    run_id:     str = field(default_factory=lambda: _identifier("mcprun"))
    _turn:      int = 0

    def begin_turn(self) -> int:
        """Start a new agent request and return its index.

        Called once per inbound request, not once per scan: every decision made
        while serving that request shares the index.
        """
        self._turn += 1
        return self._turn

    @property
    def turn_index(self) -> int:
        """The turn currently being served."""
        return self._turn

    def trace(self) -> str:
        """An identifier for one security decision."""
        return _identifier("mcp")

    def describe(self) -> str:
        """For the startup record, so an operator can find this run later."""
        return f"session={self.session_id} run={self.run_id}"
