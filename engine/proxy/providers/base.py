# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Base provider contract for proxy mode.
All providers must implement chat_completions() and return ProviderResponse.
Exceptions must propagate -- providers must never swallow errors.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ProviderResponse:
    """
    Normalised response returned by every provider.
    The raw field contains the full provider response for audit logging.
    """
    content:       str
    model:         str
    finish_reason: str
    latency_ms:    int
    raw:           dict


class BaseProxyProvider(ABC):

    @abstractmethod
    async def chat_completions(
        self,
        model:    str,
        messages: list[dict],
        **kwargs,
    ) -> ProviderResponse:
        """
        Send messages to the provider and return a ProviderResponse.

        Contract:
          - Must never return None.
          - Raises httpx.TimeoutException on timeout.
          - Raises httpx.HTTPStatusError on non-2xx provider response.
          - Raises httpx.ConnectError on connection failure.
          - All other exceptions must propagate -- do not swallow them.
          - Must forward X-WrapSec-Trace-Id header when trace_id is provided.
        """
