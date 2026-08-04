# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

"""
Source Registry: resolves an input_source string to a trust tier.

Provenance concern only -- classifying WHERE scanned content came from. It is
deliberately separate from the policy package: the registry answers "how much do
we trust this origin", while the posture/policy layer decides "what to do about
it". Config-driven, so new sources are onboarded by settings, never by code.
"""

from dataclasses import dataclass
from enum import Enum


class TrustTier(str, Enum):
    """Trust classification of an input_source's origin.

    trusted   - first-party content the caller authored (user_prompt).
    untrusted - content an agent pulled in (tool results, retrieved documents,
                other external text) -- the indirect prompt-injection surface.
    unknown   - a source in neither configured list. No trust assertion is
                made; it gets BASE posture unless treat_unknown_as_untrusted
                escalates it (Zero-Trust stance).
    """
    TRUSTED   = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN   = "unknown"


@dataclass(frozen=True)
class SourceDescriptor:
    """What the registry knows about an input_source. Today just the normalized
    source string and its trust tier; kept as a small struct so future
    provenance attributes (e.g. a display label, a default detector profile) can
    be added without changing call sites."""
    input_source: str
    tier:         TrustTier


class SourceRegistry:
    """Lookup from an input_source string to a SourceDescriptor.

    Classification order is UNTRUSTED-first: if a source is (mis)configured into
    both lists, the stricter tier wins so a config mistake can never quietly
    downgrade an origin to trusted. Anything in neither list is UNKNOWN, or
    UNTRUSTED when treat_unknown_as_untrusted is set.
    """

    def __init__(
        self,
        trusted:                    list[str],
        untrusted:                  list[str],
        treat_unknown_as_untrusted: bool = False,
    ) -> None:
        self._trusted   = {s.strip().lower() for s in trusted}
        self._untrusted = {s.strip().lower() for s in untrusted}
        self._treat_unknown_as_untrusted = treat_unknown_as_untrusted

    def resolve(self, input_source: str | None) -> SourceDescriptor:
        key = (input_source or "user_prompt").strip().lower()
        if key in self._untrusted:
            tier = TrustTier.UNTRUSTED
        elif key in self._trusted:
            tier = TrustTier.TRUSTED
        elif self._treat_unknown_as_untrusted:
            tier = TrustTier.UNTRUSTED
        else:
            tier = TrustTier.UNKNOWN
        return SourceDescriptor(input_source=key, tier=tier)

    @classmethod
    def from_settings(cls) -> "SourceRegistry":
        # Per-call settings read (never cache at module level) so trust-tier
        # config and test overrides take effect without a restart.
        from config.settings import get_settings
        s = get_settings()
        return cls(
            trusted                    = s.trusted_input_sources,
            untrusted                  = s.untrusted_input_sources,
            treat_unknown_as_untrusted = s.treat_unknown_as_untrusted,
        )
