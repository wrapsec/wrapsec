# SPDX-License-Identifier: MIT
# Copyright (c) 2026 WrapSec. All rights reserved.
# WrapSec v1.0 | AI Security Gateway - https://wrapsec.com

import hashlib
import json
import logging

from cache.redis_client import get_redis

logger = logging.getLogger("wrapsec.cache")

CACHE_PREFIX  = "prompt_cache:"
CACHE_TTL     = 3600  # 1 hour

# Version of the RESPONSE CONTRACT that cached bodies were built against.
#
# A cached entry is a fully-formed response body, and it outlives the process
# that produced it: the TTL is an hour, so a deployment that changes the shape of
# a scan response will find bodies from the previous build still in Redis and
# still being served. The response is not re-derived on a hit, so nothing else
# would notice the mismatch -- the caller simply receives yesterday's shape.
#
# Carrying the version in the key means entries from an older contract are not
# addressable by a newer build: they are never read, and expire on their own.
# That is a deliberate alternative to waiting out the TTL, and to treating a
# validation failure as a miss, which would depend on the new contract rejecting
# the old body -- an added field would pass validation and be served silently.
#
# BUMP THIS whenever the public response shape changes: a field added, removed,
# renamed or retyped, or a change to which callers see which fields. Do not bump
# it for a change in a response VALUE. It is deliberately separate from
# `policy_identity`, which answers a different question (was this verdict reached
# under the same policy) and must not absorb response-shape concerns.
RESPONSE_CONTRACT_VERSION = 1


# Provider credentials can appear in the resolved `llm` section: policy
# resolution decrypts `api_key_enc` into `api_key` before handing the policy on.
# They are removed before the digest is taken. A credential does not change a
# verdict, and rotating one should not discard the tenant's cache.
_SECRET_POLICY_FIELDS = frozenset({"api_key", "api_key_enc"})

# Sentinel for callers that have no resolved policy to describe. Distinct from
# any real digest, so a keyed entry and an unkeyed one can never collide.
NO_POLICY = "nopolicy"


def policy_identity(
    *,
    block_threshold:             float | None,
    sanitize_threshold:          float | None,
    pii_block_threshold:         float | None,
    pii_sanitize_threshold:      float | None,
    toxicity_block_threshold:    float | None,
    toxicity_sanitize_threshold: float | None,
    rule_enabled:                bool,
    ml_enabled:                  bool,
    llm_enabled:                 bool,
    llm_settings:                dict | None,
) -> str:
    """
    Stable digest of the resolved policy a decision would be made under.

    The parameters are exactly the policy-derived arguments of
    `GatewayService.process`. That is the definition being used, rather than a
    chosen subset of the policy dict: those arguments ARE the decision inputs,
    so two requests agreeing on all of them would be judged identically and can
    share a cached verdict. `tests/unit/cache/test_semantic_cache_key.py` fails
    if the two signatures drift apart, so a new decision input cannot be added
    to the pipeline without being accounted for here.

    Not included, deliberately: `rate_limit`, which throttles a request but
    cannot change its verdict.
    """
    llm = llm_settings or {}
    if not isinstance(llm, dict):
        llm = {}
    safe_llm = {k: v for k, v in llm.items() if k not in _SECRET_POLICY_FIELDS}

    material = {
        "block_threshold":             block_threshold,
        "sanitize_threshold":          sanitize_threshold,
        "pii_block_threshold":         pii_block_threshold,
        "pii_sanitize_threshold":      pii_sanitize_threshold,
        "toxicity_block_threshold":    toxicity_block_threshold,
        "toxicity_sanitize_threshold": toxicity_sanitize_threshold,
        "rule_enabled":                rule_enabled,
        "ml_enabled":                  ml_enabled,
        "llm_enabled":                 llm_enabled,
        "llm_settings":                safe_llm,
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


def _cache_key(
    text:           str,
    detection_mode: str,
    execution_mode: str,
    tenant_id:      str,
    policy_id:      str,
    input_source:   str,
) -> str:
    """
    Deterministic cache key: tenant, resolved policy, provenance, modes, prompt.

    `tenant_id` keeps one tenant's ALLOW away from another. `policy_id` keeps a
    verdict inside the scope it was reached in: departments and applications may
    tighten policy below the tenant's, so one tenant resolves to different
    thresholds and different enabled layers depending on the caller. Keyed on
    tenant alone, a department with stricter policy received a laxer one's
    cached ALLOW without its own policy ever being consulted. It also expires
    entries when policy is tightened, which the TTL alone did not do.

    `input_source` keeps a verdict reached for first-party text away from the
    same text arriving as retrieved content, which source posture may judge
    against lower thresholds.

    Input is lowercased before hashing - case variants ("Hello" vs "hello")
    share a cache entry. Only ALLOW results are cached, so the security impact
    is limited to identical treatment of case-only variants of clean inputs.
    """
    if not tenant_id:
        raise ValueError("tenant_id must be a non-empty string - use 'global' for system calls")
    content = (
        f"{tenant_id}:{policy_id}:{input_source}:"
        f"{detection_mode}:{execution_mode}:{text.strip().lower()}"
    )
    digest  = hashlib.sha256(content.encode()).hexdigest()
    # The version sits OUTSIDE the digest so it stays readable in Redis: entries
    # from a superseded contract can be seen, counted and purged by prefix rather
    # than being indistinguishable hashes.
    return f"{CACHE_PREFIX}v{RESPONSE_CONTRACT_VERSION}:{digest}"


async def get_cached_result(
    text:           str,
    detection_mode: str,
    execution_mode: str,
    tenant_id:      str,
    policy_id:      str,
    input_source:   str,
) -> dict | None:
    """
    `policy_id` and `input_source` are required rather than defaulted: a default
    would let a call site omit the scope a verdict was reached in and silently
    read an entry from a different one, which is the defect this key exists to
    close. A caller with no resolved policy passes NO_POLICY explicitly.
    """
    try:
        redis  = get_redis()
        key    = _cache_key(text, detection_mode, execution_mode, tenant_id,
                            policy_id, input_source)
        cached = await redis.get(key)
        if cached:
            logger.debug(f"Cache hit for key {key[:20]}...")
            return json.loads(cached)
        return None
    except Exception as e:
        logger.warning(f"Cache get failed: {e}")
        return None


async def set_cached_result(
    text:           str,
    detection_mode: str,
    execution_mode: str,
    tenant_id:      str,
    result:         dict,
    policy_id:      str,
    input_source:   str,
    ttl:            int = CACHE_TTL,
) -> None:
    try:
        if result.get("decision") != "ALLOW":
            return
        redis = get_redis()
        key   = _cache_key(text, detection_mode, execution_mode, tenant_id,
                           policy_id, input_source)
        await redis.setex(key, ttl, json.dumps(result))
        logger.debug(f"Cached result for key {key[:20]}...")
    except Exception as e:
        logger.warning(f"Cache set failed: {e}")


async def invalidate(
    text:           str,
    detection_mode: str,
    execution_mode: str,
    tenant_id:      str,
    policy_id:      str,
    input_source:   str,
) -> None:
    try:
        redis = get_redis()
        key   = _cache_key(text, detection_mode, execution_mode, tenant_id,
                           policy_id, input_source)
        await redis.delete(key)
    except Exception as e:
        logger.warning(f"Cache invalidate failed: {e}")