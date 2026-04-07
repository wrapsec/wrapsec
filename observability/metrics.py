from prometheus_client import (
    Counter, Histogram, Gauge,
    generate_latest, CONTENT_TYPE_LATEST,
    CollectorRegistry, REGISTRY,
)

# ── Request metrics ───────────────────────────────────────────
REQUEST_TOTAL = Counter(
    "wrapsec_requests_total",
    "Total number of requests processed",
    ["decision", "detection_mode", "execution_mode"],
)

REQUEST_LATENCY = Histogram(
    "wrapsec_request_latency_ms",
    "Request latency in milliseconds",
    ["decision", "execution_mode"],
    buckets=[5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000],
)

# ── Threat metrics ────────────────────────────────────────────
THREAT_DETECTED = Counter(
    "wrapsec_threats_detected_total",
    "Total threats detected by category",
    ["category"],
)

# ── Layer metrics ─────────────────────────────────────────────
LAYER_SCORE = Histogram(
    "wrapsec_layer_score",
    "Detection score per layer",
    ["layer"],
    buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
)

# ── LLM metrics ───────────────────────────────────────────────
LLM_INVOCATIONS = Counter(
    "wrapsec_llm_invocations_total",
    "Total LLM invocations",
    ["provider", "purpose"],  # purpose: detection | completion
)

LLM_LATENCY = Histogram(
    "wrapsec_llm_latency_ms",
    "LLM response latency in milliseconds",
    ["provider", "purpose"],
    buckets=[100, 500, 1000, 2500, 5000, 10000, 30000, 60000],
)

# ── Cache metrics ─────────────────────────────────────────────
CACHE_HITS = Counter(
    "wrapsec_cache_hits_total",
    "Total semantic cache hits",
)

CACHE_MISSES = Counter(
    "wrapsec_cache_misses_total",
    "Total semantic cache misses",
)

# ── System metrics ────────────────────────────────────────────
ACTIVE_REQUESTS = Gauge(
    "wrapsec_active_requests",
    "Number of requests currently being processed",
)


def record_request(
    decision:       str,
    detection_mode: str,
    execution_mode: str,
    latency_ms:     float,
    threats:        list[str],
    layer_scores:   dict | None = None,
) -> None:
    """Record metrics for a completed gateway request."""
    REQUEST_TOTAL.labels(
        decision       = decision,
        detection_mode = detection_mode,
        execution_mode = execution_mode,
    ).inc()

    REQUEST_LATENCY.labels(
        decision       = decision,
        execution_mode = execution_mode,
    ).observe(latency_ms)

    for threat in threats:
        THREAT_DETECTED.labels(category=threat).inc()

    if layer_scores:
        for layer, score in layer_scores.items():
            LAYER_SCORE.labels(layer=layer).observe(score)


def get_metrics() -> tuple[bytes, str]:
    """Return Prometheus metrics in text format."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST