# Changelog

All notable changes to WrapSec are documented here.

## [1.0.0] - 2026-05-13

Initial release.

- Multi-layer detection pipeline: rule-based, two-tier ML (TF-IDF + optional DeBERTa-v3 transformer), and LLM-backed analysis
- Scan-only and proxy execution modes with OpenAI-compatible API
- Multi-tenant architecture with department-level policy configuration
- Next.js dashboard, Prometheus metrics, and Grafana dashboards
- Python SDK (`wrapsec-python`) and Node.js SDK (`wrapsec-node`)
