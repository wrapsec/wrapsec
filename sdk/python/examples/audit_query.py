"""
Audit query example - list logs, get stats, export CSV.

Setup:
    pip install wrapsec-python
    export WRAPSEC_API_KEY=wsk_live_...

Run:
    python examples/audit_query.py
"""

from pathlib import Path
import wrapsec

client = wrapsec.Client()

# Recent blocked requests
print("=== Recent BLOCKs ===")
logs = client.audit_list(decision="BLOCK", limit=5)
for log in logs:
    print(f"  {log.trace_id}  {log.primary_reason:<35}  conf={log.confidence:.2f}  {log.created_at[:19]}")

# Stats for all time
print("\n=== Stats ===")
stats = client.audit_stats()
total = stats.total_requests
if total:
    print(f"  Total:     {total:,}")
    print(f"  Blocked:   {stats.block_count:,}  ({stats.block_rate * 100:.1f}%)")
    print(f"  Sanitized: {stats.sanitize_count:,}")
    print(f"  Allowed:   {stats.allow_count:,}")
    print(f"  Avg latency:  {stats.avg_latency_ms:.1f}ms")
    print(f"  P95 latency:  {stats.p95_latency_ms:.1f}ms")
    sev = stats.severity_counts
    print(f"  Severity:  CRITICAL={sev.get('CRITICAL', 0)}  HIGH={sev.get('HIGH', 0)}  MEDIUM={sev.get('MEDIUM', 0)}  LOW={sev.get('LOW', 0)}")
else:
    print("  No requests yet.")

# Export CSV
print("\n=== Export ===")
csv_bytes = client.audit_export(limit=100)
out = Path("audit_export.csv")
out.write_bytes(csv_bytes)
print(f"  Exported {len(csv_bytes):,} bytes to {out}")
