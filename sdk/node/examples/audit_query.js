/**
 * Audit query example — list logs, get stats, export CSV.
 *
 * Setup:
 *   npm install wrapsec-node
 *   export WRAPSEC_API_KEY=wsk_live_...
 *
 * Run:
 *   node examples/audit_query.js
 */

const fs      = require("fs")
const WrapSec = require("wrapsec-node").default

const client = new WrapSec({ apiKey: process.env.WRAPSEC_API_KEY })

async function main() {
  // Recent blocked requests
  console.log("=== Recent BLOCKs ===")
  const logs = await client.auditList({ decision: "BLOCK", limit: 5 })
  for (const log of logs) {
    console.log(`  ${log.traceId}  ${log.primaryReason.padEnd(35)}  conf=${log.confidence.toFixed(2)}  ${log.createdAt.slice(0, 19)}`)
  }
  if (!logs.length) console.log("  No blocked requests yet.")

  // Stats
  console.log("\n=== Stats ===")
  const stats = await client.auditStats()
  console.log(`  Total:     ${stats.totalRequests.toLocaleString()}`)
  if (stats.totalRequests) {
    console.log(`  Blocked:   ${stats.blockCount.toLocaleString()}  (${(stats.blockRate * 100).toFixed(1)}%)`)
    console.log(`  Sanitized: ${stats.sanitizeCount.toLocaleString()}`)
    console.log(`  Allowed:   ${stats.allowCount.toLocaleString()}`)
    console.log(`  Avg latency:  ${stats.avgLatencyMs.toFixed(1)}ms`)
    console.log(`  P95 latency:  ${stats.p95LatencyMs.toFixed(1)}ms`)
    const sev = stats.severityCounts
    console.log(`  Severity:  CRITICAL=${sev.CRITICAL}  HIGH=${sev.HIGH}  MEDIUM=${sev.MEDIUM}  LOW=${sev.LOW}`)
  }

  // Export CSV
  console.log("\n=== Export ===")
  const csv = await client.auditExport({ limit: 100 })
  fs.writeFileSync("audit_export.csv", csv)
  console.log(`  Exported ${csv.length.toLocaleString()} bytes to audit_export.csv`)
}

main().catch(err => {
  console.error(err.message)
  process.exit(1)
})
