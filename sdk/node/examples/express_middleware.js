/**
 * Express middleware example — scan every request body before it reaches your route.
 *
 * Setup:
 *   npm install wrapsec-node express
 *   export WRAPSEC_API_KEY=wsk_live_...
 *
 * Run:
 *   node examples/express_middleware.js
 *   curl -X POST http://localhost:3000/chat \
 *        -H "Content-Type: application/json" \
 *        -d '{"input": "What is Python?"}'
 */

const express = require("express")
const { wrapSecMiddleware } = require("wrapsec-node/middleware/express")

const app = express()
app.use(express.json())

// Attach WrapSec middleware — scans req.body.input before each route handler
app.use(wrapSecMiddleware({
  apiKey:  process.env.WRAPSEC_API_KEY,
  mode:    "fast",

  // Custom block handler — default returns 403 JSON if omitted
  onBlock: (req, res, result) => {
    res.status(403).json({
      error:   "blocked",
      reason:  result.primaryReason,
      traceId: result.traceId,
    })
  },
}))

app.post("/chat", (req, res) => {
  // If we reach here, the input passed security scanning
  const wrapsec = req.wrapsec  // attached by middleware
  if (wrapsec?.sanitizationApplied) {
    // Use sanitized input instead of original
    req.body.input = wrapsec.sanitizedInput
  }

  res.json({
    message:  "Request passed security checks",
    traceId:  wrapsec?.traceId,
    decision: wrapsec?.decision,
    input:    req.body.input,
  })
})

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000")
})
