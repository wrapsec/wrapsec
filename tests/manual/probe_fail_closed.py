"""
Dynamic probe: verify fail-closed enforcement when a detector raises.

Expectation (fail-closed policy):
    If any detector raises, the pipeline must force BLOCK. It must never
    treat a raising detector as clean.

Actual:
    services/gateway/service.py catches per-detector exceptions and
    replaces the result with DetectionResult.clean() (score 0.0), only
    setting a `detection_failed = True` flag that is never used to force
    BLOCK. Only the outer try/except forces BLOCK on total failure.

This probe monkeypatches the rule detector to raise, sends a benign
input, and checks the decision.
"""
import asyncio
from unittest.mock import patch

from domain.entities.request import IncomingRequest
from domain.enums import DetectionMode, ExecutionMode
from services.gateway.service import GatewayService


async def main() -> None:
    svc = GatewayService()

    request = IncomingRequest(
        input          = "Hello, how are you today?",  # benign
        detection_mode = DetectionMode.FAST,
        execution_mode = ExecutionMode.SCAN_ONLY,
    )

    with patch.object(
        svc._rule_detector,
        "detect",
        side_effect=RuntimeError("simulated detector crash"),
    ):
        result = await svc.process(request)

    decision = result.decision.decision.value
    score    = result.decision.risk_score.value
    reason   = result.decision.primary_reason

    print(f"Decision: {decision}")
    print(f"Risk score: {score:.3f}")
    print(f"Primary reason: {reason}")

    if decision == "ALLOW":
        print("FAIL: request ALLOWED despite detector crash (fail-open bug)")
    elif decision == "BLOCK":
        print("PASS: fail-closed enforced")
    else:
        print(f"UNEXPECTED: {decision}")


if __name__ == "__main__":
    asyncio.run(main())
