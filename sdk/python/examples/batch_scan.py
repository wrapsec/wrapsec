"""
Batch scan example - scan a list of prompts from a file.

Setup:
    pip install wrapsec-python
    export WRAPSEC_API_KEY=wsk_live_...

Run:
    python examples/batch_scan.py prompts.txt
    # Or use the built-in CLI:
    # wrapsec batch prompts.txt --summary
"""

import sys
import wrapsec


def main() -> None:
    file = sys.argv[1] if len(sys.argv) > 1 else None
    if not file:
        print("Usage: python batch_scan.py <prompts_file>")
        print("       One prompt per line. Lines starting with # are skipped.")
        sys.exit(1)

    client = wrapsec.Client()

    with open(file, encoding="utf-8") as fh:
        prompts = [
            line.strip()
            for line in fh
            if line.strip() and not line.strip().startswith("#")
        ]

    print(f"Scanning {len(prompts)} prompts...\n")

    blocked   = 0
    sanitized = 0
    allowed   = 0

    results = client.batch(prompts, delay_ms=100)

    for prompt, result in zip(prompts, results):
        marker = {"BLOCK": "BLOCK   ", "SANITIZE": "SANITIZE", "ALLOW": "ALLOW   "}.get(result.decision, result.decision)
        print(f"[{marker}]  {prompt[:60]}")
        if result.decision == "BLOCK":    blocked   += 1
        elif result.decision == "SANITIZE": sanitized += 1
        else:                              allowed   += 1

    print(f"\nTotal: {len(prompts)}  BLOCK={blocked}  SANITIZE={sanitized}  ALLOW={allowed}")
    sys.exit(2 if blocked else 0)


if __name__ == "__main__":
    main()
