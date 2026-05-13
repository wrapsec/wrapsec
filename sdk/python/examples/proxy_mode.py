"""
Proxy mode example - scan + forward to LLM in one call.

Requires:
    - A configured LLM provider (via PUT /v1/settings/proxy or dashboard)
    - A live API key (proxy mode is disabled for trial keys)

Setup:
    pip install wrapsec-python
    export WRAPSEC_API_KEY=wsk_live_...

Run:
    python examples/proxy_mode.py
"""

import wrapsec

client = wrapsec.Client()

result = client.scan(
    "Summarise the key principles of zero-trust networking.",
    execution_mode="proxy",
    model="openai/gpt-4o-mini",
)

print(f"Input decision:  {result.decision}")
print(f"Primary reason:  {result.primary_reason}")
print(f"Trace ID:        {result.trace_id}")
print(f"Execution mode:  {result.execution_mode}")

if result.is_blocked:
    print("Request was blocked - no LLM response.")
elif result.output:
    print(f"\nLLM response:\n{result.output}")
