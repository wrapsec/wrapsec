# WrapSec Manual Test Suite

Bash + curl + jq test suite for Ubuntu/Linux. Tests all API endpoints, CLI commands, and the Python SDK. No pytest or PowerShell required.

## Requirements

- `bash` >= 4.0
- `curl`
- `jq`
- `python3` (for SDK tests)

Install on Ubuntu:

```bash
sudo apt-get install -y curl jq
```

## Quick start

```bash
# Configure and run all tests
export WRAPSEC_API_KEY=wsk_live_...
export WRAPSEC_URL=http://localhost:8000   # or your server address

bash tests/manual/run_all.sh
```

## Configuration

All settings are in `tests/manual/config.sh`. Every value can be overridden with an environment variable:

| Variable | Default | Description |
|---|---|---|
| `WRAPSEC_URL` | `http://localhost:8000` | Base URL of your WrapSec instance |
| `WRAPSEC_API_KEY` | `wsk_live_changeme` | Live API key for scan/audit endpoints |
| `WRAPSEC_ADMIN_JWT` | _(empty)_ | Admin JWT for write tests (PUT settings, create/delete keys) |
| `WRAPSEC_TIMEOUT` | `30` | Request timeout in seconds |
| `SKIP_PROXY_TESTS` | `true` | Set to `false` to test proxy endpoint (needs LLM provider) |
| `SKIP_ADMIN_TESTS` | `true` | Set to `false` to test admin write operations |
| `SKIP_SDK_TESTS` | `false` | Set to `true` to skip Python SDK tests |
| `SKIP_CLI_TESTS` | `false` | Set to `true` to skip CLI tests |
| `VERBOSE` | `false` | Set to `true` to print response bodies on failures |
| `TEST_DELAY_MS` | `0` | Milliseconds between requests (use 200+ to avoid rate limits) |

## Run individual test files

```bash
# API tests
bash tests/manual/api/01_health.sh
bash tests/manual/api/02_scan.sh
bash tests/manual/api/03_audit.sh
bash tests/manual/api/04_proxy.sh       # needs SKIP_PROXY_TESTS=false
bash tests/manual/api/05_settings.sh
bash tests/manual/api/06_keys.sh

# CLI tests (requires: pip install -e sdk/python/ and wrapsec in PATH)
bash tests/manual/cli/01_config.sh
bash tests/manual/cli/02_health.sh
bash tests/manual/cli/03_scan.sh
bash tests/manual/cli/04_batch.sh
bash tests/manual/cli/05_audit.sh
bash tests/manual/cli/06_settings.sh
bash tests/manual/cli/07_keys.sh

# Python SDK tests
python3 tests/manual/sdk/test_python.py
```

## Output format

Each test prints a coloured PASS / FAIL / SKIP line:

```
== Section Name ==
  PASS  test description
  FAIL  test description
        expected HTTP 200, got HTTP 404
  SKIP  test description  (reason)

  Passed: 12  Failed: 1  Skipped: 2
```

Exit codes follow the same convention as the CLI:
- `0` all tests passed
- `1` one or more tests failed

## CLI tests setup

Install the Python SDK in development mode, then verify the `wrapsec` command is available:

```bash
pip install -e sdk/python/
wrapsec --version
```

Then configure it:

```bash
wrapsec config set api_key wsk_live_...
wrapsec config set base_url http://localhost:8000
```

## Admin tests

Admin tests require a JWT obtained from the login endpoint:

```bash
export WRAPSEC_ADMIN_JWT=$(curl -s -X POST "${WRAPSEC_URL}/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"yourpassword"}' \
  | jq -r '.access_token')

SKIP_ADMIN_TESTS=false bash tests/manual/run_all.sh
```

## Proxy tests

Proxy tests require a configured LLM provider (OpenAI, Ollama, etc.) and a proxy provider config for the API key in use. See the WrapSec dashboard to configure a provider.

```bash
SKIP_PROXY_TESTS=false bash tests/manual/run_all.sh
```

## Fixtures

`tests/manual/fixtures/batch_mixed.txt` contains a curated set of prompts covering all expected decisions:

- Safe inputs (expect ALLOW)
- Prompt injection (expect BLOCK)
- Jailbreak attempts (expect BLOCK)
- PII inputs (expect SANITIZE)
- Malicious intent (expect BLOCK)

Use this file with `wrapsec batch` or the batch CLI tests.
