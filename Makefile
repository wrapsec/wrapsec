.PHONY: run test test-integration test-e2e build up down seed lint format migrate migration typecheck semgrep coverage

run:
	uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/unit tests/integration -v

# Integration tests against a DISPOSABLE Postgres AND Redis. Spins an
# ephemeral postgres:16-alpine on port 55432 and redis:7-alpine on 56379
# (both clear of the compose stack on 5432/6379), points the app and the
# tests at them, then removes both -- even if the tests fail.
#
# Redis is provisioned for the same reason Postgres is. Left to the
# environment it resolves to the development instance, so a test run wrote
# its rate-limit counters, caches and idempotency keys into the database a
# developer is using, and the tier passed or failed depending on what was
# already in there. Both stores are now throwaway, which is also what the CI
# job provides. Requires Docker; without it the integration tier skips
# gracefully under plain `make test`.
test-integration:
	@bash -c 'set -e; \
	cleanup() { docker rm -f $$CID $$RID >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT; \
	CID=$$(docker run --rm -d -e POSTGRES_USER=wrapsec -e POSTGRES_PASSWORD=wrapsec -e POSTGRES_DB=wrapsec_test -p 55432:5432 postgres:16-alpine); \
	RID=$$(docker run --rm -d -p 56379:6379 redis:7-alpine); \
	echo "waiting for the disposable postgres and redis..."; \
	for i in $$(seq 1 30); do docker exec $$CID pg_isready -U wrapsec -d wrapsec_test >/dev/null 2>&1 && break; sleep 1; done; \
	for i in $$(seq 1 30); do docker exec $$RID redis-cli ping >/dev/null 2>&1 && break; sleep 1; done; \
	URL=postgresql+asyncpg://wrapsec:wrapsec@localhost:55432/wrapsec_test; \
	DATABASE_URL=$$URL WRAPSEC_TEST_PG_URL=$$URL REDIS_URL=redis://localhost:56379/0 TESTING=true pytest tests/integration -v'

# End-to-end browser journeys against an EPHEMERAL stack. Brings up postgres,
# redis, api, and dashboard under their own compose project (separate
# containers, network, and volumes), migrates into an empty database, seeds the
# dedicated e2e accounts, runs the suite against localhost:3100, then destroys
# the stack and its data -- even if the tests fail. The development stack and
# its database are never touched.
#
# The images are REBUILT every run. Everything else here is thrown away, which
# made the images easy to overlook: `up -d` alone builds only when no image
# exists, so a run reused whatever was built last and the tier silently
# reported on stale code. That fails in the dangerous direction -- an old image
# passes while the working tree is broken.
#
# Requires the browser and its system libraries:
#   cd dashboard && npx playwright install chromium chromium-headless-shell
#   cd dashboard && sudo npx playwright install-deps chromium
test-e2e:
	@bash -c 'set -e; \
	R="$$(pwd)"; \
	P="docker compose -p wrapsec-e2e -f $$R/infrastructure/docker/docker-compose.yml -f $$R/infrastructure/docker/docker-compose.e2e.yml"; \
	trap "echo tearing down the ephemeral stack...; $$P down -v --remove-orphans || echo TEARDOWN FAILED -- remove wrapsec-e2e by hand" EXIT; \
	echo "starting the ephemeral stack..."; \
	$$P up -d --build postgres redis api dashboard; \
	echo "waiting for the api to report healthy..."; \
	HEALTH="docker inspect --format {{.State.Health.Status}}"; \
	for i in $$(seq 1 60); do \
	  [ "$$($$HEALTH $$($$P ps -q api) 2>/dev/null)" = "healthy" ] && break; \
	  sleep 5; \
	done; \
	test "$$($$HEALTH $$($$P ps -q api) 2>/dev/null)" = "healthy" \
	  || { echo "api never became healthy"; $$P logs --tail 50 api; exit 1; }; \
	echo "waiting for the dashboard to serve /login..."; \
	for i in $$(seq 1 40); do curl -sf http://localhost:3100/login >/dev/null 2>&1 && break; sleep 3; done; \
	curl -sf http://localhost:3100/login >/dev/null \
	  || { echo "dashboard never served /login"; $$P logs --tail 50 dashboard; exit 1; }; \
	echo "seeding the e2e accounts..."; \
	$$P exec -T api python scripts/seed_e2e_user.py; \
	echo "running the source-network round trip..."; \
	$$P exec -T api python - < $$R/scripts/e2e_ip_allowlist.py; \
	echo "running the e2e suite..."; \
	( cd dashboard && PLAYWRIGHT_BASE_URL=http://localhost:3100 npx playwright test )'

# Combined unit + integration coverage over the server code (config in .coveragerc).
# Spins a disposable PostgreSQL and Redis so the integration tier runs against
# throwaway stores rather than the development ones. Writes an HTML report.
# `coverage report` enforces fail_under, so this is the local form of the gate.
coverage:
	@bash -c 'set -e; \
	cleanup() { docker rm -f $$CID $$RID >/dev/null 2>&1 || true; }; \
	trap cleanup EXIT; \
	CID=$$(docker run --rm -d -e POSTGRES_USER=wrapsec -e POSTGRES_PASSWORD=wrapsec -e POSTGRES_DB=wrapsec_test -p 55432:5432 postgres:16-alpine); \
	RID=$$(docker run --rm -d -p 56379:6379 redis:7-alpine); \
	for i in $$(seq 1 30); do docker exec $$CID pg_isready -U wrapsec -d wrapsec_test >/dev/null 2>&1 && break; sleep 1; done; \
	for i in $$(seq 1 30); do docker exec $$RID redis-cli ping >/dev/null 2>&1 && break; sleep 1; done; \
	URL=postgresql+asyncpg://wrapsec:wrapsec@localhost:55432/wrapsec_test; \
	DATABASE_URL=$$URL WRAPSEC_TEST_PG_URL=$$URL REDIS_URL=redis://localhost:56379/0 TESTING=true coverage run -m pytest tests/unit tests/integration -q; \
	coverage html; \
	coverage report'

# Apply pending Alembic migrations. Also runs automatically on API startup.
migrate:
	alembic upgrade head

# Generate a new autogenerated migration.
# Usage: make migration MSG="add webhook_signing_secret table"
migration:
	alembic revision --autogenerate -m "$(MSG)"

# The gated corpus and its regression guard, then the assistant-prose
# measurement. The latter reports and never fails: assistant scanning is off by
# default, so its cost is something to watch rather than something to block on.
# It runs here so the number stays in front of whoever runs the evaluation.
eval:
	python tests/eval/run_evaluation.py
	pytest tests/eval/test_redteam.py -v
	python tests/eval/run_assistant_eval.py

build:
	docker compose -f infrastructure/docker/docker-compose.yml build

up:
	@bash scripts/write_metrics_token.sh
	docker compose -f infrastructure/docker/docker-compose.yml up -d

down:
	docker compose -f infrastructure/docker/docker-compose.yml down

up-dev:
	docker compose -f infrastructure/docker/docker-compose.yml up -d postgres redis

logs:
	docker compose -f infrastructure/docker/docker-compose.yml logs -f

seed:
	python scripts/seed_data.py

lint:
	ruff check .

format:
	ruff format .

# Static type checking, scoped to the Python SDK (config in the repo root).
typecheck:
	pyright

# Static application-security scan (Semgrep). NOT a required PR gate -- it runs on
# a schedule / on demand via .github/workflows/security-semgrep.yml. The p/*
# rulesets are fetched live from the Semgrep registry, so the same pinned binary
# returns different findings from one run to the next (non-deterministic); its
# findings are reviewed, not merge-blocking. Path excludes live in .semgrepignore;
# --error fails the run on any finding.
#
# Two rules are excluded deliberately (each verified 100% false-positive here):
#   * detected-stripe-api-key -- WrapSec has no Stripe integration; the rule only
#     ever matches our own wsk_live_* API-key format in test fixtures (pattern
#     collision), so it can never produce a true positive.
#   * logger-credential-disclosure -- fires on auth_event log TEMPLATES that
#     contain credential words while the code logs identifiers (user_id, trace_id,
#     reason), never secret data (verified line-by-line); the log scrubber is the
#     actual control.
# Remaining one-off false positives carry an inline `# nosemgrep: <rule>` reason.
#
# The scheduled workflow and local runs use this SAME target. On Windows run it
# via Docker:
#   docker run --rm -v "$$PWD:/src" -w /src semgrep/semgrep:1.172.0 semgrep scan $(SEMGREP_RULES) $(SEMGREP_SKIP) --error --metrics off .
SEMGREP_RULES := --config p/python --config p/security-audit --config p/secrets
SEMGREP_SKIP  := --exclude-rule generic.secrets.security.detected-stripe-api-key.detected-stripe-api-key --exclude-rule python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure
semgrep:
	semgrep scan $(SEMGREP_RULES) $(SEMGREP_SKIP) --error --metrics off .

# Reproduce the OS-divergent CI checks (Linux ruff + dashboard build) in Docker
# before pushing, so Windows-invisible failures (e.g. ruff EXE001) surface early.
# The other gates run faster locally: make typecheck / coverage / eval.
ci-local:
	bash scripts/ci-local.sh

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete