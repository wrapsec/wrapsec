#!/bin/bash
# Stand up the stack, run "$@", and EXIT WITH ITS STATUS. No text inspection.
set -e
cleanup() { kill $UVI 2>/dev/null || true; docker rm -f $CID $RID >/dev/null 2>&1 || true; }
trap cleanup EXIT
SP="${SP:-$(mktemp -d)}"
CID=$(docker run --rm -d -e POSTGRES_USER=wrapsec -e POSTGRES_PASSWORD=wrapsec -e POSTGRES_DB=wrapsec_acc -p 0:5432 postgres:16-alpine -c fsync=off -c synchronous_commit=off)
RID=$(docker run --rm -d -p 0:6379 redis:7-alpine)
PG=$(docker port $CID 5432 | head -1 | sed "s/.*://"); RD=$(docker port $RID 6379 | head -1 | sed "s/.*://")
for i in $(seq 1 40); do docker exec $CID pg_isready -U wrapsec -d wrapsec_acc >/dev/null 2>&1 && break; sleep 1; done
for i in $(seq 1 40); do docker exec $RID redis-cli ping >/dev/null 2>&1 && break; sleep 1; done
export DATABASE_URL="postgresql+asyncpg://wrapsec:wrapsec@127.0.0.1:$PG/wrapsec_acc"
export REDIS_URL="redis://127.0.0.1:$RD/0"
export SECRET_KEY="acceptance_secret_key_padding_12345"
export ADMIN_API_KEY="wrapsec_admin_key_wrapsec_admin_key"
export ENVIRONMENT=development TESTING=false
export PGPORT_ACC=$PG
cd /home/kebi/projects/wrapsec
.venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 18012 > "$SP/api.log" 2>&1 &
UVI=$!
for i in $(seq 1 90); do curl -sf http://127.0.0.1:18012/health/live >/dev/null 2>&1 && break; sleep 1; done
curl -sf http://127.0.0.1:18012/health/live >/dev/null || { echo "API did not start"; tail -15 "$SP/api.log"; exit 1; }
set +e
SP="$SP" API_BASE=http://127.0.0.1:18012 ADMIN_KEY=$ADMIN_API_KEY CID=$CID "$@"
exit $?
