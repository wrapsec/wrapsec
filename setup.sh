#!/usr/bin/env bash
# WrapSec — local development setup
set -euo pipefail

COMPOSE="docker compose -f infrastructure/docker/docker-compose.yml"
VENV=".venv"

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; NC="\033[0m"
info()    { echo -e "${GREEN}[setup]${NC} $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC}  $*"; }
die()     { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v python3 >/dev/null 2>&1 || die "python3 not found"
command -v docker  >/dev/null 2>&1 || die "docker not found"
docker info >/dev/null 2>&1        || die "Docker daemon is not running"

PYTHON_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
[ "$PYTHON_MINOR" -ge 10 ] || die "Python 3.10+ required (found 3.${PYTHON_MINOR})"

# ── Virtual environment ───────────────────────────────────────────────────────
if [ ! -d "$VENV" ]; then
    info "Creating virtual environment at $VENV..."
    python3 -m venv "$VENV"
else
    info "Virtual environment already exists, skipping"
fi

PY="$VENV/bin/python"
PIP="$VENV/bin/pip"

# ── .env ──────────────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    cp .env.example .env
    SECRET=$("$PY" -c "import secrets; print(secrets.token_hex(32))")
    sed -i "s/your-secret-key-minimum-32-characters-here/${SECRET}/" .env
    warn ".env created from .env.example — review before production use"
else
    info ".env already exists, skipping"
fi

# ── Python dependencies ───────────────────────────────────────────────────────
info "Installing Python dependencies..."
"$PIP" install -r requirements.txt -q

# ── ML model ──────────────────────────────────────────────────────────────────
if [ ! -f models/ml_detector.pkl ]; then
    info "Training demo ML model (offline, ~10s)..."
    PYTHONPATH=$(pwd) "$PY" scripts/train_ml_model.py --offline
else
    info "ML model already exists, skipping training"
fi

# ── Infrastructure ────────────────────────────────────────────────────────────
info "Starting PostgreSQL and Redis..."
$COMPOSE up -d postgres redis

info "Waiting for PostgreSQL to be ready..."
until $COMPOSE exec -T postgres pg_isready -U wrapsec -q 2>/dev/null; do
    sleep 1
done

# ── Migrations ────────────────────────────────────────────────────────────────
info "Running database migrations..."
PYTHONPATH=$(pwd) "$VENV/bin/alembic" upgrade head

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}Setup complete.${NC}"
echo ""
echo "  Activate venv:    source $VENV/bin/activate"
echo "  Start API:        PYTHONPATH=\$(pwd) uvicorn api.main:app --reload --port 8000"
echo "  Start dashboard:  cd dashboard && npm run dev"
echo "  Full stack:       docker compose -f infrastructure/docker/docker-compose.yml up -d"
echo "  Run tests:        PYTHONPATH=\$(pwd) TESTING=true pytest tests/unit tests/integration -v"
echo ""
