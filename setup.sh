#!/usr/bin/env bash
# WrapSec — setup and start the full stack
#
# Runs everything in Docker: API, Dashboard, Nginx, Postgres, Redis,
# Prometheus, Grafana. Nothing is installed on the host except Docker.
#
# Usage:
#   ./setup.sh          — first-time setup and start
#   ./setup.sh --build  — force rebuild images (after code changes)
#   ./setup.sh --down   — stop and remove all containers
#
set -euo pipefail

COMPOSE="docker compose -f infrastructure/docker/docker-compose.yml"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; CYAN="\033[0;36m"; NC="\033[0m"
info()  { echo -e "${GREEN}[wrapsec]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}   $*"; }
die()   { echo -e "${RED}[error]${NC}  $*" >&2; exit 1; }

# ── Flags ─────────────────────────────────────────────────────────────────────
BUILD_FLAG=""
for arg in "$@"; do
    case $arg in
        --build) BUILD_FLAG="--build" ;;
        --down)
            info "Stopping all containers..."
            $COMPOSE down
            exit 0
            ;;
    esac
done

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "Docker not found — install from https://docs.docker.com/get-docker/"
docker info >/dev/null 2>&1       || die "Docker daemon is not running"

# ── .env ──────────────────────────────────────────────────────────────────────
if [ ! -f .env ]; then
    cp .env.example .env
    # Generate a random SECRET_KEY (no host Python dependency — use /dev/urandom)
    SECRET=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 64 | head -n 1)
    sed -i "s/your-secret-key-minimum-32-characters-here/${SECRET}/" .env
    warn ".env created from .env.example — review settings before use"
    warn "For production deployment, see: docs/deployment.md"
else
    info ".env found"
fi

# ── Build and start ───────────────────────────────────────────────────────────
# Build on first run (images don't exist yet) or when --build is passed
if [ -n "$BUILD_FLAG" ] || ! docker image inspect docker-api >/dev/null 2>&1; then
    info "Building images and starting WrapSec stack..."
    $COMPOSE up -d --build
else
    info "Starting WrapSec stack (use --build to rebuild images)..."
    $COMPOSE up -d
fi

# ── Wait for API ──────────────────────────────────────────────────────────────
info "Waiting for API to be ready..."
RETRIES=30
until curl -sf http://localhost/health >/dev/null 2>&1; do
    RETRIES=$((RETRIES - 1))
    [ $RETRIES -eq 0 ] && die "API did not become healthy in time. Check logs: docker compose -f infrastructure/docker/docker-compose.yml logs api"
    sleep 2
done

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}WrapSec is running.${NC}"
echo ""
echo -e "  ${CYAN}Dashboard:${NC}   http://localhost:3000"
echo -e "  ${CYAN}API:${NC}         http://localhost/v1       (via Nginx)"
echo -e "  ${CYAN}API docs:${NC}    http://localhost/docs"
echo -e "  ${CYAN}Grafana:${NC}     http://localhost:3001     ${YELLOW}(change default password before production)${NC}"
echo ""
echo -e "  ${CYAN}View logs:${NC}   docker compose -f infrastructure/docker/docker-compose.yml logs -f"
echo -e "  ${CYAN}Stop:${NC}        ./setup.sh --down"
echo -e "  ${CYAN}Rebuild:${NC}     ./setup.sh --build"
echo ""
echo -e "  ${CYAN}Run tests:${NC}   docker compose -f infrastructure/docker/docker-compose.yml exec api pytest tests/unit tests/integration -v"
echo ""
