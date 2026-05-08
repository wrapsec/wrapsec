#!/usr/bin/env bash
# WrapSec setup
#
# Usage:
#   ./setup.sh           — start in development mode (default)
#   ./setup.sh --prod    — start in production mode
#   ./setup.sh --build   — force rebuild images
#   ./setup.sh --down    — stop and remove all containers
#
set -euo pipefail

COMPOSE_DEV="docker compose -f infrastructure/docker/docker-compose.yml"
COMPOSE_PROD="docker compose -f infrastructure/docker/docker-compose.prod.yml"

# ── Colours ───────────────────────────────────────────────────────────────────
GREEN="\033[0;32m"; YELLOW="\033[1;33m"; RED="\033[0;31m"; CYAN="\033[0;36m"; NC="\033[0m"
info()  { echo -e "${GREEN}[wrapsec]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}    $*"; }
die()   { echo -e "${RED}[error]${NC}   $*" >&2; exit 1; }

# ── Parse flags ───────────────────────────────────────────────────────────────
MODE="dev"
BUILD_FLAG=""
for arg in "$@"; do
    case $arg in
        --prod)  MODE="prod" ;;
        --dev)   MODE="dev" ;;
        --build) BUILD_FLAG="--build" ;;
        --down)
            info "Stopping all containers..."
            $COMPOSE_DEV down 2>/dev/null || true
            $COMPOSE_PROD down 2>/dev/null || true
            exit 0
            ;;
    esac
done

# ── Prerequisites ─────────────────────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || die "Docker not found — https://docs.docker.com/get-docker/"
docker info >/dev/null 2>&1       || die "Docker daemon is not running"

# ─────────────────────────────────────────────────────────────────────────────
# PRODUCTION MODE
# ─────────────────────────────────────────────────────────────────────────────
if [ "$MODE" = "prod" ]; then

    echo ""
    echo -e "${YELLOW}  WrapSec — Production Mode${NC}"
    echo ""

    [ -f .env ] || die ".env not found. Copy .env.example, fill in production values, then re-run."

    # Required production values
    grep -q "your-secret-key-minimum-32-characters-here" .env \
        && die "SECRET_KEY is still the default. Generate one: openssl rand -hex 32"

    POSTGRES_PASSWORD=$(grep "^POSTGRES_PASSWORD=" .env | cut -d= -f2- | tr -d '"')
    REDIS_PASSWORD=$(grep "^REDIS_PASSWORD=" .env | cut -d= -f2- | tr -d '"')
    GRAFANA_PASSWORD=$(grep "^GRAFANA_PASSWORD=" .env | cut -d= -f2- | tr -d '"')

    [ -z "$POSTGRES_PASSWORD" ] && die "POSTGRES_PASSWORD not set in .env"
    [ -z "$REDIS_PASSWORD" ]    && die "REDIS_PASSWORD not set in .env"
    [ -z "$GRAFANA_PASSWORD" ]  && die "GRAFANA_PASSWORD not set in .env"

    # SSL detection
    SSL_CERT=$(grep "^SSL_CERT_PATH=" .env | cut -d= -f2- | tr -d '"')
    SSL_KEY=$(grep "^SSL_KEY_PATH=" .env | cut -d= -f2- | tr -d '"')
    DOMAIN=$(grep "^DOMAIN=" .env | cut -d= -f2- | tr -d '"')

    if [ -n "$SSL_CERT" ] && [ -n "$SSL_KEY" ]; then
        [ -f "$SSL_CERT" ] || die "SSL_CERT_PATH set but file not found: $SSL_CERT"
        [ -f "$SSL_KEY" ]  || die "SSL_KEY_PATH set but file not found: $SSL_KEY"
        SSL_MODE=true
        info "SSL enabled — certificates found"
    else
        SSL_MODE=false
        warn "SSL not configured — running HTTP only"
        warn "To enable SSL, set SSL_CERT_PATH and SSL_KEY_PATH in .env"
    fi

    # Select nginx config
    REPO_ROOT=$(pwd)
    if [ "$SSL_MODE" = true ]; then
        # Generate nginx config from template with envsubst
        NGINX_HOST="${DOMAIN:-$(hostname -I | awk '{print $1}')}"
        NGINX_CONF_FILE="$REPO_ROOT/infrastructure/nginx/nginx.prod.generated.conf"
        export NGINX_HOST SSL_CERT_PATH="$SSL_CERT" SSL_KEY_PATH="$SSL_KEY"
        envsubst '${NGINX_HOST} ${SSL_CERT_PATH} ${SSL_KEY_PATH}' \
            < "$REPO_ROOT/infrastructure/nginx/templates/default.conf.template" \
            > "$NGINX_CONF_FILE"
        export NGINX_CONF="$NGINX_CONF_FILE"
    else
        export NGINX_CONF="$REPO_ROOT/infrastructure/nginx/nginx.http.conf"
        export SSL_CERT_PATH="" SSL_KEY_PATH=""
    fi

    export POSTGRES_PASSWORD REDIS_PASSWORD GRAFANA_PASSWORD

    info "Building and starting WrapSec (production)..."
    $COMPOSE_PROD up -d --build $BUILD_FLAG

    # Wait for health via port 80 (HTTP or SSL redirect)
    info "Waiting for API to be ready..."
    RETRIES=30
    until curl -sf http://localhost/health >/dev/null 2>&1; do
        RETRIES=$((RETRIES - 1))
        [ $RETRIES -eq 0 ] && die "API did not become healthy. Check: $COMPOSE_PROD logs api"
        sleep 2
    done

    echo ""
    echo -e "${GREEN}WrapSec is running in PRODUCTION mode.${NC}"
    echo ""
    if [ "$SSL_MODE" = true ]; then
        BASE="${DOMAIN:-localhost}"
        echo -e "  ${CYAN}API:${NC}         https://${BASE}/v1"
        echo -e "  ${CYAN}Dashboard:${NC}   https://${BASE}:3000"
    else
        echo -e "  ${CYAN}API:${NC}         http://localhost/v1"
        echo -e "  ${CYAN}Dashboard:${NC}   http://localhost:3000"
    fi
    echo -e "  ${CYAN}Grafana:${NC}     http://localhost:3001  (SSH tunnel recommended)"
    echo ""
    echo -e "  ${CYAN}View logs:${NC}   $COMPOSE_PROD logs -f"
    echo -e "  ${CYAN}Stop:${NC}        ./setup.sh --down"
    echo -e "  ${CYAN}Rebuild:${NC}     ./setup.sh --prod --build"
    echo ""

# ─────────────────────────────────────────────────────────────────────────────
# DEVELOPMENT MODE
# ─────────────────────────────────────────────────────────────────────────────
else

    echo ""
    echo -e "${CYAN}  WrapSec — Development Mode${NC}"
    echo ""

    if [ ! -f .env ]; then
        cp .env.example .env
        SECRET=$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 64 | head -n 1)
        sed -i "s/your-secret-key-minimum-32-characters-here/${SECRET}/" .env
        warn ".env created from .env.example"
    else
        info ".env found"
    fi

    info "Building images and starting WrapSec (dev)..."
    $COMPOSE_DEV up -d --build $BUILD_FLAG

    info "Waiting for API to be ready..."
    RETRIES=30
    until curl -sf http://localhost/health >/dev/null 2>&1; do
        RETRIES=$((RETRIES - 1))
        [ $RETRIES -eq 0 ] && die "API did not become healthy. Check: $COMPOSE_DEV logs api"
        sleep 2
    done

    echo ""
    echo -e "${GREEN}WrapSec is running in DEVELOPMENT mode.${NC}"
    echo ""
    echo -e "  ${CYAN}Dashboard:${NC}   http://localhost:3000"
    echo -e "  ${CYAN}API:${NC}         http://localhost/v1"
    echo -e "  ${CYAN}API docs:${NC}    http://localhost/docs"
    echo -e "  ${CYAN}Grafana:${NC}     http://localhost:3001  ${YELLOW}(change password before production)${NC}"
    echo ""
    echo -e "  ${CYAN}View logs:${NC}   $COMPOSE_DEV logs -f"
    echo -e "  ${CYAN}Stop:${NC}        ./setup.sh --down"
    echo -e "  ${CYAN}Rebuild:${NC}     ./setup.sh --build"
    echo -e "  ${CYAN}Production:${NC}  ./setup.sh --prod"
    echo ""
    echo -e "  ${CYAN}Run tests:${NC}   $COMPOSE_DEV exec api python -m pytest tests/unit tests/integration -v"
    echo ""

fi
