#!/usr/bin/env bash
# FaultWall Break-Me Launcher
# ----------------------------
# Starts Postgres + FaultWall proxy + seeds fake-PII DB.
# Tester connects via port 5433 (proxy), NOT 5432 (direct).
#
# Reset between testers:  ./dev/breakme.sh reset
# Teardown:              ./dev/breakme.sh down

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# Colors
GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() {
  echo -e "${CYAN}${BOLD}"
  echo "╔════════════════════════════════════════════════════════════════╗"
  echo "║ FAULTWALL BREAK-ME ║"
  echo "║              Break My AI · Novita · SF · Apr 24                ║"
  echo "╚════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

cmd="${1:-up}"

case "$cmd" in
  down)
    echo -e "${RED}Tearing down...${NC}"
    docker compose down -v
    exit 0
    ;;

  reset)
    echo -e "${CYAN}Resetting seed data...${NC}"
    docker compose exec -T postgres psql -U ghost -d faultwall_demo < dev/breakme-seed.sql
    echo -e "${GREEN}ok Reset complete. Fresh fake-PII DB.${NC}"
    exit 0
    ;;

  up|"")
    banner
    echo -e "${CYAN}[1/4]${NC} Starting Postgres + FaultWall proxy..."
    docker compose up -d --build

    echo -e "${CYAN}[2/4]${NC} Waiting for Postgres to be healthy..."
    for i in {1..30}; do
      if docker compose exec -T postgres pg_isready -U ghost -d faultwall_demo >/dev/null 2>&1; then
        echo -e "${GREEN} ok Postgres ready${NC}"
        break
      fi
      sleep 1
    done

    echo -e "${CYAN}[3/4]${NC} Seeding fake-PII data..."
    docker compose exec -T postgres psql -U ghost -d faultwall_demo < dev/breakme-seed.sql

    echo -e "${CYAN}[4/4]${NC} Waiting for FaultWall proxy..."
    sleep 2

    echo
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}${BOLD} READY TO BE BROKEN ${NC}"
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    echo -e "${BOLD}Tester connection string (paste into any psql/tool):${NC}"
    echo
    echo -e "   ${CYAN}postgres://ghost:ghostpass@localhost:5433/faultwall_demo?application_name=agent:cursor-ai:mission:summarize-feedback:token:cursor-secret-123${NC}"
    echo
    echo -e "${BOLD}Dashboard:${NC}  ${CYAN}http://localhost:8080${NC}"
    echo -e "${BOLD}Live log:${NC}   docker compose logs -f faultwall-proxy"
    echo -e "${BOLD}Reset DB:${NC}   ./dev/breakme.sh reset"
    echo -e "${BOLD}Tear down:${NC}  ./dev/breakme.sh down"
    echo
    echo -e "${BOLD}Pro tip:${NC} open 3 terminals:"
    echo -e "  ${CYAN}1)${NC} tester's psql     ${CYAN}2)${NC} \`docker compose logs -f faultwall-proxy\`     ${CYAN}3)${NC} dashboard in browser"
    echo
    echo -e "${RED}${BOLD}Give testers INJECTIONS.md and watch the wall work.${NC}"
    echo
    ;;

  *)
    echo "Usage: ./dev/breakme.sh [up|reset|down]"
    exit 1
    ;;
esac
