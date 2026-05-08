#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# NetWatch v4 — Quick Start Script
# Usage:
#   ./start.sh           → normal mode (requires root for packet capture)
#   ./start.sh --demo    → demo mode with synthetic traffic (no root needed)
#   ./start.sh --help    → show options
# ─────────────────────────────────────────────────────────────────────────────

set -e

CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"
BOLD="\033[1m"

log()  { echo -e "${CYAN}[netwatch]${RESET} $*"; }
ok()   { echo -e "${GREEN}[  ok  ]${RESET} $*"; }
warn() { echo -e "${YELLOW}[ warn ]${RESET} $*"; }
err()  { echo -e "${RED}[ error]${RESET} $*"; exit 1; }

DEMO=false
INTERFACE=""
PORT=5000
UI_PORT=5173
NO_FRONTEND=false

for arg in "$@"; do
  case $arg in
    --demo)        DEMO=true ;;
    --interface=*) INTERFACE="${arg#*=}" ;;
    --port=*)      PORT="${arg#*=}" ;;
    --no-frontend) NO_FRONTEND=true ;;
    --help|-h)
      echo ""
      echo -e "${BOLD}NetWatch v4 — Quick Start${RESET}"
      echo ""
      echo "  Usage: ./start.sh [options]"
      echo ""
      echo "  Options:"
      echo "    --demo              Run with synthetic traffic (no root required)"
      echo "    --interface=eth0    Capture on specific interface"
      echo "    --port=5000         Backend port (default: 5000)"
      echo "    --no-frontend       Start only the backend"
      echo "    --help              Show this help"
      echo ""
      echo "  Examples:"
      echo "    ./start.sh --demo"
      echo "    sudo ./start.sh --interface=eth0"
      echo "    docker compose up"
      echo ""
      exit 0
      ;;
  esac
done

echo ""
echo -e "${BOLD}${CYAN}  ⬡  NetWatch v4${RESET}"
echo -e "${CYAN}  Network Monitor & Security Tool${RESET}"
echo ""

# ── Check root for capture ───────────────────────────────────────────────────
if [[ "$DEMO" == "false" && "$EUID" -ne 0 ]]; then
  warn "Not running as root. Packet capture may fail."
  warn "Use: sudo ./start.sh  or  ./start.sh --demo"
  echo ""
fi

# ── Python virtualenv ─────────────────────────────────────────────────────────
if [[ ! -d "venv" ]]; then
  log "Creating Python virtualenv…"
  python3 -m venv venv
fi

log "Activating virtualenv and installing dependencies…"
source venv/bin/activate
pip install -q -r requirements.txt
ok "Python dependencies ready"

# ── Build capture binary ──────────────────────────────────────────────────────
if [[ "$DEMO" == "false" && ! -f "capture/packet_capture" ]]; then
  log "Compiling packet capture binary…"
  if command -v g++ &>/dev/null && pkg-config --libs libpcap &>/dev/null 2>&1; then
    g++ -O2 -o capture/packet_capture capture/packet_capture.cpp -lpcap
    ok "Capture binary compiled"
  else
    warn "g++ or libpcap not found — will fall back to demo mode"
    DEMO=true
  fi
fi

# ── Frontend ──────────────────────────────────────────────────────────────────
if [[ "$NO_FRONTEND" == "false" ]]; then
  if [[ -d "dashboard" ]]; then
    log "Installing frontend dependencies…"
    cd dashboard
    if [[ ! -d "node_modules" ]]; then
      npm install --silent
    fi
    ok "Frontend ready"
    # Start Vite dev server in background
    VITE_API_BASE="http://localhost:${PORT}/api" npm run dev -- --port $UI_PORT &
    VITE_PID=$!
    cd ..
    ok "Frontend started at ${GREEN}http://localhost:${UI_PORT}${RESET}"
  fi
fi

# ── Copy .env if needed ───────────────────────────────────────────────────────
if [[ ! -f ".env" && -f ".env.example" ]]; then
  cp .env.example .env
  warn "Created .env from .env.example — review credentials before production use"
fi

# Load .env
if [[ -f ".env" ]]; then
  export $(grep -v '^#' .env | grep -v '^$' | xargs) 2>/dev/null || true
fi

# ── Start backend ─────────────────────────────────────────────────────────────
echo ""
log "Starting NetWatch backend…"
echo -e "  ${CYAN}→${RESET} API:      ${GREEN}http://localhost:${PORT}${RESET}"
echo -e "  ${CYAN}→${RESET} Frontend: ${GREEN}http://localhost:${UI_PORT}${RESET}"
echo -e "  ${CYAN}→${RESET} Demo:     ${YELLOW}${DEMO}${RESET}"
echo -e "  ${CYAN}→${RESET} Auth:     ${GREEN}admin / netwatch${RESET} (cambia subito!)"
echo ""

ARGS="--port $PORT"
[[ "$DEMO" == "true"     ]] && ARGS="$ARGS --demo"
[[ -n "$INTERFACE"       ]] && ARGS="$ARGS --interface $INTERFACE"

# Trap Ctrl+C to kill all background processes
cleanup() {
  echo ""
  log "Shutting down…"
  [[ -n "$VITE_PID" ]] && kill "$VITE_PID" 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM

python server.py $ARGS
