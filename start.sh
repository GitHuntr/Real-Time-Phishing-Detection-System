#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  PhishGuard — One-Command Launcher (Debian / Ubuntu)
#  Usage: bash start.sh
# ══════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
VENV_DIR="$SCRIPT_DIR/.venv"
PORT=8000
URL="http://localhost:$PORT"

# ── Colors ────────────────────────────────────────────────────────
CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

step() { echo -e "\n  ${CYAN}▶${RESET}  $1"; }
ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}   $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; exit 1; }

# ── Banner ────────────────────────────────────────────────────────
echo -e "\n${CYAN}${BOLD}"
echo "  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗"
echo "  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗"
echo "  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║"
echo "  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║"
echo "  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝"
echo "  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝"
echo -e "${RESET}  ${CYAN}Real-Time Phishing Detection  •  Debian Edition${RESET}\n"

# ── 1. Python check ───────────────────────────────────────────────
step "Checking Python 3..."
if ! command -v python3 &>/dev/null; then
  err "python3 not found. Run: sudo apt install python3"
fi
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
if [ "$PY_MINOR" -lt 9 ]; then
  err "Python 3.9+ required. Found: $PY_VER"
fi
ok "Python $PY_VER"

# ── 2. Debian system packages ─────────────────────────────────────
step "Checking Debian system packages..."

MISSING_PKGS=()

# python3-venv: needed for 'python3 -m venv'
if ! python3 -c "import ensurepip" &>/dev/null; then
  MISSING_PKGS+=("python3-venv")
fi

# python3-dev: needed to compile C extensions (shap, xgboost deps)
if ! dpkg -s python3-dev &>/dev/null 2>&1; then
  MISSING_PKGS+=("python3-dev")
fi

# build-essential: gcc/g++ for compiling native extensions
if ! command -v gcc &>/dev/null; then
  MISSING_PKGS+=("build-essential")
fi

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
  warn "Missing apt packages: ${MISSING_PKGS[*]}"
  echo -e "  ${YELLOW}Installing via apt (requires sudo)...${RESET}"
  sudo apt-get update -qq
  sudo apt-get install -y -qq "${MISSING_PKGS[@]}"
  ok "System packages installed"
else
  ok "System packages already present"
fi

# ── 3. Virtual environment ────────────────────────────────────────
step "Setting up virtual environment..."

if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
  ok "Virtual environment created at .venv/"
else
  ok "Virtual environment exists — reusing"
fi

# Activate
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
ok "Virtual environment activated"

# ── 4. Install Python dependencies ───────────────────────────────
STAMP="$VENV_DIR/.pg_installed"
REQ="$BACKEND_DIR/requirements.txt"

if [ ! -f "$STAMP" ] || [ "$REQ" -nt "$STAMP" ]; then
  step "Installing Python dependencies (this may take 2–3 min on first run)..."
  echo -e "  ${CYAN}Upgrading pip...${RESET}"
  pip install --quiet --upgrade pip wheel setuptools

  echo -e "  ${CYAN}Installing packages from requirements.txt...${RESET}"
  pip install --quiet -r "$REQ"

  touch "$STAMP"
  ok "All dependencies installed"
else
  ok "Dependencies up to date (skipping reinstall)"
fi

# ── 5. Create models directory ────────────────────────────────────
mkdir -p "$BACKEND_DIR/models"

# ── 6. Check if model exists ─────────────────────────────────────
if [ ! -f "$BACKEND_DIR/models/phishguard_model.pkl" ]; then
  warn "No trained model found — running in rule-based fallback mode"
  echo -e "  ${YELLOW}To train a model with a dataset:${RESET}"
  echo -e "  ${CYAN}  python backend/model_trainer.py --data data/dataset.csv${RESET}"
else
  ok "Trained model found"
fi

# ── 7. Open browser ───────────────────────────────────────────────
(
  sleep 2
  if command -v xdg-open &>/dev/null && [ -n "${DISPLAY:-}" ]; then
    xdg-open "$URL" &>/dev/null &
  elif command -v sensible-browser &>/dev/null; then
    sensible-browser "$URL" &>/dev/null &
  fi
) &

# ── 8. Start server ───────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${BOLD}${GREEN}  PhishGuard is live!${RESET}"
echo -e "  ${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${CYAN}Dashboard :${RESET}  $URL"
echo -e "  ${CYAN}API Docs  :${RESET}  $URL/docs"
echo -e "  ${CYAN}Health    :${RESET}  $URL/health"
echo -e ""
echo -e "  Press ${BOLD}Ctrl+C${RESET} to stop"
echo ""

cd "$BACKEND_DIR"
exec uvicorn main:app \
  --host 0.0.0.0 \
  --port "$PORT" \
  --reload \
  --reload-dir "$BACKEND_DIR" \
  --log-level info
