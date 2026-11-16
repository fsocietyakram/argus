#!/usr/bin/env bash
#
# ARGUS installer / checker for Kali Linux (and other Debian-based systems).
# Zero npm dependencies: this script only verifies Node.js, makes the launchers
# executable, and optionally links the CLI into ~/.local/bin.
#
# Usage:
#   ./install.sh                  check environment and set permissions
#   ./install.sh --with-node      install Node.js + npm with apt (needs root/sudo)
#   ./install.sh --link           symlink ./argus.sh to ~/.local/bin/argus
#   ./install.sh --with-node --link
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

WITH_NODE=0
LINK=0
MIN_MAJOR=18

for arg in "$@"; do
  case "$arg" in
    --with-node) WITH_NODE=1 ;;
    --link) LINK=1 ;;
    -h|--help)
      sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: $arg (try --help)" >&2
      exit 2
      ;;
  esac
done

say() { printf '\033[36m[argus]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[argus]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m[argus]\033[0m %s\n' "$*" >&2; exit 1; }

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    fail "Root privileges are required to run: $*"
  fi
}

node_major() {
  node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0
}

check_node() {
  if ! command -v node >/dev/null 2>&1; then
    return 1
  fi
  local major
  major="$(node_major)"
  if [ "${major:-0}" -lt "$MIN_MAJOR" ]; then
    warn "Node.js $(node -v 2>/dev/null || echo unknown) is too old; ARGUS needs Node ${MIN_MAJOR}+."
    return 1
  fi
  say "Node.js $(node -v) detected at $(command -v node)"
  return 0
}

if ! check_node; then
  if [ "$WITH_NODE" -eq 1 ]; then
    say "Installing Node.js and npm with apt…"
    as_root apt-get update
    as_root apt-get install -y nodejs npm
    if ! check_node; then
      warn "The distribution packages are older than Node ${MIN_MAJOR}."
      warn "Use NodeSource or nvm instead, for example:"
      warn "  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -"
      warn "  sudo apt-get install -y nodejs"
      fail "Please install Node.js ${MIN_MAJOR}+ and run ./install.sh again."
    fi
  else
    warn "Node.js ${MIN_MAJOR}+ is required but was not found."
    warn "On Kali/Debian you can try:"
    warn "  sudo apt-get update && sudo apt-get install -y nodejs npm"
    warn "  ./install.sh --with-node"
    warn "If apt ships an old version, use NodeSource:"
    warn "  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -"
    warn "  sudo apt-get install -y nodejs"
    exit 1
  fi
fi

say "Setting executable permissions…"
chmod +x argus.mjs argus.sh install.sh

say "Running a quick self-check…"
node argus.mjs version >/dev/null
node --input-type=module -e "await import('./src/server.mjs'); await import('./src/username.mjs'); await import('./src/exif.mjs')" \
  && say "All core modules load."

mkdir -p reports data
say "Created local reports/ and data/ directories (git-ignored)."

if [ "$LINK" -eq 1 ]; then
  TARGET_DIR="${HOME}/.local/bin"
  mkdir -p "$TARGET_DIR"
  ln -sf "$SCRIPT_DIR/argus.sh" "$TARGET_DIR/argus"
  say "Linked $TARGET_DIR/argus"
  case ":$PATH:" in
    *":$TARGET_DIR:"*) ;;
    *) warn "Add $TARGET_DIR to your PATH, e.g.: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc" ;;
  esac
fi

cat <<EOF

$(printf '\033[32m[argus]\033[0m') Installation check complete.

  CLI        ./argus.sh help
             ./argus.sh username example
             ./argus.sh serve --open

  Web UI     ./argus.sh serve
             http://127.0.0.1:8787/   (loopback only)

  Tests      npm test

  Optional   export HIBP_API_KEY="..."   # enables breach-metadata checks

Use ARGUS only on public information and files you are authorised to examine.
Reports are written to ./reports and the audit log to ./data/audit.jsonl.
EOF
