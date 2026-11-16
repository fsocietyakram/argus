#!/usr/bin/env bash
#
# Portable ARGUS launcher for Kali Linux, Debian, and other Unix-like systems.
# Keeps the current working directory, so relative file paths work naturally.
#
set -euo pipefail

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v node >/dev/null 2>&1; then
  echo "ARGUS needs Node.js 18+. On Kali/Debian: sudo apt-get install -y nodejs npm" >&2
  echo "If apt ships an old version, use NodeSource: https://github.com/nodesource/distributions" >&2
  exit 1
fi

MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
if [ "${MAJOR:-0}" -lt 18 ]; then
  echo "ARGUS needs Node.js 18+; found $(node -v 2>/dev/null || echo unknown)." >&2
  exit 1
fi

exec node "$DIR/argus.mjs" "$@"
