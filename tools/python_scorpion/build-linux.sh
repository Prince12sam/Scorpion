#!/usr/bin/env bash
set -euo pipefail

NAME="scorpion"
ENTRY="runner.py"

echo "Building $NAME (Linux onefile)"

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "PyInstaller not found. Installing into current environment..."
  pip install --user pyinstaller
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

pyinstaller --noconfirm --onefile --name "$NAME" "$ENTRY"

echo "Build complete. Binary at: $SCRIPT_DIR/dist/$NAME"
