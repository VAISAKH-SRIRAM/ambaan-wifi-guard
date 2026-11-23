#!/usr/bin/env bash
# Ambaan 3.0 Network Intelligence & Diagnostic Analyzer Launcher

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "================================================="
echo "   Running Ambaan 3.0 Diagnostic Analyzer"
echo "================================================="

if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python 3 is required. Please install it with:"
    echo "        sudo apt update && sudo apt install -y python3"
    exit 1
fi

python3 "$DIR/ambaan_analyzer.py" "$@"
