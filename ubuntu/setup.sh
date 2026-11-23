#!/usr/bin/env bash
# Ambaan 3.0 Ubuntu Environment Setup Script

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "================================================="
echo "   Ambaan 3.0 Linux / Ubuntu Setup & Diagnostics"
echo "================================================="

echo "[*] Granting execution permissions to scripts..."
chmod +x "$DIR"/*.sh 2>/dev/null || true
chmod +x "$DIR"/*.py 2>/dev/null || true

echo "[*] Ensuring required data directories exist..."
mkdir -p "$DIR/MonitorData" "$DIR/Reports" "$DIR/History"

echo "[*] Checking system dependencies..."
MISSING=""

if ! command -v python3 &>/dev/null; then
    MISSING="$MISSING python3"
fi

if ! command -v ip &>/dev/null; then
    MISSING="$MISSING iproute2"
fi

if ! command -v ping &>/dev/null; then
    MISSING="$MISSING iputils-ping"
fi

if ! python3 -c "import tkinter" &>/dev/null; then
    MISSING="$MISSING python3-tk"
fi

if [ -n "$MISSING" ]; then
    echo ""
    echo "[!] Recommended packages missing for full desktop experience:"
    echo "    $MISSING"
    echo ""
    echo "    Install them by running:"
    echo "    sudo apt update && sudo apt install -y$MISSING"
else
    echo "[+] All core and GUI dependencies verified successfully."
fi

echo ""
echo "Setup complete. You can now launch Ambaan 3.0:"
echo "  - Floating HUD Widget:    ./start-floating-widget.sh"
echo "  - Comprehensive Analyzer: ./run-wifi-analyzer.sh"
echo "================================================="
