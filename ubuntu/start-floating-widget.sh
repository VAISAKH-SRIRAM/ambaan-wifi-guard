#!/usr/bin/env bash
# Ambaan 3.0 Floating Widget Launcher for Ubuntu / Debian Linux

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "================================================="
echo "   Starting Ambaan 3.0 Wi-Fi Guard Widget"
echo "================================================="

if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python 3 is required. Please install it with:"
    echo "        sudo apt update && sudo apt install -y python3"
    exit 1
fi

# Check for tkinter if running in graphical environment
if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then
    if ! python3 -c "import tkinter" &>/dev/null; then
        echo "[INFO] Python 3 Tkinter is not installed."
        echo "       For the floating graphical HUD on Ubuntu/Debian, run:"
        echo "       sudo apt update && sudo apt install -y python3-tk"
        echo ""
        echo "[*] Falling back to high-performance Terminal TUI HUD..."
    fi
fi

exec python3 "$DIR/ambaan_widget.py" "$@"
