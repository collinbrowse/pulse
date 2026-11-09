#!/bin/bash
# Start Pulse and open the dashboard. Ctrl+C to stop.
cd "$(dirname "$0")"
[ -x probe ] || clang -O2 -w -o probe probe.c -framework IOKit -framework CoreFoundation || exit 1
PORT="${PULSE_PORT:-8765}"
(sleep 2 && open "http://127.0.0.1:$PORT") &
exec python3 server.py
