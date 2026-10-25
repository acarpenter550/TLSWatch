#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
if [ ! -f .venv/bin/python ]; then
  python3 -m venv .venv
fi
if [ ! -f .venv/tls_watch_ready.txt ]; then
  .venv/bin/python -m pip install -r requirements.txt
  touch .venv/tls_watch_ready.txt
fi
echo 'Open http://127.0.0.1:8080 and keep this process running for scheduled checks.'
exec .venv/bin/python app.py
