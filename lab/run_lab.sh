#!/usr/bin/env bash
# Bring the localhost H3->H1 desync lab up or down.
# Usage: ./run_lab.sh [up|down]
set -euo pipefail
cd "$(dirname "$0")"

case "${1:-up}" in
  up)
    mkdir -p certs logs
    if [ ! -f certs/lab.pem ]; then
      openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout certs/lab.key -out certs/lab.crt -days 365 \
        -subj "/CN=lab" >/dev/null 2>&1
      cat certs/lab.crt certs/lab.key > certs/lab.pem
      echo "generated self-signed cert at certs/lab.pem"
    fi
    : > logs/echo.jsonl
    echo "bringing up lab on https://127.0.0.1:4433 (h3)"
    docker compose up --build
    ;;
  down)
    docker compose down -v
    ;;
  *)
    echo "usage: $0 [up|down]" >&2
    exit 1
    ;;
esac
