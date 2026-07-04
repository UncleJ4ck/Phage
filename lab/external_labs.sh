#!/usr/bin/env bash
# Clone and bring up the already-published smuggling labs next to QuicDraw-evo.
# Needs docker + network egress. Not run in the dev sandbox (no egress there).
# Usage: ./external_labs.sh [up|status|down]
set -euo pipefail
cd "$(dirname "$0")"

WORKDIR="external-labs"

# name | git url
LABS=(
  "smuggling-lab|https://github.com/ZeddYu/HTTP-Smuggling-Lab.git"
  "h2csmuggler|https://github.com/BishopFox/h2csmuggler.git"
  "http3-smuggling|https://github.com/lpisu98/HTTP3-Smuggling-Tool.git"
)

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing: $1" >&2
    exit 1
  }
}

compose_files() {
  find "$1" -maxdepth 3 -type f \
    \( -name docker-compose.yml -o -name docker-compose.yaml -o -name compose.yml \) \
    2>/dev/null
}

clone_all() {
  mkdir -p "$WORKDIR"
  for entry in "${LABS[@]}"; do
    IFS="|" read -r name url <<<"$entry"
    if [ -d "$WORKDIR/$name/.git" ]; then
      echo "[=] $name already cloned"
    else
      echo "[*] cloning $name"
      git clone --depth 1 "$url" "$WORKDIR/$name"
    fi
  done
}

up() {
  need docker
  need git
  clone_all
  for entry in "${LABS[@]}"; do
    IFS="|" read -r name _ <<<"$entry"
    found=0
    while IFS= read -r cf; do
      [ -n "$cf" ] || continue
      found=1
      echo "[*] $name: docker compose up ($cf)"
      (cd "$(dirname "$cf")" && docker compose up -d)
    done < <(compose_files "$WORKDIR/$name")
    if [ "$found" -eq 0 ]; then
      echo "[!] $name: no compose file, see $WORKDIR/$name/README* for manual setup"
    fi
  done
  echo
  status
}

status() {
  need docker
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
}

down() {
  need docker
  for entry in "${LABS[@]}"; do
    IFS="|" read -r name _ <<<"$entry"
    [ -d "$WORKDIR/$name" ] || continue
    while IFS= read -r cf; do
      [ -n "$cf" ] || continue
      (cd "$(dirname "$cf")" && docker compose down -v) || true
    done < <(compose_files "$WORKDIR/$name")
  done
}

case "${1:-up}" in
  up) up ;;
  status) status ;;
  down) down ;;
  *)
    echo "usage: $0 [up|status|down]" >&2
    exit 1
    ;;
esac
