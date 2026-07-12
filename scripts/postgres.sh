#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_BIN="${PG_BIN:-$(pg_config --bindir)}"
PG_DATA="${PG_DATA:-${ROOT_DIR}/.aecontrol/postgres}"
PG_PORT="${PG_PORT:-55432}"
PG_HOST="${PG_HOST:-127.0.0.1}"
PG_USER="${PG_USER:-aecontrol}"
PG_DATABASE="${PG_DATABASE:-aecontrol}"
PG_LOG="${PG_DATA}/postgres.log"

export PATH="${PG_BIN}:${PATH}"

if [[ ! "${PG_USER}" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || \
   [[ ! "${PG_DATABASE}" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || \
   [[ ! "${PG_PORT}" =~ ^[0-9]+$ ]]; then
  echo "invalid PostgreSQL user, database, or port" >&2
  exit 2
fi

start() {
  mkdir -p "$(dirname "${PG_DATA}")"
  if [[ ! -f "${PG_DATA}/PG_VERSION" ]]; then
    initdb --pgdata="${PG_DATA}" --username="${PG_USER}" --auth=trust >/dev/null
  fi
  if ! pg_ctl --pgdata="${PG_DATA}" status >/dev/null 2>&1; then
    pg_ctl --pgdata="${PG_DATA}" --log="${PG_LOG}" \
      --options="-p ${PG_PORT} -h ${PG_HOST} -k ${PG_DATA}" --wait start >/dev/null
  fi
  if [[ "$(psql --host="${PG_HOST}" --port="${PG_PORT}" --username="${PG_USER}" \
      --dbname=postgres --tuples-only --no-align \
      --command="SELECT 1 FROM pg_database WHERE datname = '${PG_DATABASE}'")" != "1" ]]; then
    createdb --host="${PG_HOST}" --port="${PG_PORT}" \
      --username="${PG_USER}" "${PG_DATABASE}"
  fi
  echo "postgresql://${PG_USER}@${PG_HOST}:${PG_PORT}/${PG_DATABASE}"
}

case "${1:-start}" in
  start)
    start
    ;;
  stop)
    if [[ -f "${PG_DATA}/PG_VERSION" ]] && pg_ctl --pgdata="${PG_DATA}" status >/dev/null 2>&1; then
      pg_ctl --pgdata="${PG_DATA}" --wait stop >/dev/null
    fi
    ;;
  status)
    pg_ctl --pgdata="${PG_DATA}" status
    ;;
  *)
    echo "usage: $0 {start|stop|status}" >&2
    exit 2
    ;;
esac
