#!/usr/bin/env bash
# Archive the retired PRISM challenge Postgres database to disk (Task 24).
#
# ARCHIVE ONLY — there is deliberately NO import/restore path in this repo.
# PRISM's metadata database moved to SQLite (WAL, local volume); the old
# Postgres contents are preserved as a timestamped compressed pg_dump for
# audit/rollback inspection, never re-imported.
#
# Usage:
#   PRISM_PG_URL=postgres://user:pass@host:5432/dbname \
#     scripts/archive_prism_postgres.sh [output-dir]
#
# Or discrete parts (avoids the password in the URL; password via PGPASSWORD
# or ~/.pgpass):
#   PRISM_PG_HOST=... PRISM_PG_PORT=5432 PRISM_PG_USER=... PRISM_PG_DB=... \
#     scripts/archive_prism_postgres.sh [output-dir]
#
# Live archive run (production nodes) is the Task 28 GO-gated cutover step —
# do not point this at live hosts without the GO.
set -euo pipefail
umask 077

OUTPUT_DIR="${1:-./prism-pg-archive}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARCHIVE_PATH="${OUTPUT_DIR}/prism-postgres-${TIMESTAMP}.dump.gz"

PG_DUMP_BIN="${PG_DUMP_BIN:-pg_dump}"

if [[ -n "${PRISM_PG_URL:-}" ]]; then
  CONN_ARGS=(--dbname "${PRISM_PG_URL}")
else
  : "${PRISM_PG_HOST:?set PRISM_PG_URL or PRISM_PG_HOST}"
  : "${PRISM_PG_USER:?set PRISM_PG_USER}"
  : "${PRISM_PG_DB:?set PRISM_PG_DB}"
  CONN_ARGS=(
    --host "${PRISM_PG_HOST}"
    --port "${PRISM_PG_PORT:-5432}"
    --username "${PRISM_PG_USER}"
    --dbname "${PRISM_PG_DB}"
  )
fi

mkdir -p "${OUTPUT_DIR}"

echo "archiving PRISM postgres -> ${ARCHIVE_PATH}" >&2
"${PG_DUMP_BIN}" "${CONN_ARGS[@]}" --format=custom --no-password \
  | gzip -9 >"${ARCHIVE_PATH}"

if [[ ! -s "${ARCHIVE_PATH}" ]]; then
  echo "error: archive is empty: ${ARCHIVE_PATH}" >&2
  exit 1
fi

sha256sum "${ARCHIVE_PATH}" >"${ARCHIVE_PATH}.sha256"

echo "archive complete:" >&2
ls -l "${ARCHIVE_PATH}" "${ARCHIVE_PATH}.sha256" >&2
echo "${ARCHIVE_PATH}"
