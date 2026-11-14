#!/bin/sh
set -eu

psql \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 \
  --set=app_db="$POSTGRES_DB" \
  --set=app_user="$APP_DB_USER" \
  --set=app_password="$APP_DB_PASSWORD" \
  <<'EOSQL'

-- Development only: API and migrator deliberately share a schema-owning role.
-- This script can also upgrade an existing local database without deleting data.
BEGIN;
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'app_user', :'app_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app_user')
\gexec
ALTER ROLE :"app_user" LOGIN PASSWORD :'app_password';
ALTER DATABASE :"app_db" OWNER TO :"app_user";
ALTER SCHEMA public OWNER TO :"app_user";

SELECT format('ALTER TABLE %I.%I OWNER TO %I', n.nspname, c.relname, :'app_user')
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
\gexec
SELECT format('ALTER SEQUENCE %I.%I OWNER TO %I', schemaname, sequencename, :'app_user')
FROM pg_sequences WHERE schemaname = 'public'
\gexec

GRANT ALL PRIVILEGES ON DATABASE :"app_db" TO :"app_user";
GRANT ALL PRIVILEGES ON SCHEMA public TO :"app_user";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO :"app_user";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO :"app_user";
COMMIT;

EOSQL
