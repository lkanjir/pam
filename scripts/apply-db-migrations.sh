#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 || ${1:-} == --help || ${1:-} == -h ]]; then
    echo "Usage: $0 [env-file]"
    echo "Applies pending migrations using PAM_MIGRATIONS_CONNECTION."
    echo "Set it to the local PostgreSQL port and development admin credentials."
    echo "Default env file: deploy/.env (relative paths use the repository root)."
    if [[ $# -gt 1 ]]; then
        exit 1
    fi
    exit 0
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

env_file="${1:-deploy/.env}"
if [[ ! -f "$env_file" ]]; then
    echo "Environment file not found: $env_file" >&2
    exit 1
fi

compose=(docker compose --env-file "$env_file" -f deploy/compose.dev.yml)
"${compose[@]}" config --quiet

if [[ -z ${PAM_MIGRATIONS_CONNECTION:-} ]]; then
    echo "Set PAM_MIGRATIONS_CONNECTION to the local development PostgreSQL admin connection string." >&2
    exit 1
fi

"${compose[@]}" up -d --wait postgres

# The design-time factory reads the connection from the environment.
# EF applies pending migrations and manages its migration lock/transactions.
dotnet ef database update \
    --project src/Backend/Infrastructure \
    --startup-project src/Backend/Api \
    --context PamDbContext

# Default grants are configured during database initialization. Apply the two
# table-specific exceptions after EF has created the tables. This script is
# for the local Compose database; its connection must target that same database.
"${compose[@]}" exec -T postgres sh -c '
    exec psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
        --set=ON_ERROR_STOP=1 --set=app_user="$APP_DB_USER" \
        --single-transaction --file=-
' <<'SQL'
REVOKE ALL ON TABLE public."__EFMigrationsHistory" FROM :"app_user";
REVOKE UPDATE, DELETE ON TABLE public.audit_events FROM :"app_user";
SQL

echo "Database migrations applied successfully."
