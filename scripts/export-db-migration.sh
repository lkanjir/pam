#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 || -z "$1" || -z "$2" || -z "$3" ]]; then
    echo "Usage: bash scripts/export-db-migration.sh <from-migration-or-0> <to-migration> <new-output-directory>" >&2
    exit 2
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
output="$(realpath -m -- "$3")"
mkdir -- "$output"
cd "$repo_root"

# Generates files only. The design-time factory never connects to a database.
DOTNET_ENVIRONMENT=Production ASPNETCORE_ENVIRONMENT=Production \
    dotnet ef migrations script "$1" "$2" --idempotent \
    --project src/Backend/Infrastructure --startup-project src/Backend/Api \
    --context PamDbContext --output "$output/schema.sql"
cp deploy/production/app-permissions.sql "$output/app-permissions.sql"
printf 'Review and test both SQL files in %s before manual production application.\n' "$output"
