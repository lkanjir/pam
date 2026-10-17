#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <MigrationName>" >&2
    exit 1
fi

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

dotnet ef migrations add "$1" \
    --project src/Backend/Infrastructure \
    --startup-project src/Backend/Api \
    --context PamDbContext \
    --output-dir Persistence/Migrations
