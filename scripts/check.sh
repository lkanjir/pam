#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

case "${1:-}" in
    "") test_scope=all ;;
    --unit) test_scope=unit ;;
    *) echo "Usage: bash scripts/check.sh [--unit]" >&2; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then
    echo "Usage: bash scripts/check.sh [--unit]" >&2
    exit 2
fi

python3 scripts/verify-agent-skills.py

if [[ "$test_scope" == all ]]; then
    docker info > /dev/null
fi

solution=src/Backend/Backend.sln
migrations=src/Backend/Infrastructure/Persistence/Migrations

dotnet restore "$solution" --locked-mode
dotnet format whitespace "$solution" --no-restore --exclude "$migrations" --verify-no-changes
dotnet format style "$solution" --no-restore --exclude "$migrations" --severity warn --verify-no-changes
dotnet format style "$solution" --no-restore --exclude "$migrations" --diagnostics IDE0005 --severity info --verify-no-changes
dotnet build "$solution" --configuration Release --no-restore --warnaserror

if [[ "$test_scope" == unit ]]; then
    dotnet test tests/Backend.UnitTests/Backend.UnitTests.csproj --configuration Release --no-build --no-restore
else
    dotnet test "$solution" --configuration Release --no-build --no-restore
fi
