#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

solution=src/Backend/Backend.sln
migrations=src/Backend/Infrastructure/Persistence/Migrations

dotnet restore "$solution" --locked-mode
dotnet format whitespace "$solution" --no-restore --exclude "$migrations"
dotnet format style "$solution" --no-restore --exclude "$migrations" --severity warn
dotnet format style "$solution" --no-restore --exclude "$migrations" --diagnostics IDE0005 --severity info
