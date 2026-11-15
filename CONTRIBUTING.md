# Backend development

Install the exact SDK in `global.json` (currently **10.0.113**), Python 3 and
Bash. Full checks require a Docker-compatible daemon accessible to your user.
Windows contributors can use WSL2 with Docker integration. Open the repository
root in your editor to load its shared configuration.

The same command runs locally and in GitHub Actions:

```sh
bash scripts/check.sh
```

It verifies shared skill hashes, locked NuGet restore, whitespace and C# style,
then builds the whole solution in Release with warnings as errors and runs both
test projects. Missing Docker fails the full check. Testcontainers starts isolated
PostgreSQL and Redis instances; no development Compose stack or `.env` is needed.

Use `bash scripts/check.sh --unit` for an explicitly partial check without Docker.
This still checks skills, formatting and the entire solution build, but executes
only unit tests. It does not replace the full check required before merge.
See [test coverage and conventions](tests/README.md) for test design and isolation.

## Run the API locally in Rider

Run PostgreSQL, Redis, Keycloak and Vault independently of the API debugger:

```sh
docker compose --env-file deploy/.env -f deploy/compose.dev.yml up -d --wait
```

Development Compose contains dependencies only. Open `src/Backend/Backend.sln`
and select the shared **API (local, migrate first)** configuration in Rider.
Its Before launch task runs **Migrate development database** to completion before
starting the API debugger. A failed migration returns a nonzero exit code and
blocks API startup. These configurations contain no credentials.

For CLI development, or when using the generated **Api: http** configuration,
run the local development migrator before starting the API:

```sh
dotnet run --project src/Backend/Migrator --launch-profile Development
```

The API and migrator share `Database:ConnectionString` through the same
`UserSecretsId`. The development app account owns the database, public schema,
tables and sequences so both processes can use that one connection. The migrator
applies pending EF migrations without restricting audit or history permissions.
It refuses to run outside Development. No migrator is included in the API image.

PostgreSQL runs `deploy/postgres/01-create-app-user.sh` automatically through
`/docker-entrypoint-initdb.d` when initializing an empty data directory. It creates
the development app role and gives it database/schema ownership. Existing dev
databases are disposable; the bootstrap does not upgrade old volumes or run on
container restarts.

The API runs as a local .NET process. Its URL is `http://localhost:8090`, matching
the development Keycloak client's registered
`http://localhost:8090/signin-oidc` callback. The browser opens `/swagger`.

The project uses `UserSecretsId` for development credentials. Initialize User
Secrets for the API if the project has not been configured yet, then use the
.NET User Secrets CLI or Rider's User Secrets editor to populate these keys:

- `Database:ConnectionString`: use `127.0.0.1:5433`, `POSTGRES_DB` and the app
  identity (`APP_DB_USER` / `APP_DB_PASSWORD`), rather than the database admin.
- `Redis:Password`: the development `REDIS_PASSWORD`.
- `Keycloak:ClientSecret`: the development `KEYCLOAK_CLIENT_SECRET`.

Keep these values in User Secrets rather than committed files or shared launch
settings. Compose still needs `deploy/.env` for its containers; the API does not
automatically import that file. `WebApplication.CreateBuilder` loads the API's
User Secrets in Development. Environment variables override User Secrets, so
remove stale Docker connection overrides from the local Rider profile.

Non-secret host defaults belong in `appsettings.Development.json`: Redis uses
`127.0.0.1:6379`, and Keycloak metadata uses `localhost:8080`.

## Production database releases

Production has no migrator service, image target or API startup migration. A
database admin applies reviewed SQL before deploying the matching API version.
This follows EF Core's [SQL deployment guidance](https://learn.microsoft.com/en-us/ef/core/managing-schemas/migrations/applying).

Restore the repository-pinned EF CLI (matching EF Core), then export an explicit
migration range to a new directory. Use `0` only for an empty application schema:

```sh
dotnet tool restore
bash scripts/export-db-migration.sh 0 20261028204341_AddAuditEventNavigation artifacts/db-release
```

The command generates only `schema.sql` and never connects to a database. For
subsequent releases, replace `0` with the migration currently applied in
production and specify the release's exact target ID.

The production admin reviews the SQL, connects to PostgreSQL using Rider or
another database tool (for example, through an SSH tunnel), and runs the script
with their admin account before deploying the matching API version. Production
account provisioning and permissions are managed by the admin; the API account
must not have schema migration privileges. No permissions script is generated.

## Session ledger recovery

Redis remains authoritative for authentication. PostgreSQL is an audit ledger and
is never used as a fallback session store. Ticket creation/renewal also records a
non-secret expiry lease in Redis. Explicit revocation atomically removes the
ticket and lease and retains an immutable end intent containing the session hash,
reason, original time and correlation ID. That intent is acknowledged only after
the PostgreSQL ledger and its audit event have been committed together.

`SessionReconciliation` settings default to `Enabled: true`, `Interval: 00:00:30`
and `BatchSize: 200`. The interval must be between one second and one hour; batch
size is 1–1000. Each API replica runs a scoped background pass with bounded pending
retries and a keyset page of open ledger rows. Fixed sweep ceilings prevent new
logins from starving older rows. Concurrent replicas can safely process the same
completion. Redis recovery hashes are scoped to the configured PostgreSQL database
name; replicas sharing that database must use the same Redis service. Independent
deployments should use separate Redis services.

A pass repairs stale renewal expiry, finishes retained end intents and records
known expiry at the lease deadline. When the ticket disappears before a known
future deadline, or all recovery metadata has been lost, it records `session_lost`
at the time of detection. A stale ledger deadline is never used to invent a
reason or historical time after complete Redis data loss. Redis errors fail the
pass and are never treated as evidence of a missing session.

Database failures retain the Redis intent for retry; successful Redis renewals
remain valid while their ledger update is deferred. Recovery requires the
dependencies to become available. The interval is not a completion deadline: a
full sweep depends on open-session count and batch size. Precise original end
information survives only while the Redis recovery record survives. If Redis
loses it before PostgreSQL commits, the accepted fallback is `session_lost` with
the detection time. Recovery records deliberately have no TTL until acknowledged.

## C# formatting

The root `.editorconfig` is the shared source of formatting preferences:

- Four spaces, UTF-8, LF, final newline, no trailing whitespace.
- Allman braces (opening brace on a new line); compact auto-properties are allowed.
- File-scoped namespaces and `using` directives outside the namespace.
- A 120-character line-length target. Rider wraps long parameter/argument lists
  one item per line and indents continuations rather than aligning them in columns.
- Existing deliberate line breaks are preserved. Braces for control statements
  are required; `var` is preferred for inferred object types, explicit types for primitives.
- Project/build files, JSON and YAML use two spaces.

Rider reads EditorConfig by default, and configured properties override its local
preferences. Use **Reformat Code** to apply them. If a file still looks different,
use **Show Code Style Configuration** in Find Action to inspect which settings
apply. See [Rider's EditorConfig documentation](https://www.jetbrains.com/help/rider/Using_EditorConfig.html)
and its [wrapping settings](https://www.jetbrains.com/help/rider/EditorConfig_CSHARP_LineBreaksPageSchema.html).

Apply the shared C# whitespace and enabled style fixes from the CLI:

```sh
bash scripts/format.sh
bash scripts/check.sh
```

`dotnet format` handles Roslyn formatting rules; Rider-specific wrapping and
alignment settings are applied by Rider. It does not enforce the 120-character
limit or every syntax-style suggestion. EF migration files are generated code
and excluded from routine formatting.

The check command never rewrites source files. Compiler, nullable, .NET analyzer,
xUnit analyzer and selected IDE style warnings fail the build. The pinned SDK owns
the formatter and analyzers; `Directory.Build.props` selects .NET 10 recommended
analysis. Unused imports are checked separately by the formatter because Roslyn
requires XML documentation generation to enforce IDE0005 on build. `var`
preferences remain suggestions. JSON/YAML/Markdown indentation is an editor
convention; this backend gate does not lint those files.

Fix warning causes. Do not lower severity, add broad `NoWarn` settings, suppress
diagnostics or skip tests just to get a green build. Necessary narrow exceptions
require a documented reason and review.
The checked-in exception is CA1707 only in test files: underscores separate the
documented `Operation_Condition_ExpectedOutcome` name clauses. Production code
keeps the naming rule enabled.

## Build and packages

`Directory.Build.props` defines the shared target framework, nullable context and
implicit usings. `Directory.Packages.props` owns NuGet versions; project files list
package references without versions. Change versions centrally when upgrading.
Commit the affected `packages.lock.json` files together. Regenerate them with
`dotnet restore src/Backend/Backend.sln --force-evaluate` for intentional updates,
then run the full check. Ordinary checks and Docker builds use `--locked-mode`.

`global.json` disables SDK roll-forward so the team uses the same compiler,
formatter and analyzers. Upgrade its SDK pin and the SDK archive version/checksums
in `src/Backend/Dockerfile` together. MCR does not publish a `10.0.113` SDK image,
so the Docker build installs Microsoft's official SDK archive with SHA-512
verification (amd64/arm64) into a separate directory. `global.json` selects it.
The image copies the SDK settings,
EditorConfig and package locks before restore.

Docker builds use the repository root as their context so these files are included:

```sh
docker build -f src/Backend/Dockerfile --target final -t pam-api .
```

Development Compose runs dependency images only. The root `.dockerignore` allows
only backend source and shared build files, excluding build output and `.env` files.

## Shared agent instructions and skills

Every agent must follow [AGENTS.md](AGENTS.md), which records architecture,
implementation conventions, skill selection and required checks. These coding
rules also apply to humans.

Reviewed skills from [`dotnet/skills`](https://github.com/dotnet/skills) live in
`.agents/skills`, including their references. Codex discovers repository skills
there; team members do not need personal installations. Other hosts should read
the relevant `SKILL.md` as directed by `AGENTS.md`. If a host needs a separate
instruction file, point it at `AGENTS.md` rather than duplicating its rules.
Start a new agent session after instruction or skill updates to refresh discovery.

`agent-skills.lock.json` records the upstream commit, paths and SHA-256 hashes.
CI rejects changed, missing or unlisted skill files. It detects drift; changing
the lock and content together still needs review. To update skills, select one
reviewed upstream commit, copy complete skill directories including references,
regenerate hashes and update `THIRD-PARTY-NOTICES.md`. Do not auto-update skills
during a build or an agent task. Copilot custom-agent files are not native Codex
agents; the test skill documents an inline fallback when its named agent is absent.

Skills guide decisions. The formatter, analyzers and tests enforce what can be
automated. Reviewers still assess design, authorization, data integrity and
behavioral correctness.

## Pull requests and merge policy

The `Backend quality` workflow runs on every PR and pushes to `main`, using
`bash scripts/check.sh` including integration tests. It has no path filters that
could leave a required check pending.

In GitHub branch rules for `main`, require pull requests, at least one reviewer
and the **Backend quality** status check. Restrict bypass and direct pushes
according to the team's ownership policy. These server-side settings are separate
from this workflow and must be enabled by a repository administrator. Include
changes to instructions, analyzers, CI and skill locks in review.

This gate covers the .NET backend. When a frontend is added, add its locked package
manager, lint, format, type-check and test commands to CI.
