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
docker build -f src/Backend/Dockerfile --target migrator -t pam-migrator .
```

The Compose configuration uses the same context. The root `.dockerignore` allows
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
