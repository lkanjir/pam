# PAM engineering instructions

These instructions apply to every contributor and coding agent in this repository.
Read `CONTRIBUTING.md` and the nearest applicable `AGENTS.md` before changing code.

## Shared environment and completion

- Use the exact SDK in `global.json`. Do not change the SDK, language version,
  dependency versions or analyzer severities as a workaround for a failing check.
- `.editorconfig` owns formatting; `Directory.Build.props` owns analyzer policy.
  Compiler, nullable, analyzer and restore warnings must be fixed, not hidden.
- Use `bash scripts/format.sh` to format. Keep generated EF migrations unchanged.
- Run `bash scripts/check.sh` before handing off backend changes. It verifies the
  pinned skills, locked restore, formatting, analyzers, Release build and both test
  projects. `bash scripts/check.sh --unit` is a partial check when Docker is
  unavailable; explicitly report that integration tests were not run.
- Report checks actually run and their outcome. A missing prerequisite or a skipped
  check is not a pass. Preserve unrelated user changes.
- Never add broad `NoWarn`, disable analyzers, insert `#pragma warning disable`,
  add null-forgiving operators or skip tests just to make checks green. A necessary
  narrow exception needs a specific technical rationale and review.

## Shared skills

The reviewed team skills live in `.agents/skills`; provenance and file hashes are
in `agent-skills.lock.json`. Use these repository copies rather than personal copies.
Load only the skills relevant to the task, including their required references:

| Work | Skill |
| --- | --- |
| C# semantics and specialist selection | `csharp-expert` |
| Behavior-preserving C# refactoring | `csharp-refactoring` |
| Compatibility across assemblies or external callers | `dotnet-breaking-changes` |
| ASP.NET Core endpoints, HTTP semantics and error contracts | `dotnet-webapi` |
| EF Core data-access correctness and performance | `optimizing-ef-core-queries` |
| Writing, repairing or strengthening tests | `code-testing` |
| Running .NET tests and choosing command syntax | `run-tests` |
| Reviewing tests, assertions or behavioral gaps | `test-anti-patterns`, `assertion-quality` or `test-gap-analysis` |
| Build and project configuration | `msbuild` |

`platform-detection`, `filter-syntax`, `code-testing-extensions` and
`test-analysis-extensions` support the main skills. Read reference-only catalogs
directly when required. If your agent host cannot discover skills automatically,
read the relevant `.agents/skills/<name>/SKILL.md` directly. Do not silently replace
a missing skill with a different workflow or claim a skill was loaded when it was
not. Copilot-specific custom agents are not installed as native Codex agents;
follow the skill's documented inline fallback when one is unavailable.

## Implementation conventions

- Preserve the current API / Application / Infrastructure boundaries. Do not
  introduce a new architecture, generic repository or dependency without a concrete need.
- Keep API contracts in DTOs; do not expose EF entities. Use the existing HTTP,
  authorization, antiforgery and Problem Details conventions.
- Propagate cancellation through async I/O. Avoid blocking on tasks, fire-and-forget
  request work and overlapping operations on one `DbContext`.
- Project read queries into the required DTOs, bound list sizes and preserve
  pagination. Keep business changes and their audit records atomic.
- Respect the OIDC/BFF boundary. Never log credentials, cookies or tokens. Use
  structured logging and the existing correlation conventions.
- Manage package versions only in `Directory.Packages.props`. Commit affected
  `packages.lock.json` files together with intentional dependency updates.
- Follow `tests/README.md`: one observable behavior per test, Arrange–Act–Assert,
  deterministic clocks, isolated state and descriptive names. Use real PostgreSQL
  and Redis via Testcontainers for storage behavior; no in-memory EF substitute.
- Add focused regression coverage for changed behavior. Do not reproduce production
  algorithms in expected values or change assertions merely to hide a failure.

Passing automated checks is required; reviewers still assess correctness,
authorization, data integrity and whether the chosen design fits the feature.
