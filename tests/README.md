# Backend tests

## Run

From the repository root, with the .NET 10 SDK:

```sh
dotnet test tests/Backend.UnitTests/Backend.UnitTests.csproj
dotnet test tests/Backend.IntegrationTests/Backend.IntegrationTests.csproj
```

Integration tests require a running Docker-compatible daemon accessible to the user.
Testcontainers pulls `postgres:18.0-alpine` and `redis:8.2.2-alpine`, allocates random
host ports and removes its containers afterwards. No Compose stack or `.env` is
needed. Tests never connect to the development database or Redis. Missing Docker
is a test setup failure, not a silent skip.

Both projects are included in `src/Backend/Backend.sln`:

```sh
dotnet test src/Backend/Backend.sln -m:1
```

## Seven test conventions

1. **One behavior per test.** Multiple assertions are acceptable only when they
   describe the same outcome, such as rejection without an issued cookie.
2. **Arrange–Act–Assert.** Each test has explicit sections and one operation under
   test. Existing records and preceding lifecycle operations belong in Arrange.
3. **Descriptive names.** Use `Operation_Condition_ExpectedOutcome` (omit the
   condition when it adds no useful information).
4. **Isolation.** No test depends on another test's order or results. PostgreSQL
   tests use a separate database per test; Redis tests use fresh random session IDs.
5. **Repeatability.** Control the application clock. Avoid sleeps and timing-based
   coordination; use task completion signals. TTL assertions allow execution time.
6. **Observable behavior.** Assert public results, persisted data and required
   dependency interactions. Do not test private methods through reflection or
   reproduce production algorithms as the expected result.
7. **Small, readable tests.** Keep helpers focused on setup and data. Unit tests
   do not need Docker; database and Redis semantics belong in integration tests.

## Tools and coverage

- xUnit with its bundled analyzers and standard assertions.
- FakeItEasy for external interfaces in unit tests; real in-process DI and Data
  Protection where useful. No custom proxy/mock framework.
- Testcontainers PostgreSQL/Redis for storage integration tests.
- Actual EF migrations (`MigrateAsync`), not `EnsureCreated` or an in-memory EF provider.
- A real ASP.NET cookie handler for successful sign-in and rejection on failed DB writes.

Current coverage focuses on session creation, ledger/audit atomicity, cleanup on
failure, metadata mapping, Redis ticket protection/TTL, renewal coordination and
explicit logout through the real endpoint delegate and cookie handler. Logout tests
exercise both successful persistence and failed audit writes after Redis revocation.
A TestHost HTTP pipeline uses the production authentication registration and a controlled
clock to exercise continuous sliding renewal up to the absolute deadline. Tests check
acceptance at 7:59, rejection at 8:00, capped ledger expiry and Redis TTL, and rejection
of legacy tickets without absolute-expiration metadata. No sleeps or Keycloak calls
are needed for these checks.

They do not exercise the full authorization/antiforgery middleware pipeline or
Keycloak/OIDC browser flows. Natural-expiration reconciliation is outside the
current coverage.

## Absolute session lifetime

`PamSessionLifetime` stores `pam:absolute-expires-utc` in protected ticket properties.
The deadline is initialized at sign-in/session creation and preserved by sliding
renewal. Renewal limits `ExpiresUtc` before updating Redis and the session ledger.
Retrieval independently rejects tickets past their deadline or without valid metadata.
Deploying this change invalidates existing tickets without the metadata; users must
sign in again. A successful new OIDC sign-in can start a new lifetime, including when
the cookie handler reuses an existing session ID. Keycloak SSO may make that sign-in
silent; this is not a requirement to re-enter credentials every eight hours.

Expiry enforcement does not itself write an expired-session audit or fill `EndedAt`.
That remains separate work from enforcing access expiration.
