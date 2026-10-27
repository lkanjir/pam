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
sign in again. A successful new OIDC sign-in can start a new lifetime, with a fresh session ID. The previous session is revoked and ended with reason
`reauthentication`; the new session and its identity receive a separate start audit. Keycloak SSO may make that sign-in
silent; this is not a requirement to re-enter credentials every eight hours.

Expiry enforcement does not itself write an expired-session audit or fill `EndedAt`.
That remains separate work from enforcing access expiration.

## Access changes

Cookie authentication rechecks the local principal and role assignments on every
request. Disabled or missing principals, identity mismatches and changed role sets
revoke the session with reason `access_changed`; a new sign-in is required. Database
lookup failures fail the request instead of accepting stale authorization data.

## Concurrent renewal

Redis renewal compares the expiration in the protected current ticket and uses an
StackExchange.Redis conditional transaction (`Condition.StringEqual`) to atomically
replace that exact payload and its TTL. There are no application-owned Lua scripts. Older/equal expirations are
ignored; removal or expiration between the read and write cannot recreate a session.
Contention is retried at most eight times, then leaves the winning ticket intact.
The ledger is extended only after a successful Redis update. Regression tests cover
out-of-order renewals across two store instances, concurrent requests and TTL.

## Cookie issuance and rotation

Both cookie schemes use the framework's `CookieAuthenticationHandler`. `Cookies`
authenticates requests, slides expiration and handles logout. Its `ForwardSignIn`
routes explicit sign-ins (including OIDC) to `PamSessionSignIn`, which shares the
cookie settings, ticket protection and session store. The issuing scheme's
`ICookieManager` adapter ignores incoming cookies and delegates all response writes
to the standard manager, ensuring sign-in uses `StoreAsync`, never `RenewAsync`.

Before issuing a new session, `PamSignInCookieEvents.SigningIn` ends the authenticated previous session
through standard `SignOutAsync`, recording `reauthentication` and suppressing any
pending renewal on that handler. If creation fails, the old cookie may be expired
but no usable new cookie is issued. The framework owns cookie protection, chunking,
persistence, cache headers, events and redirects; PAM does not construct its internal
session-ID claim. Tests cover rotation after authentication/with pending renewal,
old-cookie replay, identity changes, audit failures, persistence and redirects.

## Ticket storage boundary

`PamTicketStore` is the ASP.NET `ITicketStore` adapter coordinating lifetime and audit.
It depends on `ISessionTicketStore`, the small authentication-storage contract in
Infrastructure. `RedisTicketStore` implements that contract with Data Protection
and Redis. The contract uses ASP.NET authentication tickets, so it stays outside
the framework-independent Application and Domain projects.

Coordination unit tests fake `ISessionTicketStore` and `ISessionLedgerWriter`; they
do not configure Redis commands, serialization or cryptography. Storage tests
exercise the Redis implementation separately, including conditional renewal, TTL,
concurrent removal and rejection of expired stored tickets.

## Explicit session termination

Application sign-out calls use `EndPamSessionAsync` with a `SessionEndReason`.
The adapter carries that intent only during the standard framework `SignOutAsync`
call, restoring the previous request state in `finally`. This bridge is necessary
because `ITicketStore.RemoveAsync` does not receive sign-out properties and runs
before the cookie `SigningOut` event. Call sites do not manipulate request features.

The ticket-store adapter delegates explicit endings to the scoped
`SessionTerminator.EndSessionAsync(sessionId, reason, correlationId)`. This operation
can also be invoked without HTTP. It revokes storage first, then persists the end
with stable codes `logout`, `reauthentication` or `access_changed`. Storage failure
propagates without an end audit; audit failure after revocation is logged and does
not undo revocation or prevent cookie expiry. The correlation ID is used in failure
logs; ledger/audit persistence retains its existing correlation behavior.

Framework removal without explicit intent, and cleanup of an unissued session,
remain storage-only operations. They do not record a user logout. Tests cover all
three reason codes, operation ordering, storage/audit failures and isolation of the
sign-out intent from later cleanup in the same request.

## PAM identity claims

`PamClaimTypes` defines the cookie claim names, and `PamClaims` creates and reads
the typed `PamUserIdentity`. OIDC issuance, cookie validation, `/me` and session
audit use this shared mapping. Required identity fields are validated together;
malformed or incomplete identities are rejected. Existing valid ticket claims
retain their names and ASP.NET name/role semantics.

Both cookie schemes resolve scoped `CookieAuthenticationEvents` through
`EventsType`. `PamCookieEvents` receives the identity reader through its
constructor and rejects disabled users or changed roles. `PamSignInCookieEvents`
initializes the session lifetime and rotates an authenticated previous session.
