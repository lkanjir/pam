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
dotnet test src/Backend/Backend.sln
```

## Parallel execution and storage isolation

Integration tests use xUnit's native collection scheduling, capped at **four
concurrent collections** through `CollectionBehavior(MaxParallelThreads = 4)`.
The four `StorageCollection1`–`StorageCollection4` collections each own an
independent PostgreSQL/Redis container pair. Tests inside a collection remain
sequential, and each test still creates a separate PostgreSQL database. Standalone
class fixtures also respect the assembly's concurrency cap. No runner/package
change or custom scheduler is required.

Assign new HTTP/storage test classes to one of these collections using
`[Collection(StorageCollection1.Name)]` (or 2–4), spreading larger suites across
them. Do not put all storage classes back into one collection: xUnit serializes
classes in the same collection. Tests for custom migration environments retain
their dedicated fixtures. Never share a mutable database/`DbContext` between
parallel cases; explicit application concurrency tests use separate contexts
inside one isolated case.

PostgreSQL fixtures run the actual EF migrations once into a private template,
close its connections and disable new connections to that source. Each test uses
native `CREATE DATABASE ... TEMPLATE ...` to create a separate writable database,
which is dropped after the test. Test-specific interceptors attach to the clone's
context. Data, schema changes, locks and transactions stay isolated between tests.
The dedicated development/production migration suites still start fresh databases
and exercise migration/SQL application directly; they do not use the template.
See [PostgreSQL template databases](https://www.postgresql.org/docs/18/manage-ag-templatedbs.html).

On 2026-11-21/22, a matched Release/no-build/no-restore benchmark of 193 existing
cases (principal enable/role assignment, eligibility/authority assignment,
bootstrap handover and resource update) passed in all three configurations:

| Configuration | Process wall time | Peak overlapping test cases |
| --- | ---: | ---: |
| Original single storage collection | 81.3 s | 1 |
| Four bounded storage collections | 40.7 s | 4 |
| Four collections with migrated-template clones | 30.3 s | 4 |

Each figure is one local run with cached Docker images; fixture startup and the
same TRX logging are included. This measures that subset on this machine, rather
than promising a fixed CI speedup. TRX results confirmed the same 193 cases passed
and that execution actually overlapped. See [xUnit collection scheduling](https://xunit.net/docs/running-tests-in-parallel).

The complete `bash scripts/check.sh` gate passed on 2026-11-22 at `c590a57`:
227 unit and 1,023 integration cases, zero failed/skipped and a Release build with
zero warnings/errors. Integration execution took 1 minute 26 seconds; the entire
gate, including restore/format/build checks, took 111 seconds. These are local
observations, not a CI time limit.

`PostgresFixtureTests.CreateDatabase_ConcurrentCalls_ReturnIndependentMigratedDatabases`
checks concurrent cloning, current migration history and independent persisted
rows. `CreateDatabase_ModifiedClone_DoesNotLeakDataOrSchemaIntoLaterClone` checks
that neither inserted data nor a test-added SQL constraint reaches a later clone.

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
- Actual EF migrations (`MigrateAsync`) build a protected template once per
  PostgreSQL fixture; each test gets a fresh native database clone. No
  `EnsureCreated`, transaction rollback substitute or in-memory EF provider.
- A real ASP.NET cookie handler for successful sign-in and rejection on failed DB writes.

Current coverage focuses on session creation, ledger/audit atomicity, cleanup on
failure, metadata mapping, Redis ticket protection/TTL, renewal coordination and
explicit logout. Cookie tests are split into sign-in, rotation, access changes,
lifetime and logout scenarios. They share PostgreSQL/Redis collection fixtures,
with a separate database per test and fresh random session IDs.

`SessionTestHost` uses the same `AddPamApi` service registrations and `UsePamApi`
HTTP pipeline as `Program`. Test configuration supplies the isolated database;
only the Redis connection, clock and Data Protection provider are replaced. A
local sign-in endpoint substitutes for the external OIDC flow. `/api/me` and
`/api/auth/*` are the actual application endpoints with authorization and the
antiforgery filter enabled. The cookie helper preserves both the session and
antiforgery cookies when applying response headers.

`LogoutPipelineTests` verifies rejection of anonymous requests and missing/invalid
antiforgery tokens, and successful logout with a valid token, including failed
audit writes and replay of the revoked cookie. Direct handler/endpoint tests
remain for persistence failures and termination-feature cleanup within one context.
Lifetime tests check acceptance at 7:59, rejection at 8:00, capped ledger expiry
and Redis TTL, and rejection of legacy tickets without expiration metadata.

Live Keycloak/browser flows remain outside the current coverage. Session
reconciliation uses real storage and deterministic clocks; no sleeps or Keycloak
calls are needed.

## Migration environments

`DevelopmentMigratorTests` covers the Development guard, shared configuration,
cancellation and credential-safe failures. `DevelopmentDatabaseTests` lets
PostgreSQL run the actual dev bootstrap on initial container startup, then checks
that the app role can migrate, manipulate schema and repeat the migration run.

`ProductionDatabaseTests` applies EF-generated idempotent SQL twice as an admin
without running the dev migrator, then checks the applied migration IDs. These
tests use disposable databases, never the local Compose or production database.

## Absolute session lifetime

`PamSessionLifetime` stores `pam:absolute-expires-utc` in protected ticket properties.
The deadline is initialized at sign-in/session creation and preserved by sliding
renewal. Renewal limits `ExpiresUtc` before updating Redis and the session ledger.
Retrieval independently rejects tickets past their deadline or without valid metadata.
Deploying this change invalidates existing tickets without the metadata; users must
sign in again. A successful new OIDC sign-in can start a new lifetime, with a fresh session ID. The previous session is revoked and ended with reason
`reauthentication`; the new session and its identity receive a separate start audit. Keycloak SSO may make that sign-in
silent; this is not a requirement to re-enter credentials every eight hours.

Expiry enforcement rejects the ticket immediately. The periodic session reconciler
records `expired` and fills `EndedAt` at the retained lease deadline; if all Redis
recovery data has disappeared, it records `session_lost` at detection time instead.

## Access changes

Cookie authentication rechecks the local principal and role assignments on every
request. Disabled or missing principals, identity mismatches and changed role sets
revoke the session with reason `access_changed`; a new sign-in is required. Database
lookup failures fail the request instead of accepting stale authorization data.

## Concurrent renewal

Redis renewal compares the expiration in the protected current ticket and uses an
StackExchange.Redis conditional transaction (`Condition.StringEqual`) to atomically
replace that exact payload, TTL and recovery lease. Separate small Lua scripts
atomically observe tickets and seal end intents. Older/equal expirations are
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
the framework-independent Application project.

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
can also be invoked without HTTP. It atomically retains the first end intent while
revoking the ticket, then persists the end
with stable codes `logout`, `reauthentication` or `access_changed`. Storage failure
propagates without an end audit; audit failure after revocation is logged and does
not undo revocation or prevent cookie expiry. The retained end intent is retried by
the session reconciler until ledger/audit persistence and acknowledgement succeed.
The caller correlation ID is required before revocation and is preserved in both
failure logs and the session-end audit, without generation in the persistence layer.

Framework removal without explicit intent, and cleanup of an unissued session,
remain storage-only operations. They do not record a user logout. Framework
removal keeps the lease for later reconciliation; unissued cleanup discards it.
Tests cover all
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

## Persistence entities

EF entities live in `Infrastructure/Persistence/Entities` and are mapped directly
by `PamDbContext`. There is no separate Domain project or parallel domain model.
Application contains the use-case contracts and read projections, without a
dependency on EF or Infrastructure.

Moving the entity namespace does not change the database schema. The current EF
model snapshot uses the new namespace; historical migration target models retain
the original names. Integration tests apply the existing migrations to PostgreSQL.

Core resource, entitlement, eligibility, access-request and role relationships have
explicit navigation mappings alongside their existing FK properties. Navigation
declarations do not enable lazy loading or automatic includes. Required references
use `null!` for materialization; this does not mean the related entity was loaded.

`EntityRelationshipsTests` checks graph inserts with generated keys, distinct role
assignees/assigners, one-command navigation projections without tracked entities,
tracked resource updates and history after resource soft deletion. The PostgreSQL
fixture accepts command interceptors for measuring the actual query count.
`EntityModelTests` compares the relational model with the last migration, guarding
against accidental extra FK columns or other schema changes during this refactor.

The required `Entitlement.Resource` relationship points to a filtered entity. EF
warns about that combination: projecting or including the required resource can
hide an entitlement when the resource is soft-deleted. Historical queries that
need that resource use `IgnoreQueryFilters()` explicitly. No filter is propagated
to requests, entitlements or audit history. Audit snapshots remain the historical
source of truth; loading a current entity is optional and does not replace them.

## Resource CRUD

Resource endpoint tests use the production HTTP pipeline with real cookie sessions,
antiforgery validation, PostgreSQL and Redis. A local test sign-in replaces the
external identity provider, using the same infrastructure as the cookie tests.
Management fixtures explicitly assign the Admin bundle and a fresh original
authentication time. The target can have a different creator; ownership grants no
management capability. Authorization suites separately prove denial for ordinary,
unknown and roleless accounts, and independent requester visibility/eligibility.

PUT fully replaces editable fields and requires `IsActive` explicitly. An omitted
description clears the previous value. Tests cover trimming, validation boundaries,
missing required fields, malformed JSON, authentication/CSRF rejection, unavailable
targets, actor/timestamp stamping and the audit snapshot. The 24 PUT cases passed
before DELETE was implemented.

DELETE sets `DeletedAt` and `ModifiedAt` to the same operation timestamp,
`IsActive=false` and `ModifiedByPrincipalId` to the caller. Tests cover active and
inactive targets, retained entitlements, audit snapshots, authentication/CSRF,
missing targets and repeated deletion. A repeat returns 404 without a new audit.
Deleted targets disappear from GET/list and cannot be restored through PUT.

Resource changes and their `resource.created`, `resource.updated` or
`resource.deleted` audit use one `SaveChangesAsync`. Check-constraint failures on
the audit table verify rollback of creation, update and soft deletion. Snapshots
include resource identity, editable fields, creation/modification actors and
timestamps, and the deletion timestamp. Earlier snapshot fields retain their names.

Read/create regressions exercise Location resolution, explicit/default active state,
cursor pagination without overlap, a cursor whose last resource was deleted,
invalid cursors/limits and authentication. These are HTTP/storage tests; unit tests
do not mock EF query behavior. Concurrent writes use
optimistic concurrency through strong resource ETags. PUT and DELETE require one
canonical `If-Match` value: missing is 428, invalid is 400 and stale is 412.
`ResourceConcurrencyTests` proves that concurrent losing writes, including no-op
updates, cannot persist their audit event.

## Requestable resources

`RequestableResourceTests` exercises `GET /api/resources?requestable=true` through
the production HTTP pipeline with PostgreSQL, Redis and real PAM cookie sessions.
It verifies caller-specific enabled eligibility, active resources/entitlements,
soft deletion, public identifiers and form constraints, empty results, filtering
before cursor pagination, invalid query Problem Details and anonymous rejection.
Management-list regressions verify that omitted/false `requestable` still returns
inactive targets and omits `entitlements`. The OpenAPI test checks the boolean
filter and entitlement response contract. Request-submission policy enforcement
remains separate work.

Verification on 2026-11-14: all **21 requestable-resource cases** passed in the
focused run. `bash scripts/check.sh` then passed locked restore, formatting,
analyzers, Release build (zero warnings/errors), **62 unit tests and 155
integration tests**, with no failures or skips.

## Own-request queries

`OwnAccessRequestListTests` exercises `/api/access-requests/mine` through the
real cookie pipeline, PostgreSQL and Redis. It checks session ownership before
pagination, pending and denied summaries, empty pages, cursor continuation,
default/minimum/maximum limits, invalid pagination, historical visibility after
retirement, unauthenticated access and the generated OpenAPI contract. GET does
not require an antiforgery token or write audit records.

`OwnAccessRequestDetailTests` follows the submission's `Location` to
`/api/access-requests/{requestId}` and checks pending/denied request data, the
persisted policy result and the two initial audit summaries. Foreign and missing
requests both return 404 Problem Details. Historical details remain readable
after retirement and eligibility changes. Other requests' audit events, internal
events, policy evidence and raw audit snapshots/metadata are not exposed. Tests
also verify authentication and OpenAPI for the detail response.

## Access-request submission

`AccessRequestPolicyTests` checks duration boundaries, required/optional tickets,
eligibility outcomes and validation before policy denial. Sprint 1 always queues
eligible requests for manual approval.

`AccessRequestSubmissionTests` uses production HTTP handlers, real PAM sessions,
antiforgery, PostgreSQL and Redis. It covers request validation, normalized text,
active resource/entitlement consistency, session-derived identity and server
values, Denied/PendingApproval persistence, versioned policy evidence and linked
audit snapshots. OpenAPI checks describe the required idempotency header,
success/error status codes and public response schema; no `.http` files are used.

`AccessRequestIdempotencyTests` covers normalization, changed-payload conflicts,
independent requester keys, concurrent identical/conflicting submissions and
replays after resource retirement or eligibility changes. Test middleware gates
both concurrent HTTP requests before submission without sleeps. A retry after
failure can reuse the key.

`AccessRequestAtomicityTests` uses check constraints to force failures at request,
policy and either audit insert, proving transaction rollback.

The local `/login` test substitute now creates claims from the seeded principal's
actual public identity through `PamClaims`, supporting realistic requester audit
snapshots and multiple principals. The external identity provider remains
substituted. Own-request GET endpoints are covered by the list/detail suites.

Verification on 2026-11-14: the focused runs passed **12 policy unit tests and
56 submission integration cases**. `bash scripts/check.sh` passed the complete
gate with a warning-free Release build, **74 unit tests and 211 integration
tests**, with zero failures or skips. The EF model check confirms that the new
request navigations reuse existing foreign keys without a schema migration.

## Audit payload contract

`SessionStarted` groups `PrincipalSnapshot` and `SessionRequestMetadata` separately
from session lifetime data. The snapshot JSON retains schema version 1 and the
fields `id` (number), `publicId` (string), `displayName`, `issuer`, and `subject`.
Both actor and subject snapshots are checked against that contract for start and
end events. Start events serialize the typed snapshot; end events still use one
atomic PostgreSQL statement to close the ledger and insert the audit event.

Authentication/session registrations have one entry point,
`AddPamAuthentication(configuration, environment)`. Cookie/session options and
OIDC registration are kept in separate files; antiforgery registration lives with
the API filter. `AddPamApi` remains the shared composition root for tests and runtime.

## Verification checkpoint — 2026-10-28

With the current error-handling/correlation changes on top of `f06c730`,
`dotnet test src/Backend/Backend.sln --no-restore -m:1` passed **61 unit tests and
78 integration tests**, including PostgreSQL/Redis Testcontainers.

Error tests cover safe generic 500 responses (including PostgreSQL/Redis failures),
empty status responses, browser Accept headers, explicit optional error codes,
validation fields, malformed JSON/query binding in both environments and preservation
of BadHttpRequestException status. Automatic status-to-code mapping was removed.

`OidcErrorTests` uses the production authentication registration and real OIDC/cookie
handlers with a local simulated token endpoint and signed tokens. It tests valid
sign-in, unknown/disabled principals, IdP access denial, database lookup failure and
invalid state. State, nonce and signature validation remain enabled. Failed-login
cases verify no session-store issuance and no PAM cookie. These tests use FakeItEasy
for identity lookup and ITicketStore; existing session tests cover real persistence.
They do not replace a live Keycloak/browser smoke test.

Unit tests cover missing identity claims and disconnected callback requests.
Session tests verify required caller correlation before revocation, persistence of
that value, replay preserving the original audit correlation, and the full HTTP
logout-to-PostgreSQL audit path.

Detailed request logging, response-ID headers and tracing remain deferred as recorded
in the local project documentation. No production request-logging pipeline is implied
by these tests.

## Verification checkpoint — 2026-10-29

After the EF navigation refactor, `dotnet test src/Backend/Backend.sln --no-build
--no-restore -m:1` passed **62 unit tests and 84 integration tests**. The seven new
tests cover the schema comparison and the persistence/navigation behaviors described
above. No schema migration is required for these navigation and setter changes.

After PUT, DELETE and resource CRUD regressions, the same full-suite command passed
**62 unit tests and 134 integration tests**. The 50 new resource cases use real HTTP,
cookies/antiforgery, PostgreSQL and Redis. PUT's 24 cases also passed separately
before DELETE implementation. Build completed with no warnings or errors.

## Session reconciliation

`SessionRecoveryStoreTests` exercises atomic Redis end intents, immutable first
reason/time/correlation, scoped pending queues, lease retention and stale
observation rejection across renewal. The opaque ticket revision is compared as
well as the lease, including legacy ticket writes that do not change a lease.

`SessionReconcilerTests` uses actual PostgreSQL and Redis with deterministic clocks.
It proves repair of stale renewal expiry, exact known expiry, full metadata loss
before and after the stale database deadline, retry after audit rejection,
concurrent replica completion, cleanup after a lost acknowledgement, and fair
bounded keyset sweeps while new sessions arrive. Redis connection errors must
leave ledgers open, and cancellation must stop work. Other HTTP fixtures disable
the hosted worker to keep their state transitions under test control; direct
reconciliation tests invoke production passes with a fresh scope each time.

Verification on 2026-11-15 after the six backend review fixes:
`bash scripts/check.sh` passed pinned skill verification, locked restore, formatting,
analyzers and the warning-free Release build. **113 unit and 291 integration tests
passed**, with zero failures or skips. The EF model matches its latest migration.
The reviewed migration-range SQL export contains the open-session partial index
and migration history entries, with no duplicate physical xmin column.

## Authorization baseline

The suites under `Authorization/` exercise current DB identity/roles, native
ASP.NET policies, recent original OIDC authentication, explicit resource view,
requester eligibility and resource-level approval authority. Management permission
does not imply requester scope or approval authority. Tests cover self-operation
rules (including no-op retries), last-Admin races, retained/retired assignments,
parent ETags, filtering before pagination and rollback of required audit failures.
Actual approval decisions and grants remain Sprint 2 work.

`BootstrapInstallerTests` runs the reviewed installer SQL against disposable
PostgreSQL, including failed/concurrent installation. `BootstrapBoundaryTests` and
`BootstrapHandoverTests` cover the restricted temporary identity, real cookie/CSRF
pipeline, current authorization repeated in services, atomic retirement and old
cookie rejection while its ticket is still retained. No test provisions a live
Keycloak user or claims a manual browser handover.

`AccessRequestPagingIndexTests` verifies the migrated ordered owner/cursor index
path with planner hints on an empty disposable table; it is not a workload
benchmark. `OrphanSessionLeaseTests` covers both publication orderings, expired
unpublished lease cleanup without fabricated audit, preservation of published
expiry and resumed native Redis scans across server cursor pages. Publication
expiry is checked after a shared PostgreSQL transaction advisory lock, so a delayed
publisher cannot create a ledger after expired orphan cleanup.
