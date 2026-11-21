# PAM authorization design and delivery plan

Updated: **2026-11-21**. Status: **backend baseline implemented and automated checks passed**.
Live Keycloak/browser release smoke remains a separately recorded manual check.
This is the shared, versioned authorization contract. Existing local planning
material in `docs/` links here; this file does not depend on ignored documents.
The implementation branch is `codex/fine-grained-authorization`, based on local
`feature/resource-crud` commit `10f567c`. Implementation/test pairs are recorded in Git. Actual approval decisions remain
Sprint 2 work; the baseline does not add a placeholder approval state transition.

## 1. Goal, decisions and delivery boundary

Provide complete authorization for each delivered feature, using explicit
capabilities, resource relationships and business invariants. Keep the existing
API/Application/Infrastructure boundaries, ASP.NET Core authorization, PostgreSQL,
Redis sessions and Keycloak OIDC. No generic policy language, external permission
service, new authentication database or framework dependency is required.

Confirmed decisions:

- User, Approver and Admin are initially fixed **permission bundles**. There is no
  role inheritance. Approver and Admin do not acquire requester capabilities by
  implication. A principal can receive multiple explicit roles.
- Authorization names the operation and resource, not just an account's role.
  Fixed roles and fine-grained authorization are compatible: a permission permits
  an operation, and a current assignment limits the resources it can affect.
- Admins configure resource visibility and entitlement eligibility for requesters,
  and approval authority **per resource**. Bindings initially name individual PAM
  principals. Custom roles and principal groups are later extensions.
- Approval authority covers requests for all entitlements of that resource,
  including future entitlements. It never implies authority over another resource.
- Self-approval is forbidden globally, including for combined Admin/Approver
  accounts. The decision commands reject both own approve and own reject; a future
  owner cancellation is a distinct operation. Administrative authority cannot
  bypass an approval invariant.
- Admins can create, inspect and manage resources through management permissions.
  Creating a resource does not grant target access or approval authority.
- Admins may assign themselves resource visibility and requester eligibility,
  with audit, when they already have the corresponding requester capabilities.
  Their own role changes and own approval-authority changes require another Admin.
- The initial Admin can be a temporary bootstrap identity authenticated by
  Keycloak. Staging/production use an installation-specific generated secret;
  known demo credentials are Development-only. Retire the identity after a real
  Admin signs in and completes handover; retain its disabled PAM principal for audit.
- Preserve last-enabled-Admin protection, recent authentication for sensitive
  administration, current database checks and atomic administrative audit.

The first delivery covers existing resource/request routes, principal and role
administration, resource assignments, eligibility administration, recent-auth and
bootstrap handover. Actual approval decisions, grants, SSH keys, connector actions,
audit search and revoke-all-session features receive this authorization contract
when their vertical slices are delivered. They are not claimed implemented merely
because their intended permissions appear here. Approval must later create its
grant and durable provisioning work atomically; an isolated state flip is not a
complete approval feature.

## 2. What fine-grained means

For a requester operation, permission, resource visibility, entitlement eligibility
and command policy are separate checks. For an approval, permission, resource
approval authority, request state and separation of duty are separate checks.
Missing permission/relationship, an unknown permission code or an evaluation
failure cannot produce access. No wildcard permission or implicit Admin bypass.

Example: Bob has the Approver bundle and an approval binding to Linux A; Ana has
that bundle and a binding to Database B. Bob cannot read/decide Database B requests.
Bob needs an explicit User role and requester assignments to request access. If
Bob requests Linux A access, another authorized approver must decide it.

Initial catalog, expressed as stable codes rather than role checks in handlers:

| Capability | Initial bundle | Scope or additional rule |
| --- | --- | --- |
| `resources.read_scoped` | User, Approver, explicitly in both bundles | View binding, or approval-context read through current approval authority |
| `resources.read_all` | Admin | Management catalog and resource configuration |
| `resources.manage` | Admin | Resource management; never target access |
| `entitlements.manage` | Admin; activated with entitlement-management slices | Entitlement configuration and policy; never target access |
| `requests.create` | User | New submissions require visible resource and evaluate entitlement eligibility/policy |
| `requests.read_own` | User | Requester must match; resource retirement/assignment removal does not erase history |
| `principals.read`, `principals.manage` | Admin | Identity mapping/status; no passwords and no self-status changes |
| `roles.read`, `roles.assign` | Admin | Known bundle codes; no self-change; last-Admin invariant |
| `resource_access.read`, `resource_access.assign` | Admin | Explicit resource visibility assignments; own assignment allowed |
| `eligibility.read`, `eligibility.assign` | Admin | Per-entitlement requester eligibility; own assignment allowed |
| `approval_authority.read`, `approval_authority.assign` | Admin | Per-resource authority; own authority changes forbidden |
| `bootstrap.read` | Admin, including pending bootstrap | Read installation state; never initializes it |
| `bootstrap.complete` | Permanent Admin | Pending handover, matching real identity and recent-auth |
| `approvals.read`, `approvals.decide` | Approver; activated with approval slices | Resource authority; decisions additionally prohibit self-approval |
| `audit.read` | Admin; activated with audit-search slice | Explicit bounded operational audit API |

Overlapping bundles explicitly enumerate the overlapping permissions. Permission
catalog and initial bundle map live in code and are tested. Database role
assignments do not make arbitrary external claims or unknown role codes trusted.
There are initially no direct per-user permission overrides or deny/allow precedence
language. Future custom roles can change how the same catalog is assembled without
changing endpoint operation names or removing resource/invariant checks.

Canonical initial role codes are `user`, `approver` and `admin`, matched explicitly
and case-sensitively. Review existing prepared data before deployment; do not infer
permissions from an arbitrary role label such as `reader` or `superadmin`.

Session-only routes such as `/api/me`, antiforgery and logout require a valid,
enabled PAM session, not a business role. A roleless principal can use those
routes but gets no business capability. The UI may receive effective capability
codes for navigation; the server remains authoritative for every request.

## 3. Resource relationships and visibility

Add a typed resource-principal binding with two initial kinds:

| Binding | Effect |
| --- | --- |
| `ViewResource` | Scoped catalog/detail visibility, subject to read capability |
| `ApproveRequests` | Read/decision scope for requests on the resource, subject to approval capabilities |

Each relationship records resource, principal, active state, assigning/modifying
actor, UTC timestamps and a concurrency token. Enforce uniqueness for
`(principal, kind, resource)` and index reverse resource administration queries.
Validate binding kinds and parent/child relationships; no public wildcard scope.

Keep `EligibilityRule` as the explicit principal/entitlement relationship. A view
binding does not enable all entitlements. A new entitlement has no requester
eligibility by default. Approval bindings intentionally cover every entitlement
on their resource. Show that scope explicitly in the administration UI/API.

Assignment targets must be enabled and have the matching capability. Removing a
role deactivates bindings/eligibility that lose their last supporting capability
in the same audited transaction. Reassigning a role does not silently restore
those deactivated grants. Disabling a principal suspends all use; re-enabling is
an explicit audited sensitive action that shows the retained assignments.

Resource creation is management-only. The creator sees it in the management
catalog through `resources.read_all`, with no automatic requester or approver grant.

Read contracts:

- Management resource list requires `resources.read_all`.
- Add a bounded visible-resource catalog for `resources.read_scoped`. It includes
  explicit view bindings and resources visible through approval authority. An
  approver-only context exposes no unrelated users, assignments or request history.
- Existing `requestable=true` requires requester/read capability and filters by
  view binding, active resource, active entitlement and current eligibility.
- Single-resource reads accept management read, a scoped view binding, or scoped
  approval-context read. These are explicit alternative paths, not an accidental
  AND of unrelated policies.
- A new request to an invisible/missing/retired resource returns the same 404.
  A visible but ineligible submission retains Sprint 1's persisted `Denied`
  policy outcome; visibility denial is not turned into a persisted policy denial.
- Own request history remains readable with `requests.read_own` after resource
  visibility/eligibility changes or retirement. Foreign and missing requests
  remain indistinguishable 404s, including for Admin on the owner-only route.
- Existing identical idempotency replays remain stable after resource assignment
  removal or retirement. After validating current identity/capability, check the
  owner/key/fingerprint before evaluating visibility for a *new* submission.
  A replay never creates a new grant, policy result or audit event.
- Approval lists/details filter to current resource authority. The actionable
  pending queue excludes the caller's own requests. The command independently
  rejects self-approval even if a crafted request bypasses that queue.

Filter authorization in SQL **before pagination**, counts and projection. Use the
same operation rules for list and detail paths. Removing visibility does not revoke
an already-issued target grant; that is a separate explicit grant lifecycle action.

## 4. Enforcement and extension points

API: use ASP.NET Core named policies/requirements for capabilities and imperative
resource authorization where necessary. Keep handlers thin. Business services
accept the server-derived actor and enforce write invariants too; a background
caller cannot bypass authorization by invoking an application command directly.

Application: keep stable permission/operation identifiers and pure decision rules
independent of HttpContext and EF. Use a small typed current-authorization context
rather than passing EF entities or trusting a client-supplied requester/actor.

Infrastructure: load current roles, bindings and eligibility, compose authorized
queries, and own transactional locking, mutation and audit persistence. Reuse the
same rule semantics in endpoint checks and locked write checks; do not introduce
a generic repository, universal expression language or duplicate role logic.

Every business endpoint must declare its operation policy. Session-only and
anonymous endpoints require explicit classification. Validate the mapped endpoint
inventory and referenced policies at startup; an unclassified business endpoint
fails startup. Test this so `/api`'s existing authenticated group cannot silently
make a newly added endpoint available to every signed-in account. Explicit public
exceptions cover login/callback protocol handling, liveness/readiness, and the
existing Development-only OpenAPI surface. No production Swagger expansion.

Existing issuer/sub mappings are immutable. Display names and email addresses
cannot select a different identity or silently transfer an existing principal.

No cross-request cache of authorization grants initially. Cookie validation checks
the current enabled state, full identity tuple (internal/public ID and issuer/sub)
and explicit role set; resource scopes are read from the database, not
copied into long-lived tickets. A role change revokes the stale PAM session on its
next authentication attempt. A scope change applies on the next authorization
check without requiring a fresh login. DB/Redis outages fail closed with the
existing safe error contract; the session ledger never authenticates requests.

Privilege restoration must not revive a retained PAM cookie. Before enabling an
account, or adding an effective role, revoke its previously published sessions
through the existing Redis end-intent/CAS mechanism. Keep the principal exclusively
locked while selecting published ledger rows and revoking their tickets: the
ledger/audit foreign keys serialize concurrent publication against that row lock.
The ledger identifies issued sessions for cleanup; a Redis ticket remains required
for authentication. No new security-version claim or authorization cache is added.

Cleanup is bounded (initially 200 session rows per command). If another batch or a
lost CAS race remains, return a safe `session_cleanup_pending` conflict without
restoring privileges. Completed revocations remain safe progress if the later DB
mutation/audit fails. Existing reconciliation acknowledges retained end intents
and proactively closes disabled accounts' live sessions. Use the latest atomic
`principal.disabled` audit time when known; externally disabled accounts without
that record use detection time. Expired/lost-ticket handling retains its existing
reason/time rules. Effective role removal remains immediate in the DB; a later
role regrant must cross the cleanup barrier. A desired-state no-op must not revoke
new sessions or duplicate a change audit.

Extension rule: add a catalog capability only with its feature, define scoped
predicates/invariants, expose an operation policy and add positive/negative/race
tests. Future groups/custom roles feed effective grants into the same evaluator.
An IdP group/role is not automatically trusted as a PAM permission or resource grant.

## 5. Concurrent writes and revocation semantics

An endpoint check alone cannot authorize a later database mutation. Recheck the
actor and relevant grants inside the write transaction. Protect both existing and
absent assignments by locking stable parent rows; an EF token on an assignment
alone cannot prevent a concurrent insert or a grant being revoked after a read.

Use a consistent PostgreSQL locking protocol across every affected writer:

1. Role/status/bootstrap mutations acquire a common administration guard first
   (the immutable Admin-role row is a suitable existing stable guard).
2. Lock involved principal rows in ascending internal-ID order: actor, target and,
   for a decision, requester. Read current roles/status after taking those locks.
3. Acquire resource locks in ascending ID order: protected commands may take a
   shared row lock; scope, eligibility, entitlement and resource-policy changes
   take a conflicting write lock on that parent resource.
4. Acquire request/other child locks after principals and resources. Validate
   current authority, state/version and self-operation restrictions, then persist
   the change plus required audit in the same transaction.

All writers that can affect the checked invariant must follow the protocol,
including role removal, status changes, eligibility updates and resource retirement.
No process-local lock, stale request cache or promise based only on Read Committed
is sufficient across replicas. Keep transactions short and propagate cancellation;
use parameterized SQL through the existing EF/Npgsql boundary where locking needs it.

The serial order is the security boundary: if revocation commits first, a later
protected write fails. A write which obtained the necessary locks first can finish
before the revocation; a revocation does not retroactively erase committed work.
Reads already in flight may finish; avoid claiming instantaneous cancellation of
all requests or physical target sessions. Deterministic concurrent tests must
exercise both orderings. Resource ETag preconditions remain in force.

Last-Admin protection counts enabled, **non-bootstrap** principals with the Admin
bundle. The temporary identity never substitutes for a permanent Admin. Removing Admin, disabling a principal and
handover all use the same guard and count rule. Two concurrent removals cannot
both observe another usable Admin and leave zero. The bootstrap exception permits
initialization only while a recorded installation handover is pending. It never
reopens merely because someone removed or externally disabled administrators.

Direct privileged DB maintenance is outside the API's enforcement boundary. Its
runbook must preserve the same invariants and audit; normal runtime callers cannot
use that connection. No production migrator or schema privileges are introduced.

## 6. Sensitive administration and recent authentication

Require authenticated permission plus recent-auth for all administrative mutations:
resource/entitlement writes, role assignment/removal, principal mapping/enable/disable,
visibility/eligibility/approval-authority changes and bootstrap completion. Reads
and ordinary requester submissions do not require this additional check. This
uniform first policy avoids a field-based bypass through a general update DTO;
finer distinctions can be introduced with separately reviewed operations later.
Keep the sensitive-operation list explicit in one place and test it.

Initial maximum authentication age: **10 minutes**, inclusive at the boundary.
Use the original `auth_time` from the fully validated ID token, preserve it in the
protected PAM ticket, and use TimeProvider for comparisons. Cookie issuance,
sliding renewal and token issuance time cannot refresh this clock. Missing or
malformed `auth_time` cannot authorize a sensitive operation; ordinary authenticated
reads can continue. Reject unreasonable future times; define and test an explicit
small clock-skew allowance (initial proposal: 60 seconds, future age clamped to
zero without replacing the original timestamp).

Provide a dedicated reauthentication flow through the existing BFF/Keycloak
scheme. Request OIDC `max_age`, validate returned `auth_time`, and bind the protected
flow state to the original PAM principal/session. Require the same issuer/sub;
account switching cannot complete step-up. Reuse framework state, nonce and PKCE
validation. Permit only server-approved local return locations. A successful new
sign-in rotates the session through existing handlers and preserves the original
authentication time. A failed step-up grants nothing and does not silently replace
the account or authorize a pending command. The client explicitly resubmits after
success; never replay a privileged command carried in an untrusted redirect.

A stale/missing recent-auth result is a 403 Problem Details with stable
`recent_auth_required` code; an invalid session is 401. API requests do not get
redirected silently to an IdP. The UI initiates the separate browser flow. Recent
authentication proves freshness, not a particular MFA strength; actual MFA/ACR
policy remains an explicit Keycloak/security decision, not an inferred guarantee.

## 7. Bootstrap, permanent administrators and self-changes

Use a regular temporary identity in the PAM Keycloak realm and map it by exact
issuer/sub. The Keycloak **master-realm bootstrap administrator** is a separate
platform identity, never a PAM user or a credential held by the API. Runtime PAM
does not need Keycloak realm-administration privileges. The initial installer
creates/maps the PAM bootstrap identity and initial role using a controlled
installation step, not an anonymous public first-user-wins endpoint or recurring
API startup seeder. Initial bootstrap DML and its audit must be atomic; it is not
an EF schema migration and contains no fixed staging/production password.

Record a one-time installation state with the bootstrap principal, pending/complete
state and handover actor/time. The initial assignment is an explicit, controlled
installation exception to the normal no-self-role-change rule. Restrict a pending
bootstrap identity to setup/session functions needed to map permanent principals,
assign the permanent accounts' explicit initial bundles (including the first Admin)
and inspect handover progress. It cannot request
or approve target access or operate as a long-lived general administrator.

Handover sequence:

1. The operator creates the temporary Keycloak identity with an installation-specific
   secret and establishes the local mapping/initial administrative assignment.
2. Bootstrap maps a real, verified Keycloak issuer/sub identity to a PAM principal
   and grants its permanent Admin bundle through audited administration. If that
   person will also request access, assign User explicitly during setup or through
   another Admin later; never infer it from Admin. No target approval scope is
   assigned automatically.
3. That permanent Admin signs in normally and completes handover with recent-auth.
   Creating a database row alone is not evidence that the real person can sign in.
4. One locked transaction rechecks the caller, confirms a permanent enabled Admin,
   disables the bootstrap PAM principal, removes its roles/scopes and audits the
   handover. Record completion permanently and retain the principal/audit FKs.
5. Current enabled checks reject all bootstrap sessions after commit. Physical
   Redis ticket cleanup can follow; a cleanup failure cannot re-enable the account.
   Do not claim all stored tickets were deleted until that operation is verified.
   The operator also disables/removes the temporary Keycloak account and secret.

There is no distributed PostgreSQL/Keycloak/Redis transaction. Database disable
provides the PAM access guarantee even if IdP/Redis cleanup temporarily fails.
Recovery is an explicit audited operator procedure, not an automatic bootstrap
reactivation when no Admin is found. Completed bootstrap retirement is terminal:
normal enable/role/scope APIs cannot reactivate that identity. Staging/production
never use shared default
credentials; any known Development demo identity must be environment-scoped.

Normal API self-change rules:

- An Admin cannot add/remove their own roles, change their own approval binding,
  or disable their own principal. Another Admin performs these actions.
- An Admin can create/manage resources and set their own view/eligibility assignments
  if they already have the required scoped-read/requester capabilities. These
  changes are audited and do not produce target access. Independent approval
  remains mandatory in the current request policy.
- Self-approval is always denied, whatever the bundles or resource creator.
- Future auto-approval must receive a separate separation-of-duty review; it cannot
  silently turn a self-assigned eligibility change into an administrative bypass.
- Admin operations are available with one permanent Admin, including mapping a
  second Admin. Two-person approval for every configuration edit is not introduced.

## 8. HTTP, audit and rollout contracts

Keep DTOs, public UUIDs, validation, antiforgery, central no-store, safe Problem
Details and OpenAPI metadata. No `.http` documentation/test files.

| Condition | Result |
| --- | --- |
| Missing/invalid PAM session | 401 |
| Missing operation capability or forbidden self-operation | 403, no mutation |
| Hidden/foreign/missing scoped object | Indistinguishable 404 |
| Missing recent-auth for an otherwise permitted sensitive action | 403 with `recent_auth_required` |
| Invalid assignment kind, unknown bundle code or malformed input | 400 validation problem |
| Stale ETag / missing version on versioned update | Existing 412 / 428 contract |
| Last-Admin, invalid target state or other authorized business conflict | 409 with a stable safe code |
| Dependency failure | Existing generic safe 500; never grant access as fallback |

Define error precedence in each operation: authenticate, require capability,
constrain object visibility, check sensitive/self/state requirements, mutate.
Never reveal a foreign object's existence through a different error or audit payload.

Each successful administrative mutation and its audit commit together. Record
actor, affected principal/resource/entitlement, before/after grants, reason,
correlation, UTC time and schema version. Preserve the acting identity and existing
business snapshots. A failed required audit rolls back the change. Failed access
attempts use safe structured diagnostics; durable denied-attempt auditing is a
separate explicit product requirement, not a fake successful-change event.

Bulk dependent-grant deactivation must run in SQL without loading an unbounded
relationship graph or placing it into one audit JSON payload. Preserve the operation
correlation and exact affected relationships through bounded event payloads/server-side
audit insertion as needed, atomically with the role change.

Mutations should address one role/binding/eligibility relationship, not replace an
unbounded collection. Define bounded DTOs and paginated administrative reads.
Use desired-state/idempotent assignment operations: an identical retry makes no
second effective change/audit; conflicting versions cannot overwrite a newer edit.
Actor/self-checks cannot be bypassed by replaying a desired-state request.

Intentional compatibility changes include requiring explicit roles/scopes where
all authenticated users currently succeed. Adapt test fixtures and frontend flows;
do not automatically give every existing principal broad permissions. Inspect
existing role codes/data, use a reviewed migration/data-transition procedure and
manual development data. New databases do not get a hidden production Admin seed.
Existing session tickets missing auth_time remain unsuitable for sensitive actions.

Delivered role read: `GET /api/principals/{id}/roles` requires `roles.read`,
returns the explicitly assigned known bundles (at most three), and exposes the
principal aggregate ETag. Disabled principals retain their assignments. Unknown
DB role labels are omitted and do not grant capabilities.

Delivered role grant: `PUT /api/principals/{id}/roles/{roleCode}` changes one
known bundle on another enabled account, using `roles.assign`, recent-auth,
reason and the principal ETag. It revokes old published sessions before granting,
updates that ETag and commits the assignment with `role.assigned` audit. Repeating
an existing assignment with the current version preserves sessions and creates
no duplicate audit. A missing fixed bundle descriptor is created on its first
explicit assignment; arbitrary bundle codes are rejected.

Delivered role removal: `DELETE /api/principals/{id}/roles/{roleCode}` accepts a
JSON reason and the same authorization/version requirements. Removal immediately
changes current DB authorization. It atomically deactivates eligibility losing its
last requester capability, recording one `eligibility.deactivated` audit per exact
relationship in SQL, and `role.removed` for the bundle. It does not wait on Redis.
An absent-role retry is a no-op; granting User later leaves eligibility disabled.

Delivered visibility enforcement uses a typed `ViewResource` relationship with
unique `(principal, kind, resource)`, reverse index and xmin. It filters current
enabled principals and explicit supporting bundles in SQL. Requestable queries
also require User and current eligibility; management reads remain a separate
alternative. Scoped details and new submissions return 404 for hidden resources.
New submissions hold requester/resource locks through policy persistence; replay
and owner history do not depend on current visibility. Losing the last supporting
scoped-read bundle atomically deactivates view bindings with exact per-row audit.
This schema migration grants no existing account visibility automatically. The
visibility management and the scoped catalog now use the explicit view relationship.

Delivered visibility administration read: `GET /api/principals/{id}/resource-access`
requires `resource_access.read` and returns a bounded ascending resource-ID page,
including inactive bindings and retired resources for disabled or enabled accounts.
Its principal aggregate ETag and rows share one SQL snapshot. Read access does not
change assignments or imply requester/approver capability.

Delivered view grant: `PUT /api/principals/{id}/resource-access/{resourceId}`
requires `resource_access.assign`, recent-auth, reason and principal If-Match. It
locks actor/target principals in ID order, then the resource, rechecks current
capabilities and target state, and atomically grants/reactivates visibility with
`resource_access.granted` audit and a new principal ETag. The target must be an
enabled User or Approver. An Admin with that existing capability may assign their
own view; no role, eligibility or approval authority is created. An active-state
retry with the current version is a no-op. Successful writes return 204 and ETag.

Delivered view revocation: `DELETE /api/principals/{id}/resource-access/{resourceId}`
uses the same sensitive permission, JSON reason and principal If-Match. It supports
own removal, disabled/roleless targets and retired resources, deactivating the
relationship with `resource_access.revoked` audit and a new principal ETag. A
current-version absent/inactive retry is a no-op. It changes scoped checks, not
owner history/replay or an already-issued target grant.

Delivered scoped catalog: `GET /api/resources/visible` requires `resources.read_scoped`
and applies current visibility in SQL before bounded cursor pagination. It includes
assigned inactive resources, excludes retired resources and returns no entitlement
eligibility or other principals' assignments. ReadAll remains a separate management
catalog; an Admin/User account receives no implicit scoped visibility.

Delivered entitlement discovery for eligibility administration:
`GET /api/resources/{id}/entitlements` uses `resources.read_all` to inspect resource
configuration. It returns a bounded entitlement-ID page including inactive
entitlements, without filtering by caller eligibility. Inactive resources remain
inspectable; missing/retired parents return 404. This read creates no assignments
and does not introduce entitlement-management writes.

Delivered eligibility inspection: `GET /api/principals/{id}/eligibility` requires
`eligibility.read`, returning a bounded entitlement-ID page and principal ETag from
one SQL snapshot. Disabled principals/rules and inactive or retired parents remain
inspectable. Configured eligibility, parent availability and resource visibility
remain separate facts; this read creates no access.

Delivered eligibility grant: `PUT /api/principals/{id}/eligibility/{resourceId}/{entitlementId}`
requires `eligibility.assign`, recent-auth, a reason and principal If-Match. It
locks actor/target principals then the resource, requires an enabled User target,
validates the entitlement's parent and atomically enables the rule with
`eligibility.granted` audit and a new principal ETag. Own eligibility is allowed
only with existing User capability. Inactive configuration can be prepared;
retired/missing/wrong-parent objects return 404. No view, role or target grant is
created. A current-version enabled-rule retry is a no-op. Success returns 204.

Delivered eligibility revocation: `DELETE /api/principals/{id}/eligibility/{resourceId}/{entitlementId}`
uses the same sensitive permission, JSON reason and principal ETag. It supports own
removal, disabled/roleless targets and retired parents, preserving parent integrity.
It atomically disables the rule with `eligibility.revoked` audit and a new ETag.
Current-version absent/disabled retries are no-ops. It changes new policy outcomes,
not view assignments, owner history/replay or previously issued target grants.

Delivered approval-authority grant:
`PUT /api/principals/{id}/approval-authority/{resourceId}` requires
`approval_authority.assign`, recent-auth, reason and principal If-Match. It creates
an explicit `ApproveRequests` relationship only for another enabled Approver,
covering every current/future entitlement on that resource. Own changes are
forbidden before desired-state no-op handling. Assignment/audit/principal ETag
commit together; no role, requester view, eligibility, decision or target grant is
created. Authority grants scoped resource context only with current Approver
support. Requester queries/submissions still require an explicit ViewResource
relationship, even for combined User/Approver accounts. Role removal deactivates
unsupported authority atomically with exact per-relationship audit.

Delivered authority inspection: `GET /api/principals/{id}/approval-authority`
requires `approval_authority.read` and returns a bounded resource-ID page with
principal ETag from one SQL snapshot. Inactive authority, disabled principals and
retired resources remain inspectable. View and authority reads select their exact
relationship kind and never merge the two administrative collections.

Delivered authority revocation:
`DELETE /api/principals/{id}/approval-authority/{resourceId}` uses the same sensitive
permission, JSON reason and principal ETag. Own authority changes remain forbidden,
including absent/inactive no-ops. Other disabled/roleless targets and retired
resources can be cleaned up. Authority/audit/ETag change atomically; independent
view/eligibility and issued target grants remain separate. Successful revocation
and current-version inactive retries return 204.

Delivered authorization overview: `GET /api/principals/{id}/authorization`
requires all five administrative read permissions together. One SQL snapshot
returns principal state, known explicit bundles and configured active/inactive
counts for view, eligibility and approval authority, with principal ETag. Counts
retain unavailable parents separately and do not claim effective access. Native
ASP.NET link generation points to each bounded detail collection for pre-enable
review. This read changes no grants.

Delivered bootstrap: the controlled [installation runbook](bootstrap-installation.md)
and reviewed `scripts/initialize-pam.sql` create the restricted temporary identity,
initial explicit Admin assignment and singleton installation/audit atomically.
`bootstrap.read` reports state without initializing it. A fresh permanent Admin
completes the installation through the authenticated API with installation ETag,
reason and CSRF protection. One transaction removes every bootstrap role, deactivates
all its view/authority/eligibility rows with per-row audit, disables it and records
completion. Current identity checks reject its old cookies before Redis cleanup.
Completed retirement cannot be reversed by normal status/role/scope APIs, and
manually enabling the retained principal does not make it authenticatable.

### Endpoint and operation matrix

The following baseline surfaces are implemented and documented through native
Minimal API/OpenAPI metadata. The approval feature is explicitly future scope.

| HTTP surface | Required permission/context |
| --- | --- |
| Existing login and framework OIDC callback | Explicit protocol/public classification; full framework validation |
| `/api/me`, `/api/auth/antiforgery`, POST `/api/auth/logout` | Enabled authenticated PAM session; logout retains CSRF protection |
| GET `/api/auth/reauthenticate` | Current PAM session, protected flow binding and approved local return location |
| GET `/api/resources` with omitted/false `requestable` | `resources.read_all` |
| GET `/api/resources?requestable=true` | `requests.create` + `resources.read_scoped`; view and eligibility filtered in SQL |
| GET `/api/resources/visible` | `resources.read_scoped`; view/approval-context predicate before paging |
| GET `/api/resources/{id}` | Management read OR authorized scoped resource read |
| GET `/api/resources/{id}/entitlements` | `resources.read_all`; bounded management configuration, including inactive entries |
| POST/PUT/DELETE `/api/resources` and `{id}` | `resources.manage` + recent-auth; existing PUT/DELETE If-Match remains required |
| POST `/api/access-requests` | `requests.create`; new-command visibility and current policy, with stable owner replay |
| GET `/api/access-requests/mine` and `/{id}` | `requests.read_own` + owner predicate, without Admin bypass |
| Principal list/detail and mapping/status writes | `principals.read` / `principals.manage`; mutations require recent-auth and self/last-Admin rules |
| Role-assignment reads/writes | `roles.read` / `roles.assign`; mutations require recent-auth and self/last-Admin rules |
| View-assignment reads/writes | `resource_access.read` / `resource_access.assign`; mutations require recent-auth |
| Eligibility reads/writes | `eligibility.read` / `eligibility.assign`; mutations require recent-auth and matching entitlement parent |
| Approver-assignment reads/writes | `approval_authority.read` / `approval_authority.assign`; mutations require recent-auth and no self-authority changes |
| GET `/api/authorization/bootstrap` | `bootstrap.read`; installation ETag, no initialization side effect |
| POST `/api/authorization/bootstrap/complete` | `bootstrap.complete`, pending installation, permanent caller and recent-auth |
| Future approval queue/detail/decision | `approvals.read` / `approvals.decide` + resource authority; decision also applies no-self-approval and current state |

An administration response must provide a concurrency token for the aggregate its
write changes. Prefer the existing PostgreSQL xmin/ETag pattern: touch the target
principal's modification metadata when its status, role or scope relationships
change, so the administration ETag detects concurrent relationship edits. This is
not a new session security-version claim or a cache of authorization in cookies.
State the expected aggregate/token explicitly in each new endpoint's OpenAPI.
A stale retry may return 412 and require a re-read; it must never duplicate a grant
or its change audit. Mapping creation uses the existing unique issuer/sub invariant.

## 9. Vertical-slice implementation sequence

Items 1–9 and the two retained follow-ups are implemented. Final automated and
manual release evidence is tracked separately below. Each item was delivered
through adjacent working implementation and focused
test commits. If a row names more than one write operation, split it into separate
pairs; do not implement a whole interface/service layer before its first behavior.
Update existing fixtures in implementation commits when required to preserve tests.

1. **Protect management and requester reads.** Introduce only the capability/bundle
   mapping needed by the first existing read operation, then extend to other read
   and requester operations in independent pairs. Prove roleless, combined-role
   and unknown-role behavior without inheritance. Preserve ownership and replay.
2. **Capture authentication freshness.** Preserve validated auth_time through normal
   sign-in/rotation/renewal, then deliver the dedicated reauthentication flow and
   recent-auth policy. Administrative mutation slices depend on this behavior.
3. **Protect current writes and endpoint coverage.** Extend across resource
   create/update/delete in independent pairs, with capability, recent-auth, ETags
   and atomic audits from each first working write. Classify every current route
   with operation/session/public metadata and validate the inventory at startup.
   Finish the existing-API contract before adding new administration endpoints.
4. **Principal administration.** Deliver bounded directory reads, one explicit
   issuer/sub mapping command, disable and enable as separate pairs. Identity issuer/sub
   is immutable after mapping; changing it requires a new mapping. Prepare the
   common administration guard, no-self-status check and last-Admin invariant before
   the first state-changing endpoint. Do not add IdP password administration.
5. **Role administration.** Deliver one known-role assignment and removal at a
   time, with no-self-change, guard/locking, concurrency, dependent-grant deactivation
   and atomic audit from the first working write. Add its read model only as needed.
6. **Requester resource visibility.** Add the typed view binding and audited grant,
   revoke and scoped-read behavior incrementally. Enforce it on current detail,
   requestable catalog and new submissions in the slice that introduces it;
   preserve own history and idempotent replay. Introduce a visible-only catalog as
   its own observable read slice. Do not leave a new binding decorative while old
   routes still bypass it.
7. **Eligibility administration.** Add per-entitlement grant/revoke writes around
   the existing eligibility model, target/parent validation, self-assignment rules
   and the shared locking protocol. Preserve visible-but-ineligible Denied behavior.
8. **Resource approval authority.** Add grant/revoke/read administration, target
   capability and no-self-authority checks, reusing the typed relationship contract.
   It becomes effective in approval list/decision slices, not a promise of global
   Approver access. No grant or approval workflow scaffolding in this phase.
9. **Bootstrap and handover.** Deliver installation provisioning/runbook and recorded
   bootstrap status, followed by permanent-Admin completion and retirement. Test
   failed/partial handover and access denial with retained Redis cookies. Until
   this slice is delivered, development/test identities are prepared explicitly;
   there is no public fallback setup endpoint.
10. **Close the authz baseline.** Run the complete backend check, real Keycloak/browser
    smoke for account switching/freshness and review the current endpoint matrix.
    Resolve the separate session-lease and paging-index follow-ups, review/merge
    the backend baseline and start approval work from updated main.
11. **Approval feature in Sprint 2.** Deliver scoped pending/detail reads, then one
    complete decision transaction with authority, no-self-approval, state concurrency,
    immutable decision/audit and the required grant/durable-work semantics. Define
    grant/provisioning lifecycle before approving this implementation scope.
    Repeat focused and full checks for the actual approval feature; the baseline
    gate does not substitute for validating its new state transitions.

Permission constants, methods, DTO fields and migrations appear only with the slice
that uses them. The requester/public-ID paging index and bounded orphan session-lease cleanup
are implemented. Cleanup uses native Redis scanning, conditional deletion and a
PostgreSQL publication lock shared with expiry-checked ledger creation. It never
deletes published recovery metadata or fabricates an audit for an unissued ticket.
Production schema changes are exported as reviewed SQL for manual admin application;
no production migrator, permission SQL bundle or live DB migration is introduced.

## 10. Required evidence before completion

| Area | Concrete acceptance evidence |
| --- | --- |
| Fine-grained grants | User/Approver/Admin alone and combinations; no role inheritance, wildcard, unknown-code or roleless business access |
| Endpoint inventory | Unclassified business endpoint/unknown policy fails closed; explicit session/public exceptions still work |
| Scope isolation | Two resources and users/approvers with disjoint bindings; guessed UUID, list/detail/count and cursor continuation cannot cross scopes |
| Eligibility | Visibility without eligibility gives no requestable entitlement; eligible without visibility cannot expose a resource; mismatched parent rejected |
| Existing requests | Removed scopes/retired resources preserve owner history and identical replay; foreign owner route remains 404 even for Admin |
| Self operations | Own roles/status/approval scope denied; own view/eligible assignment allowed only with existing capabilities; self-approval denied despite all roles |
| Revocation | Retained cookie cannot authorize after disable/role removal; resource-scope removal applies on the next check; outages never grant access |
| Concurrency | Deterministic revoke-first/decision-first orderings; last two Admin removals; duplicate assignments; resource retirement; stale versions |
| Administrative audit | Real PostgreSQL rejection of audit insert rolls back every changed relationship/status; exact actor/target/before/after/reason/correlation |
| Recent-auth | Missing/malformed/future timestamp, 10-minute boundary and adjacent values; sliding renewal cannot refresh age; callback account mismatch/replay rejected |
| Bootstrap | No anonymous first-user race; bootstrap-only restrictions; real successful login before handover; failure rollback; permanent disable despite cleanup failure; no automatic reactivation |
| Query/storage | Real PostgreSQL/Redis; filters before paging, bounded lists, cancellation, appropriate indexes and no overlapping DbContext operations |
| HTTP/frontend | Actual cookie/CSRF pipeline, documented 401/403/404/409/412/428, generated OpenAPI, navigation hints never replace backend checks |

Automated acceptance uses `bash scripts/format.sh`, `bash scripts/check.sh` and
focused real PostgreSQL/Redis tests per implementation/test pair. Test names and
the final clean gate are recorded in [verification evidence](authorization-verification.md).
Protocol tests exercise the actual framework OIDC callback with a local signed
identity-provider test double. A live Keycloak/browser smoke for account switching,
reauthentication and operator handover remains a manual release check; it is not
claimed by the automated suite. Production SQL is exported for review only and
has not been applied to a live database.

## 11. Decision closure and references

Resolved on 2026-11-20: fixed initial bundles with explicit permissions, no inheritance,
individual assignments first, resource-level approval scope, global self-approval
ban, separate visibility/eligibility, own-view/eligibility exception, and a temporary
Keycloak-authenticated bootstrap account retired after permanent handover.

Implemented technical choices: code-defined permission/bundle catalog,
startup endpoint inventory validation, the shared parent-row locking protocol,
60-second future clock-skew tolerance, stable safe conflict codes and explicit
single-assignment APIs. Final DTOs and routes are documented in generated OpenAPI
and exercised through the production HTTP pipeline. Future custom roles, groups, MFA strength,
auto-approval, audit retention and grant/connector semantics remain explicit feature
work; they do not require changing the completed baseline's operation names.

- [ASP.NET Core policy authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-10.0)
- [ASP.NET Core resource authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resource-based?view=aspnetcore-10.0)
- [OWASP authorization](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OIDC auth_time and max_age](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)
- [PostgreSQL locking](https://www.postgresql.org/docs/18/explicit-locking.html)
- [Keycloak bootstrap/recovery](https://www.keycloak.org/server/bootstrap-admin-recovery) — platform administrator lifecycle only; not a PAM bootstrap API.
