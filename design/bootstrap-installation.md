# Controlled PAM installation

PAM stores no bootstrap password and exposes no anonymous installation endpoint.
The temporary identity is a dedicated user in the normal PAM Keycloak realm,
authenticated through the same validated OIDC flow as permanent accounts. It is
not Keycloak's platform bootstrap administrator. Use an installation-specific
secret; no shared or committed default credentials.

After applying the reviewed schema, a database administrator reviews
[`scripts/initialize-pam.sql`](../scripts/initialize-pam.sql), replaces its three
identity placeholders with the configured validated issuer, the user's verified
immutable subject and its display name, then runs it once in a database tool.
Subject is opaque and is not normalized. The script refuses existing installation
state, any existing Admin assignment (even disabled), or an already mapped
identity. It creates the mapping, explicit Admin assignment, pending installation
and `bootstrap.initialized` audit atomically. Concurrent installers serialize.
It is not run by the API, development migrator or production deployment.

The bootstrap account may inspect/map principals, enable a mapped permanent
account and assign explicit initial bundles. It cannot disable accounts, remove
roles, manage/read resources, request access or configure resource assignments.
Giving it extra bundles directly in the database does not remove this boundary.
Normal administration APIs cannot change its own status or roles, and cannot
grant it resource scope or eligibility. No global access is granted to a newly
created resource's owner or to a new Admin.

`GET /api/authorization/bootstrap` requires `bootstrap.read` and reports the
pending/completed state with an installation ETag. Reading an uninitialized
installation never creates one. Already administered databases can continue
without installation state; the installer is not an account-recovery mechanism.

`POST /api/authorization/bootstrap/complete` requires a permanent Admin's actual
authenticated session, recent original authentication, CSRF protection, the
installation ETag and a reason. It atomically retires the bootstrap identity and
all its permissions, records completion and retains audit references. A current
ETag retry after completion is a no-op; stale versions return 412. No reset or
reactivation API exists. Assigning Admin alone does not complete installation;
the permanent administrator must log in and call the authenticated endpoint.
Redis cleanup is independent: current DB identity checks reject the retired
account immediately even when Redis cleanup is unavailable. After handover the
operator disables/deletes the temporary Keycloak user and destroys its secret.
The retained PAM identity is disabled, rather than deleted, because audit and
creator foreign keys must remain valid.

## Planned first-start experience

Follow-up **BOOTSTRAP-UX-01**: consider during Sprint 2 planning and deliver with
frontend onboarding/installation automation. This is planned work, not part of
the implemented authz baseline. The target is a preconfigured bootstrap login and
guided setup **without manually reviewing or running account-bootstrap SQL**.

User flow:

1. A one-time installer provisions a dedicated temporary user in the PAM Keycloak
   realm and creates its PAM mapping, initial Admin assignment, installation state
   and audit automatically. It supplies unique installation credentials through a
   secure installation-secret mechanism; no shared hardcoded default password.
2. The user signs in through normal OIDC and the frontend guides them through
   preparing a permanent Admin using the existing principal/role APIs.
3. The user signs in as that permanent Admin. Resource and other operational
   configuration happens under the permanent account; bootstrap permissions stay
   restricted to administrator setup.
4. The permanent Admin explicitly completes handover through the existing
   completion endpoint, with recent authentication, CSRF, installation ETag and
   reason. The frontend must not substitute a generic disable/self-disable call.
5. Installation automation disables the temporary Keycloak account and destroys
   its installation secret. Cleanup failures are retried without undoing PAM
   retirement or reopening setup.

Remaining implementation:

- Replace the manual initial-mapping step with an audited initializer invoked by
  a one-time installation command/job. Reuse the installation guards and atomic
  PAM transaction; do not introduce an anonymous first-user-wins endpoint or an
  API startup seeder that grants access on ordinary restarts.
- Automate Keycloak provisioning and retirement. Provisioning privileges belong
  to the installation mechanism, without retaining realm-administration
  credentials in the running PAM API. PAM continues to store no passwords.
- Handle partial failures across Keycloak and PostgreSQL with safe retries and
  reconciliation. Do not assume a distributed transaction. Retries must not
  duplicate identities, assignments or audit, adopt an unrelated existing
  mapping, or reset completed installation state. Missing permanent admins after
  handover must never trigger bootstrap recreation.
- Build the frontend setup flow around the existing authenticated bootstrap
  status, principal/role administration and handover contracts. Authentication
  remains normal OIDC; frontend navigation never grants permission.

Acceptance must include fresh-install onboarding without manual account SQL,
interrupted/retried and concurrent initialization, existing-install restart,
successful permanent-Admin login before handover, Keycloak cleanup failure after
PAM retirement, terminal retirement across redeployments and no credential leakage
to logs, source control or the PAM database.

Production **schema migrations remain a separate reviewed-SQL process**, applied
by the production database administrator. Automating initial account provisioning
does not add a production schema migrator or give the runtime API schema privileges.
