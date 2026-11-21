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
