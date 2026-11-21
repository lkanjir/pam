using Api.Authentication;
using Api.Authorization;
using Api.Resources;
using Application.Authorization;
using Application.Principals;
using Application.Sessions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace Api.Principals;

public static class PrincipalRoleEndpoints
{
    public static IEndpointRouteBuilder MapPrincipalRoleEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/principals/{id:guid}/roles", Get)
            .WithTags("Principal roles")
            .WithName("Principal.Roles.Get")
            .WithSummary("Read a principal's explicitly assigned PAM bundles")
            .WithDescription("Requires roles.read. Returns zero to three known bundles (admin, approver, user), "
                + "including assignments retained by disabled accounts. Unknown database labels grant no capability and are omitted. "
                + "The ETag identifies the target principal aggregate. No recent-auth is required for this read.")
            .RequireAuthorization(PamPermissions.RolesRead)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);
        endpoints.MapPut("/principals/{id:guid}/roles/{roleCode}", Assign).WithResourceVersion()
            .WithTags("Principal roles")
            .WithName("Principal.Roles.Assign")
            .WithSummary("Assign one explicit PAM bundle to another enabled account")
            .WithDescription("Requires roles.assign, recent-auth, a reason and the target principal aggregate's current ETag in If-Match. "
                + "roleCode must be exactly admin, approver or user; no inherited roles. Self changes are forbidden, including no-op retries. "
                + "Old published sessions are revoked before an effective grant. Unfinished bounded cleanup returns 409 with "
                + "session_cleanup_pending, without granting the role. An already assigned role with a current version is a no-op. "
                + "A grant does not reactivate resource or eligibility assignments.")
            .RequireAuthorization(PamPermissions.RolesAssign, PamPolicies.RecentAuthentication)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);
        endpoints.MapDelete("/principals/{id:guid}/roles/{roleCode}", Remove).WithResourceVersion()
            .WithTags("Principal roles")
            .WithName("Principal.Roles.Remove")
            .WithSummary("Remove one explicit PAM bundle from another account")
            .WithDescription("Requires roles.assign, recent-auth, a JSON reason and the target principal aggregate's current ETag in If-Match. "
                + "roleCode must be exactly admin, approver or user. Self changes and removing the last enabled Admin are forbidden. "
                + "Removal applies immediately in the DB, including disabled accounts, without waiting for Redis cleanup. "
                + "Eligibility that loses its supporting requester capability is deactivated with per-relationship audit in the same transaction. "
                + "An absent role with a current version is a no-op. A later grant does not reactivate dependent assignments.")
            .RequireAuthorization(PamPermissions.RolesAssign, PamPolicies.RecentAuthentication)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);
        return endpoints;
    }

    private static async Task<Results<Ok<PrincipalRolesResponse>, NotFound>> Get(Guid id, HttpContext context,
        IPrincipalRoleService service, CancellationToken cancellationToken)
    {
        var roles = await service.GetAsync(id, cancellationToken);
        if (roles is null)
        {
            return TypedResults.NotFound();
        }
        context.Response.Headers.ETag = ResourceEtags.Format(roles.Version);
        return TypedResults.Ok(roles);
    }

    private static Task<Results<Ok<PrincipalRolesResponse>, UnauthorizedHttpResult, ProblemHttpResult>> Assign(Guid id,
        string roleCode, ChangePrincipalRoleRequest request, [FromHeader(Name = "If-Match")] string? ifMatch,
        HttpContext context, IPrincipalRoleService service, CancellationToken cancellationToken) =>
        WriteAsync(id, roleCode, request, ifMatch, context, service, true, cancellationToken);

    private static Task<Results<Ok<PrincipalRolesResponse>, UnauthorizedHttpResult, ProblemHttpResult>> Remove(Guid id,
        string roleCode, [FromBody] ChangePrincipalRoleRequest request, [FromHeader(Name = "If-Match")] string? ifMatch,
        HttpContext context, IPrincipalRoleService service, CancellationToken cancellationToken) =>
        WriteAsync(id, roleCode, request, ifMatch, context, service, false, cancellationToken);

    private static async Task<Results<Ok<PrincipalRolesResponse>, UnauthorizedHttpResult, ProblemHttpResult>> WriteAsync(Guid id,
        string roleCode, ChangePrincipalRoleRequest request, string? ifMatch, HttpContext context,
        IPrincipalRoleService service, bool assigned, CancellationToken cancellationToken)
    {
        if (!PamClaims.TryRead(context.User, out var identity))
        {
            return TypedResults.Unauthorized();
        }
        if (ResourceEtags.RequireVersion(context.Request, ifMatch, out uint version) is { } precondition)
        {
            return precondition;
        }
        var snapshot = new PrincipalSnapshot(identity.Id, identity.PublicId, identity.DisplayName, identity.Issuer, identity.Subject);
        var actor = new AdministrativeActor(snapshot, PamAuthenticationTime.Read(context.User));
        var result = assigned
            ? await service.AssignAsync(id, roleCode, request, actor, version, context.TraceIdentifier, cancellationToken)
            : await service.RemoveAsync(id, roleCode, request, actor, version, context.TraceIdentifier, cancellationToken);
        if (result.Kind != PrincipalWriteKind.Succeeded)
        {
            return WriteProblem(result.Kind);
        }
        var roles = result.Roles ?? throw new InvalidOperationException("Role command returned no assignments.");
        context.Response.Headers.ETag = ResourceEtags.Format(roles.Version);
        return TypedResults.Ok(roles);
    }

    private static ProblemHttpResult WriteProblem(PrincipalWriteKind kind)
    {
        int status = kind switch
        {
            PrincipalWriteKind.NotFound => StatusCodes.Status404NotFound,
            PrincipalWriteKind.PreconditionFailed => StatusCodes.Status412PreconditionFailed,
            PrincipalWriteKind.LastAdmin or PrincipalWriteKind.SessionCleanupPending or PrincipalWriteKind.TargetDisabled => StatusCodes.Status409Conflict,
            PrincipalWriteKind.InvalidRequest => StatusCodes.Status400BadRequest,
            _ => StatusCodes.Status403Forbidden
        };
        string? code = kind switch
        {
            PrincipalWriteKind.RecentAuthenticationRequired => "recent_auth_required",
            PrincipalWriteKind.SelfChangeForbidden => "self_change_forbidden",
            PrincipalWriteKind.LastAdmin => "last_admin",
            PrincipalWriteKind.SessionCleanupPending => "session_cleanup_pending",
            PrincipalWriteKind.TargetDisabled => "target_disabled",
            _ => null
        };
        return TypedResults.Problem(statusCode: status,
            extensions: code is null ? null : new Dictionary<string, object?> { ["code"] = code });
    }
}
