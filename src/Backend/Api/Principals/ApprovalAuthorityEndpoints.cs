using Api.Authentication;
using Api.Authorization;
using Api.Resources;
using Application.Authorization;
using Application.Common.Pagination;
using Application.Principals;
using Application.Sessions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace Api.Principals;

public static class ApprovalAuthorityEndpoints
{
    public static IEndpointRouteBuilder MapApprovalAuthorityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/principals/{id:guid}/approval-authority", List)
            .WithTags("Approval authority")
            .WithName("Principal.ApprovalAuthority.List")
            .WithSummary("Inspect a principal's resource approval authority")
            .WithDescription("Requires approval_authority.read. Includes inactive authority and retired resources for enabled or disabled principals. "
                + "Each relationship covers all current and future entitlements of that resource; this read changes no authority. "
                + "Uses ascending resource public-ID pagination; limit defaults to 20, range 1–100. Returns the principal ETag from the same SQL snapshot. "
                + "No recent-auth is required for this read.")
            .RequireAuthorization(PamPermissions.ApprovalAuthorityRead)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);
        endpoints.MapPut("/principals/{id:guid}/approval-authority/{resourceId:guid}", Assign).WithResourceVersion()
            .WithTags("Approval authority")
            .WithName("Principal.ApprovalAuthority.Assign")
            .WithSummary("Assign approval authority for one resource to another enabled Approver")
            .WithDescription("Requires approval_authority.assign, recent-auth, a reason and the target principal aggregate's current ETag in If-Match. "
                + "The target must already have the explicit Approver bundle. Own authority changes are forbidden, including active-state retries. "
                + "Authority covers every current and future entitlement of this resource and grants approval-context resource visibility. "
                + "It creates no requester view, eligibility, role, request decision or target grant; requests still require their independent policy and separation of duty. "
                + "Returns 204 and principal ETag; an existing active assignment with a current version is a no-op for another principal.")
            .RequireAuthorization(PamPermissions.ApprovalAuthorityAssign, PamPolicies.RecentAuthentication)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);
        endpoints.MapDelete("/principals/{id:guid}/approval-authority/{resourceId:guid}", Revoke).WithResourceVersion()
            .WithTags("Approval authority")
            .WithName("Principal.ApprovalAuthority.Revoke")
            .WithSummary("Revoke another principal's approval authority for one resource")
            .WithDescription("Requires approval_authority.assign, recent-auth, a JSON reason and the target principal aggregate's current ETag in If-Match. "
                + "Own authority changes are always forbidden, including absent/inactive-state retries. Other disabled/roleless targets and retired resources may be cleaned up. "
                + "Revocation removes approval-context resource visibility, independently of requester view/eligibility and already issued target grants. "
                + "Returns 204 and ETag; a current-version absent/inactive assignment for another principal is a no-op.")
            .RequireAuthorization(PamPermissions.ApprovalAuthorityAssign, PamPolicies.RecentAuthentication)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);
        return endpoints;
    }

    private static async Task<Results<Ok<CursorPage<ResourceAccessResponse>>, NotFound>> List(Guid id,
        [AsParameters] ResourceAccessListQuery query, HttpContext context, IApprovalAuthorityService service,
        CancellationToken cancellationToken)
    {
        var result = await service.ListAsync(id, query.Limit, query.Cursor, cancellationToken);
        if (result is null)
        {
            return TypedResults.NotFound();
        }
        context.Response.Headers.ETag = ResourceEtags.Format(result.Version);
        return TypedResults.Ok(result.Page);
    }

    private static Task<Results<NoContent, UnauthorizedHttpResult, ProblemHttpResult>> Assign(Guid id, Guid resourceId,
        ChangeResourceAccessRequest request, [FromHeader(Name = "If-Match")] string? ifMatch, HttpContext context,
        IApprovalAuthorityService service, CancellationToken cancellationToken) =>
        WriteAsync(id, resourceId, request, ifMatch, context, service, true, cancellationToken);

    private static Task<Results<NoContent, UnauthorizedHttpResult, ProblemHttpResult>> Revoke(Guid id, Guid resourceId,
        [FromBody] ChangeResourceAccessRequest request, [FromHeader(Name = "If-Match")] string? ifMatch, HttpContext context,
        IApprovalAuthorityService service, CancellationToken cancellationToken) =>
        WriteAsync(id, resourceId, request, ifMatch, context, service, false, cancellationToken);

    private static async Task<Results<NoContent, UnauthorizedHttpResult, ProblemHttpResult>> WriteAsync(Guid id, Guid resourceId,
        ChangeResourceAccessRequest request, string? ifMatch, HttpContext context, IApprovalAuthorityService service,
        bool assigned, CancellationToken cancellationToken)
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
            ? await service.AssignAsync(id, resourceId, request, actor, version, context.TraceIdentifier, cancellationToken)
            : await service.RevokeAsync(id, resourceId, request, actor, version, context.TraceIdentifier, cancellationToken);
        if (result.Kind != PrincipalWriteKind.Succeeded)
        {
            int status = result.Kind switch
            {
                PrincipalWriteKind.NotFound => StatusCodes.Status404NotFound,
                PrincipalWriteKind.PreconditionFailed => StatusCodes.Status412PreconditionFailed,
                PrincipalWriteKind.TargetDisabled or PrincipalWriteKind.TargetMissingCapability => StatusCodes.Status409Conflict,
                PrincipalWriteKind.InvalidRequest => StatusCodes.Status400BadRequest,
                _ => StatusCodes.Status403Forbidden
            };
            string? code = result.Kind switch
            {
                PrincipalWriteKind.RecentAuthenticationRequired => "recent_auth_required",
                PrincipalWriteKind.SelfChangeForbidden => "self_change_forbidden",
                PrincipalWriteKind.TargetDisabled => "target_disabled",
                PrincipalWriteKind.TargetMissingCapability => "target_missing_capability",
                _ => null
            };
            return TypedResults.Problem(statusCode: status,
                extensions: code is null ? null : new Dictionary<string, object?> { ["code"] = code });
        }
        uint currentVersion = result.Version ?? throw new InvalidOperationException("Authority command returned no principal version.");
        context.Response.Headers.ETag = ResourceEtags.Format(currentVersion);
        return TypedResults.NoContent();
    }
}
