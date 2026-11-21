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

public static class EligibilityEndpoints
{
    public static IEndpointRouteBuilder MapEligibilityEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/principals/{id:guid}/eligibility", List)
            .WithTags("Eligibility")
            .WithName("Principal.Eligibility.List")
            .WithSummary("Inspect a principal's retained entitlement eligibility")
            .WithDescription("Requires eligibility.read. Includes disabled rules, inactive entitlements and retired resources, including disabled principals. "
                + "Configured eligibility does not imply resource visibility or target access. Uses ascending entitlement public-ID pagination; limit defaults to 20, range 1–100. "
                + "Returns the principal aggregate ETag from the same database snapshot. No recent-auth is required for this read.")
            .RequireAuthorization(PamPermissions.EligibilityRead)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);
        endpoints.MapPut("/principals/{id:guid}/eligibility/{resourceId:guid}/{entitlementId:guid}", Assign).WithResourceVersion()
            .WithTags("Eligibility")
            .WithName("Principal.Eligibility.Assign")
            .WithSummary("Assign entitlement eligibility to one enabled requester")
            .WithDescription("Requires eligibility.assign, recent-auth, a reason and the target principal aggregate's current ETag in If-Match. "
                + "The target must already have requests.create through User; own assignment is allowed with that existing capability. "
                + "The entitlement must belong to the specified non-retired resource. Inactive configuration may be prepared but cannot be requested until active. "
                + "Eligibility creates no view binding, approval authority or target grant; normal request policy remains required. "
                + "Returns 204 and principal ETag. An already enabled rule with a current version is a no-op without duplicate audit.")
            .RequireAuthorization(PamPermissions.EligibilityAssign, PamPolicies.RecentAuthentication)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);
        endpoints.MapDelete("/principals/{id:guid}/eligibility/{resourceId:guid}/{entitlementId:guid}", Revoke).WithResourceVersion()
            .WithTags("Eligibility")
            .WithName("Principal.Eligibility.Revoke")
            .WithSummary("Revoke one entitlement eligibility rule")
            .WithDescription("Requires eligibility.assign, recent-auth, a JSON reason and the target principal aggregate's current ETag in If-Match. "
                + "Own removal is allowed, including roleless/disabled targets and retired resources. The entitlement must match the specified parent. "
                + "Visibility remains independent; a new visible but ineligible request follows the normal Denied policy. Owner history and identical replays remain stable. "
                + "Returns 204 and principal ETag; a current-version absent/disabled rule is a no-op. Existing issued target grants are not revoked by this command.")
            .RequireAuthorization(PamPermissions.EligibilityAssign, PamPolicies.RecentAuthentication)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);
        return endpoints;
    }

    private static async Task<Results<Ok<CursorPage<EligibilityResponse>>, NotFound>> List(Guid id,
        [AsParameters] EligibilityListQuery query, HttpContext context, IEligibilityService service, CancellationToken cancellationToken)
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
        Guid entitlementId, ChangeEligibilityRequest request, [FromHeader(Name = "If-Match")] string? ifMatch,
        HttpContext context, IEligibilityService service, CancellationToken cancellationToken) =>
        WriteAsync(id, resourceId, entitlementId, request, ifMatch, context, service, true, cancellationToken);

    private static Task<Results<NoContent, UnauthorizedHttpResult, ProblemHttpResult>> Revoke(Guid id, Guid resourceId,
        Guid entitlementId, [FromBody] ChangeEligibilityRequest request, [FromHeader(Name = "If-Match")] string? ifMatch,
        HttpContext context, IEligibilityService service, CancellationToken cancellationToken) =>
        WriteAsync(id, resourceId, entitlementId, request, ifMatch, context, service, false, cancellationToken);

    private static async Task<Results<NoContent, UnauthorizedHttpResult, ProblemHttpResult>> WriteAsync(Guid id, Guid resourceId,
        Guid entitlementId, ChangeEligibilityRequest request, string? ifMatch, HttpContext context,
        IEligibilityService service, bool assigned, CancellationToken cancellationToken)
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
            ? await service.AssignAsync(id, resourceId, entitlementId, request, actor, version, context.TraceIdentifier, cancellationToken)
            : await service.RevokeAsync(id, resourceId, entitlementId, request, actor, version, context.TraceIdentifier, cancellationToken);
        if (result.Kind != PrincipalWriteKind.Succeeded)
        {
            return WriteProblem(result.Kind);
        }
        uint currentVersion = result.Version ?? throw new InvalidOperationException("Eligibility command returned no principal version.");
        context.Response.Headers.ETag = ResourceEtags.Format(currentVersion);
        return TypedResults.NoContent();
    }

    private static ProblemHttpResult WriteProblem(PrincipalWriteKind kind)
    {
        int status = kind switch
        {
            PrincipalWriteKind.NotFound => StatusCodes.Status404NotFound,
            PrincipalWriteKind.PreconditionFailed => StatusCodes.Status412PreconditionFailed,
            PrincipalWriteKind.TargetDisabled or PrincipalWriteKind.TargetMissingCapability => StatusCodes.Status409Conflict,
            PrincipalWriteKind.InvalidRequest => StatusCodes.Status400BadRequest,
            _ => StatusCodes.Status403Forbidden
        };
        string? code = kind switch
        {
            PrincipalWriteKind.RecentAuthenticationRequired => "recent_auth_required",
            PrincipalWriteKind.TargetDisabled => "target_disabled",
            PrincipalWriteKind.TargetMissingCapability => "target_missing_capability",
            _ => null
        };
        return TypedResults.Problem(statusCode: status,
            extensions: code is null ? null : new Dictionary<string, object?> { ["code"] = code });
    }
}
