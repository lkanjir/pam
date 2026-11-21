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

public static class ResourceAccessEndpoints
{
    public static IEndpointRouteBuilder MapResourceAccessEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/principals/{id:guid}/resource-access", List)
            .WithTags("Resource access")
            .WithName("Principal.ResourceAccess.List")
            .WithSummary("Inspect a principal's explicit resource visibility assignments")
            .WithDescription("Requires resource_access.read. Includes inactive assignments and retired resources, and works for disabled principals. "
                + "Active assignments on retired resources do not grant access. Uses ascending resource public-ID pagination; limit defaults to 20, range 1–100. "
                + "Returns the target principal aggregate ETag from the same database snapshot. No recent-auth is required for this read.")
            .RequireAuthorization(PamPermissions.ResourceAccessRead)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);
        endpoints.MapPut("/principals/{id:guid}/resource-access/{resourceId:guid}", Assign).WithResourceVersion()
            .WithTags("Resource access")
            .WithName("Principal.ResourceAccess.Assign")
            .WithSummary("Assign explicit resource visibility to one enabled principal")
            .WithDescription("Requires resource_access.assign, recent-auth, a reason and the target principal aggregate's current ETag in If-Match. "
                + "The target must already have resources.read_scoped through User or Approver. Own visibility assignments are allowed with that existing capability. "
                + "Visibility grants no entitlement eligibility, target access or approval authority. Retired resources return 404. "
                + "Returns 204 and a new principal ETag; an already active assignment with the current version is a no-op without duplicate audit.")
            .RequireAuthorization(PamPermissions.ResourceAccessAssign, PamPolicies.RecentAuthentication)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);
        return endpoints;
    }

    private static async Task<Results<Ok<CursorPage<ResourceAccessResponse>>, NotFound>> List(Guid id,
        [AsParameters] ResourceAccessListQuery query, HttpContext context, IResourceAccessService service,
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

    private static async Task<Results<NoContent, UnauthorizedHttpResult, ProblemHttpResult>> Assign(Guid id, Guid resourceId,
        ChangeResourceAccessRequest request, [FromHeader(Name = "If-Match")] string? ifMatch, HttpContext context,
        IResourceAccessService service, CancellationToken cancellationToken)
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
        var result = await service.AssignAsync(id, resourceId, request,
            new(snapshot, PamAuthenticationTime.Read(context.User)), version, context.TraceIdentifier, cancellationToken);
        if (result.Kind != PrincipalWriteKind.Succeeded)
        {
            return WriteProblem(result.Kind);
        }
        uint currentVersion = result.Version ?? throw new InvalidOperationException("Visibility command returned no principal version.");
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
