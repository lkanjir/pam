using Api.Resources;
using Application.Authorization;
using Application.Common.Pagination;
using Application.Principals;
using Microsoft.AspNetCore.Http.HttpResults;

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
}
