using Api.Resources;
using Application.Authorization;
using Application.Common.Pagination;
using Application.Principals;
using Microsoft.AspNetCore.Http.HttpResults;

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
}
