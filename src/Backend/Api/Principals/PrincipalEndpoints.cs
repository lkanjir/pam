using Application.Authorization;
using Application.Common.Pagination;
using Application.Principals;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Api.Principals;

public static class PrincipalEndpoints
{
    public static IEndpointRouteBuilder MapPrincipalEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/principals", List)
            .WithTags("Principals")
            .WithName("Principal.List")
            .WithSummary("List PAM identity mappings")
            .WithDescription("Requires principals.read. Includes enabled and disabled mappings, without credentials. "
                + "Uses ascending public-ID cursor pagination; limit defaults to 20, range 1–100. No recent-auth is required for this read.")
            .RequireAuthorization(PamPermissions.PrincipalsRead)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);
        return endpoints;
    }

    private static async Task<Ok<CursorPage<PrincipalResponse>>> List([AsParameters] PrincipalListQuery query,
        IPrincipalAdministrationService service, CancellationToken cancellationToken) =>
        TypedResults.Ok(await service.ListAsync(query.Limit, query.Cursor, cancellationToken));
}
