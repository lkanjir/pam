using Application.Authorization;
using Application.Common.Pagination;
using Application.Principals;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Api.Principals;

public static class PrincipalEndpoints
{
    public const string GetByIdRouteName = "Principal.GetById";

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
        endpoints.MapGet("/principals/{id:guid}", GetById)
            .WithTags("Principals")
            .WithName(GetByIdRouteName)
            .WithSummary("Read a PAM identity mapping")
            .WithDescription("Requires principals.read. Returns the immutable issuer/subject mapping and current enabled status, "
                + "including disabled accounts. No passwords or identity-provider credentials are returned.")
            .RequireAuthorization(PamPermissions.PrincipalsRead)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);
        return endpoints;
    }

    private static async Task<Ok<CursorPage<PrincipalResponse>>> List([AsParameters] PrincipalListQuery query,
        IPrincipalAdministrationService service, CancellationToken cancellationToken) =>
        TypedResults.Ok(await service.ListAsync(query.Limit, query.Cursor, cancellationToken));

    private static async Task<Results<Ok<PrincipalResponse>, NotFound>> GetById(Guid id,
        IPrincipalAdministrationService service, CancellationToken cancellationToken)
    {
        var principal = await service.GetByIdAsync(id, cancellationToken);
        return principal is null ? TypedResults.NotFound() : TypedResults.Ok(principal);
    }
}
