using Api.Resources;
using Application.Authorization;
using Application.Principals;
using Microsoft.AspNetCore.Http.HttpResults;

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
}
