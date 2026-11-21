using Api.Resources;
using Application.Authorization;
using Application.Bootstrap;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Api.Authorization;

public static class BootstrapEndpoints
{
    public static IEndpointRouteBuilder MapBootstrapEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/authorization/bootstrap", Get)
            .WithTags("Installation")
            .WithName("Bootstrap.Get")
            .WithSummary("Inspect the controlled administrator handover")
            .WithDescription("Requires bootstrap.read. This read never initializes an installation or grants access. "
                + "An initialized installation returns its ETag. Bootstrap identity references remain after retirement for audit.")
            .RequireAuthorization(PamPermissions.BootstrapRead)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);
        return endpoints;
    }

    private static async Task<Ok<BootstrapStateResponse>> Get(HttpContext context, IBootstrapService service,
        CancellationToken cancellationToken)
    {
        var state = await service.GetAsync(cancellationToken);
        if (state.Version is { } version)
        {
            context.Response.Headers.ETag = ResourceEtags.Format(version);
        }
        return TypedResults.Ok(state);
    }
}
