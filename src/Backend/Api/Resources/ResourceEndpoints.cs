using Application.Resources;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Api.Resources;

public static class ResourceEndpoints
{
    public const string GetByIdRouteName = "Resource.GetById";

    public static IEndpointRouteBuilder MapResourceEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var resources = endpoints.MapGroup("/resources").WithTags("Resources");

        resources.MapGet("/{id:guid}", GetById).WithName(GetByIdRouteName);

        return endpoints;
    }

    private static async Task<Results<Ok<ResourceResponse>, NotFound>> GetById(
        Guid id,
        IResourceService resourceService,
        CancellationToken cancellationToken)
    {
        var resource = await resourceService.GetByIdAsync(id, cancellationToken);
        return resource is null ? TypedResults.NotFound() : TypedResults.Ok(resource);
    }
}
