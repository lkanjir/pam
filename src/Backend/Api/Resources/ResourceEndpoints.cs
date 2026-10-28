using Api.Authentication;
using Application.Resources;
using Application.Sessions;
using Microsoft.AspNetCore.Http.HttpResults;

namespace Api.Resources;

public static class ResourceEndpoints
{
    public const string GetByIdRouteName = "Resource.GetById";

    public static IEndpointRouteBuilder MapResourceEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var resources = endpoints.MapGroup("/resources").WithTags("Resources");

        resources.MapGet("/{id:guid}", GetById).WithName(GetByIdRouteName);
        resources.MapPost("", Create).ProducesValidationProblem();

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

    public static async Task<Results<CreatedAtRoute<ResourceResponse>, UnauthorizedHttpResult>> Create(
        CreateResourceRequest request,
        HttpContext context,
        IResourceService resourceService,
        CancellationToken cancellationToken)
    {
        if (!PamClaims.TryRead(context.User, out var identity))
        {
            return TypedResults.Unauthorized();
        }

        var actor = new PrincipalSnapshot(
            identity.Id,
            identity.PublicId,
            identity.DisplayName,
            identity.Issuer,
            identity.Subject);

        var resource = await resourceService.CreateAsync(
            request,
            actor,
            context.TraceIdentifier,
            cancellationToken);

        return TypedResults.CreatedAtRoute(
            resource,
            GetByIdRouteName,
            new { id = resource.Id });
    }
}
