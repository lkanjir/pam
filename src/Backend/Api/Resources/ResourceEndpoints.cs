using Api.Authentication;
using Application.Common.Pagination;
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

        resources.MapGet("", List)
            .WithSummary("List managed resources or the caller's requestable resources")
            .WithDescription("Set requestable=true to include only active resources with active entitlements "
                + "enabled for the current user. Each item then includes the available entitlements and their "
                + "duration, approval and ticket requirements. Uses limit and cursor pagination.")
            .ProducesProblem(StatusCodes.Status400BadRequest);
        resources.MapGet("/{id:guid}", GetById).WithName(GetByIdRouteName)
            .WithDescription("Returns a strong ETag identifying the resource version for conditional updates.");
        resources.MapPost("", Create).ProducesValidationProblem();
        resources.MapPut("/{id:guid}", Update).ProducesValidationProblem();
        resources.MapDelete("/{id:guid}", Delete).ProducesProblem(StatusCodes.Status400BadRequest);

        return endpoints;
    }

    private static async Task<Results<Ok<CursorPage<ResourceResponse>>, UnauthorizedHttpResult>> List(
        [AsParameters] ResourceListQuery query,
        HttpContext context,
        IResourceService resourceService,
        CancellationToken cancellationToken)
    {
        if (query.Requestable)
        {
            if (!PamClaims.TryRead(context.User, out var identity))
            {
                return TypedResults.Unauthorized();
            }

            var requestablePage = await resourceService.ListRequestableAsync(
                identity.Id,
                query.Limit,
                query.Cursor,
                cancellationToken);

            return TypedResults.Ok(requestablePage);
        }

        var page = await resourceService.ListAsync(
            query.Limit,
            query.Cursor,
            cancellationToken);

        return TypedResults.Ok(page);
    }

    private static async Task<Results<Ok<ResourceResponse>, NotFound>> GetById(
        Guid id,
        HttpContext context,
        IResourceService resourceService,
        CancellationToken cancellationToken)
    {
        var resource = await resourceService.GetByIdAsync(id, cancellationToken);
        if (resource is not null)
        {
            context.Response.Headers.ETag = ResourceEtags.Format(resource.Version);
        }

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

    private static async Task<Results<Ok<ResourceResponse>, NotFound, UnauthorizedHttpResult>> Update(
        Guid id,
        UpdateResourceRequest request,
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

        var resource = await resourceService.UpdateAsync(
            id,
            request,
            actor,
            context.TraceIdentifier,
            cancellationToken);

        return resource is null ? TypedResults.NotFound() : TypedResults.Ok(resource);
    }

    private static async Task<Results<NoContent, NotFound, UnauthorizedHttpResult>> Delete(
        Guid id,
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

        bool deleted = await resourceService.DeleteAsync(
            id,
            actor,
            context.TraceIdentifier,
            cancellationToken);

        return deleted ? TypedResults.NoContent() : TypedResults.NotFound();
    }
}
