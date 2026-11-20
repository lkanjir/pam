using Api.Authentication;
using Application.Authorization;
using Application.Common.Pagination;
using Application.Resources;
using Application.Sessions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

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
                + "duration, approval and ticket requirements. The management list requires resources.read_all. "
                + "Uses limit and cursor pagination.")
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status400BadRequest);
        resources.MapGet("/{id:guid}", GetById).WithName(GetByIdRouteName)
            .WithDescription("Returns a strong ETag identifying the resource version for conditional updates.");
        resources.MapPost("", Create).ProducesValidationProblem();
        resources.MapPut("/{id:guid}", Update).WithResourceVersion().ProducesValidationProblem()
            .WithDescription("Requires one strong resource ETag in If-Match. Missing preconditions return 428; "
                + "a stale version or concurrent write returns 412 without changing the resource or its audit.")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);
        resources.MapDelete("/{id:guid}", Delete).WithResourceVersion()
            .WithDescription("Requires one strong ETag in If-Match. Missing preconditions return 428; "
                + "a stale version or concurrent write returns 412 without deleting or auditing the resource.")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);

        return endpoints;
    }

    private static async Task<Results<Ok<CursorPage<ResourceResponse>>, UnauthorizedHttpResult, ForbidHttpResult>> List(
        [AsParameters] ResourceListQuery query,
        HttpContext context,
        IResourceService resourceService,
        IAuthorizationService authorization,
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

        if (!(await authorization.AuthorizeAsync(context.User, PamPermissions.ResourcesReadAll)).Succeeded)
        {
            return TypedResults.Forbid();
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

    private static async Task<Results<Ok<ResourceResponse>, NotFound, UnauthorizedHttpResult, ProblemHttpResult>> Update(
        Guid id,
        UpdateResourceRequest request,
        [FromHeader(Name = "If-Match")] string? ifMatch,
        HttpContext context,
        IResourceService resourceService,
        CancellationToken cancellationToken)
    {
        if (!PamClaims.TryRead(context.User, out var identity))
        {
            return TypedResults.Unauthorized();
        }

        if (ResourceEtags.RequireVersion(context.Request, ifMatch, out uint version) is { } precondition)
        {
            return precondition;
        }

        var actor = new PrincipalSnapshot(
            identity.Id,
            identity.PublicId,
            identity.DisplayName,
            identity.Issuer,
            identity.Subject);

        var result = await resourceService.UpdateAsync(
            id,
            request,
            actor,
            context.TraceIdentifier,
            version,
            cancellationToken);

        if (result.Kind == ResourceWriteKind.Conflict)
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status412PreconditionFailed);
        }

        if (result.Kind == ResourceWriteKind.NotFound)
        {
            return TypedResults.NotFound();
        }

        var resource = result.Resource ?? throw new InvalidOperationException("Update returned no resource.");
        context.Response.Headers.ETag = ResourceEtags.Format(resource.Version);
        return TypedResults.Ok(resource);
    }

    private static async Task<Results<NoContent, NotFound, UnauthorizedHttpResult, ProblemHttpResult>> Delete(
        Guid id,
        [FromHeader(Name = "If-Match")] string? ifMatch,
        HttpContext context,
        IResourceService resourceService,
        CancellationToken cancellationToken)
    {
        if (!PamClaims.TryRead(context.User, out var identity))
        {
            return TypedResults.Unauthorized();
        }

        if (ResourceEtags.RequireVersion(context.Request, ifMatch, out uint version) is { } precondition)
        {
            return precondition;
        }

        var actor = new PrincipalSnapshot(
            identity.Id,
            identity.PublicId,
            identity.DisplayName,
            identity.Issuer,
            identity.Subject);

        var result = await resourceService.DeleteAsync(
            id,
            actor,
            context.TraceIdentifier,
            version,
            cancellationToken);

        if (result == ResourceWriteKind.Conflict)
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status412PreconditionFailed);
        }

        return result == ResourceWriteKind.Succeeded ? TypedResults.NoContent() : TypedResults.NotFound();
    }
}
