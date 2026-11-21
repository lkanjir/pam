using Api.Authentication;
using Api.Authorization;
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
            .WithName("Resource.List")
            .WithMetadata(new PamConditionalPermissionMetadata(PamPermissions.ResourcesReadAll, PamPermissions.RequestsCreate, PamPermissions.ResourcesReadScoped))
            .WithSummary("List managed resources or the caller's requestable resources")
            .WithDescription("Set requestable=true to include only active resources with active entitlements "
                + "enabled for the current user with an explicit active view binding. Each item then includes the available entitlements and their "
                + "duration, approval and ticket requirements. The management list requires resources.read_all; requestable=true requires requests.create and resources.read_scoped. "
                + "Uses limit and cursor pagination.")
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status400BadRequest);
        resources.MapGet("/{id:guid}", GetById).WithName(GetByIdRouteName)
            .WithMetadata(new PamConditionalPermissionMetadata(PamPermissions.ResourcesReadAll, PamPermissions.ResourcesReadScoped))
            .WithSummary("Read a resource through management or explicit scoped visibility")
            .WithDescription("Requires resources.read_all, or resources.read_scoped with a current active view binding. "
                + "Hidden, missing and retired resources are indistinguishable 404s for a scoped caller. "
                + "Returns a strong resource ETag; visibility grants no write or target-access permission.")
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);
        resources.MapPost("", Create).ProducesValidationProblem()
            .RequireAuthorization(PamPermissions.ResourcesManage, PamPolicies.RecentAuthentication)
            .WithName("Resource.Create")
            .WithSummary("Create a managed resource")
            .WithDescription("Requires resources.manage and original OIDC authentication within ten minutes. "
                + "Creates the resource and its audit atomically; grants no target access or approval authority.")
            .ProducesProblem(StatusCodes.Status403Forbidden);
        resources.MapPut("/{id:guid}", Update).WithResourceVersion().ProducesValidationProblem()
            .RequireAuthorization(PamPermissions.ResourcesManage, PamPolicies.RecentAuthentication)
            .WithName("Resource.Update")
            .WithSummary("Update a managed resource")
            .WithDescription("Requires one strong resource ETag in If-Match. Missing preconditions return 428; "
                + "a stale version or concurrent write returns 412 without changing the resource or its audit.")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);
        resources.MapDelete("/{id:guid}", Delete).WithResourceVersion()
            .RequireAuthorization(PamPermissions.ResourcesManage, PamPolicies.RecentAuthentication)
            .WithName("Resource.Delete")
            .WithSummary("Retire a managed resource")
            .WithDescription("Requires one strong ETag in If-Match. Missing preconditions return 428; "
                + "a stale version or concurrent write returns 412 without deleting or auditing the resource.")
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .ProducesProblem(StatusCodes.Status403Forbidden)
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
            if (!(await authorization.AuthorizeAsync(context.User, PamPermissions.RequestsCreate)).Succeeded
                || !(await authorization.AuthorizeAsync(context.User, PamPermissions.ResourcesReadScoped)).Succeeded)
            {
                return TypedResults.Forbid();
            }

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

    private static async Task<Results<Ok<ResourceResponse>, NotFound, UnauthorizedHttpResult, ForbidHttpResult>> GetById(
        Guid id,
        HttpContext context,
        IResourceService resourceService,
        IAuthorizationService authorization,
        CancellationToken cancellationToken)
    {
        ResourceResponse? resource;
        if ((await authorization.AuthorizeAsync(context.User, PamPermissions.ResourcesReadAll)).Succeeded)
        {
            resource = await resourceService.GetByIdAsync(id, cancellationToken);
        }
        else
        {
            if (!(await authorization.AuthorizeAsync(context.User, PamPermissions.ResourcesReadScoped)).Succeeded)
            {
                return TypedResults.Forbid();
            }
            if (!PamClaims.TryRead(context.User, out var identity))
            {
                return TypedResults.Unauthorized();
            }
            resource = await resourceService.GetScopedByIdAsync(id, identity.Id, cancellationToken);
        }
        if (resource is not null)
        {
            context.Response.Headers.ETag = ResourceEtags.Format(resource.Version);
        }

        return resource is null ? TypedResults.NotFound() : TypedResults.Ok(resource);
    }

    public static async Task<Results<CreatedAtRoute<ResourceResponse>, UnauthorizedHttpResult, ForbidHttpResult, ProblemHttpResult>> Create(
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

        var result = await resourceService.CreateAsync(
            request,
            new AdministrativeActor(actor, PamAuthenticationTime.Read(context.User)),
            context.TraceIdentifier,
            cancellationToken);

        if (result.Kind == ResourceWriteKind.Forbidden)
        {
            return TypedResults.Forbid();
        }
        if (result.Kind == ResourceWriteKind.RecentAuthenticationRequired)
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status403Forbidden,
                title: "Recent authentication is required.",
                extensions: new Dictionary<string, object?> { ["code"] = "recent_auth_required" });
        }

        var resource = result.Resource ?? throw new InvalidOperationException("Create returned no resource.");
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
            new AdministrativeActor(actor, PamAuthenticationTime.Read(context.User)),
            context.TraceIdentifier,
            version,
            cancellationToken);

        if (result.Kind is ResourceWriteKind.Forbidden or ResourceWriteKind.RecentAuthenticationRequired)
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status403Forbidden,
                extensions: result.Kind == ResourceWriteKind.RecentAuthenticationRequired
                    ? new Dictionary<string, object?> { ["code"] = "recent_auth_required" } : null);
        }

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
            new AdministrativeActor(actor, PamAuthenticationTime.Read(context.User)),
            context.TraceIdentifier,
            version,
            cancellationToken);

        if (result is ResourceWriteKind.Forbidden or ResourceWriteKind.RecentAuthenticationRequired)
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status403Forbidden,
                extensions: result == ResourceWriteKind.RecentAuthenticationRequired
                    ? new Dictionary<string, object?> { ["code"] = "recent_auth_required" } : null);
        }

        if (result == ResourceWriteKind.Conflict)
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status412PreconditionFailed);
        }

        return result == ResourceWriteKind.Succeeded ? TypedResults.NoContent() : TypedResults.NotFound();
    }
}
