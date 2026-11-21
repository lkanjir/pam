using Api.Authentication;
using Api.Resources;
using Application.Authorization;
using Application.Bootstrap;
using Application.Sessions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

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
        endpoints.MapPost("/authorization/bootstrap/complete", Complete).WithResourceVersion()
            .WithTags("Installation")
            .WithName("Bootstrap.Complete")
            .WithSummary("Permanently retire the temporary bootstrap administrator")
            .WithDescription("Requires bootstrap.complete, a permanent Admin's authenticated session, original recent-auth, "
                + "CSRF token, reason and installation ETag in If-Match. Atomically disables the temporary identity, removes all "
                + "its roles, deactivates resource/eligibility assignments and audits completion. No reset or reactivation exists. "
                + "Redis cleanup follows independently; completed bootstrap identities are rejected immediately by current DB identity checks. "
                + "An already completed state with a current ETag is a no-op; missing installation returns 409.")
            .RequireAuthorization(PamPermissions.BootstrapComplete, PamPolicies.RecentAuthentication, PamPolicies.PermanentAdministrator)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status412PreconditionFailed)
            .ProducesProblem(StatusCodes.Status428PreconditionRequired);
        return endpoints;
    }

    private static async Task<Results<Ok<BootstrapStateResponse>, UnauthorizedHttpResult, ProblemHttpResult>> Complete(
        CompleteBootstrapRequest request, [FromHeader(Name = "If-Match")] string? ifMatch, HttpContext context,
        IBootstrapService service, CancellationToken cancellationToken)
    {
        if (!PamClaims.TryRead(context.User, out var identity))
        {
            return TypedResults.Unauthorized();
        }
        if (ResourceEtags.RequireVersion(context.Request, ifMatch, out uint version) is { } precondition)
        {
            return precondition;
        }
        var actor = new AdministrativeActor(new PrincipalSnapshot(identity.Id, identity.PublicId, identity.DisplayName,
            identity.Issuer, identity.Subject), PamAuthenticationTime.Read(context.User));
        var result = await service.CompleteAsync(request, actor, version, context.TraceIdentifier, cancellationToken);
        if (result.Kind != BootstrapWriteKind.Succeeded)
        {
            int status = result.Kind switch
            {
                BootstrapWriteKind.NotInitialized => StatusCodes.Status409Conflict,
                BootstrapWriteKind.PreconditionFailed => StatusCodes.Status412PreconditionFailed,
                BootstrapWriteKind.InvalidRequest => StatusCodes.Status400BadRequest,
                _ => StatusCodes.Status403Forbidden
            };
            string? code = result.Kind switch
            {
                BootstrapWriteKind.RecentAuthenticationRequired => "recent_auth_required",
                BootstrapWriteKind.NotInitialized => "bootstrap_not_initialized",
                _ => null
            };
            return TypedResults.Problem(statusCode: status,
                extensions: code is null ? null : new Dictionary<string, object?> { ["code"] = code });
        }
        var state = result.State ?? throw new InvalidOperationException("Bootstrap completion returned no state.");
        if (state.Version is { } currentVersion)
        {
            context.Response.Headers.ETag = ResourceEtags.Format(currentVersion);
        }
        return TypedResults.Ok(state);
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
