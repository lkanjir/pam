using Api.Authentication;
using Api.Authorization;
using Api.Resources;
using Application.Authorization;
using Application.Common.Pagination;
using Application.Principals;
using Application.Sessions;
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
                + "including disabled accounts. Returns the principal aggregate's strong ETag for conditional administrative changes. "
                + "No passwords or identity-provider credentials are returned.")
            .RequireAuthorization(PamPermissions.PrincipalsRead)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);
        endpoints.MapPost("/principals", Create)
            .WithTags("Principals")
            .WithName("Principal.Create")
            .WithSummary("Map a verified Keycloak identity to a disabled PAM account")
            .WithDescription("Requires principals.manage and recent-auth. Supply the validated realm issuer and exact opaque subject "
                + "from Keycloak, not an email address. Creates a disabled mapping without roles and an atomic audit with a required reason. "
                + "Issuer and subject cannot be edited later. An existing mapping returns 409; no passwords are accepted.")
            .RequireAuthorization(PamPermissions.PrincipalsManage, PamPolicies.RecentAuthentication)
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status409Conflict);
        return endpoints;
    }

    private static async Task<Ok<CursorPage<PrincipalResponse>>> List([AsParameters] PrincipalListQuery query,
        IPrincipalAdministrationService service, CancellationToken cancellationToken) =>
        TypedResults.Ok(await service.ListAsync(query.Limit, query.Cursor, cancellationToken));

    private static async Task<Results<Ok<PrincipalResponse>, NotFound>> GetById(Guid id, HttpContext context,
        IPrincipalAdministrationService service, CancellationToken cancellationToken)
    {
        var principal = await service.GetByIdAsync(id, cancellationToken);
        if (principal is not null)
        {
            context.Response.Headers.ETag = ResourceEtags.Format(principal.Version);
        }
        return principal is null ? TypedResults.NotFound() : TypedResults.Ok(principal);
    }

    private static async Task<Results<CreatedAtRoute<PrincipalResponse>, UnauthorizedHttpResult, ProblemHttpResult>> Create(
        CreatePrincipalRequest request, HttpContext context, IPrincipalAdministrationService service, CancellationToken cancellationToken)
    {
        if (!PamClaims.TryRead(context.User, out var identity))
        {
            return TypedResults.Unauthorized();
        }
        var snapshot = new PrincipalSnapshot(identity.Id, identity.PublicId, identity.DisplayName, identity.Issuer, identity.Subject);
        var result = await service.CreateAsync(request, new AdministrativeActor(snapshot, PamAuthenticationTime.Read(context.User)),
            context.TraceIdentifier, cancellationToken);
        if (result.Kind != PrincipalWriteKind.Succeeded)
        {
            int status = result.Kind switch
            {
                PrincipalWriteKind.Conflict => StatusCodes.Status409Conflict,
                PrincipalWriteKind.InvalidIdentity => StatusCodes.Status400BadRequest,
                _ => StatusCodes.Status403Forbidden
            };
            return TypedResults.Problem(statusCode: status,
                extensions: result.Kind == PrincipalWriteKind.RecentAuthenticationRequired
                    ? new Dictionary<string, object?> { ["code"] = "recent_auth_required" } : null);
        }
        var principal = result.Principal ?? throw new InvalidOperationException("Mapping returned no principal.");
        return TypedResults.CreatedAtRoute(principal, GetByIdRouteName, new { id = principal.Id });
    }
}
