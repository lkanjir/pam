using System.Security.Claims;
using Application.Sessions;
using Infrastructure.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;

namespace Api.Authentication;

public static class AuthenticationEndpoints
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/auth/login", () => Results.Challenge(
            properties: new AuthenticationProperties { RedirectUri = "/api/me" },
            authenticationSchemes: ["oidc"])).AllowAnonymous();

        endpoints.MapGet("/auth/reauthenticate", Reauthenticate)
            .RequireAuthorization()
            .WithName("Authentication.Reauthenticate")
            .WithSummary("Reauthenticate the current PAM identity through Keycloak")
            .WithDescription("Requests a new authentication using max_age=0, bound to the original active PAM session. "
                + "The callback must preserve the identity and authentication freshness. Returns to /api/me; "
                + "no privileged command is replayed.")
            .Produces(StatusCodes.Status302Found)
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden);

        endpoints.MapGet("/me", GetCurrentUser);

        endpoints.MapGet("/auth/antiforgery", (HttpContext context, IAntiforgery antiforgery) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(context);
            return TypedResults.Ok(new AntiforgeryTokenResponse(tokens.RequestToken!));
        });

        endpoints.MapPost("/auth/logout", async (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            await context.EndPamSessionAsync(SessionEndReason.Logout);
            return TypedResults.NoContent();
        });

        return endpoints;
    }

    private static async Task<Results<ChallengeHttpResult, UnauthorizedHttpResult, ProblemHttpResult>> Reauthenticate(
        HttpContext context, IAuthenticationService authentication)
    {
        var original = await authentication.AuthenticateAsync(context, CookieAuthenticationDefaults.AuthenticationScheme);
        if (!original.Succeeded || original.Principal is null || !PamClaims.TryRead(original.Principal, out var identity))
        {
            return TypedResults.Unauthorized();
        }

        string? hash = original.Properties?.GetString(SessionTicketMetadata.SessionIdHash);
        if (hash is null || !SessionIdentifier.IsValid(hash))
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status403Forbidden,
                title: "The original session cannot be bound to reauthentication.");
        }

        return TypedResults.Challenge(PamReauthentication.CreateChallenge(identity, hash), ["oidc"]);
    }

    private static IResult GetCurrentUser(ClaimsPrincipal user, HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";

        if (!PamClaims.TryRead(user, out var identity))
        {
            return TypedResults.Unauthorized();
        }

        var response = new CurrentUserResponse(identity.PublicId, identity.DisplayName, [.. identity.Roles]);

        return TypedResults.Ok(response);
    }
}
