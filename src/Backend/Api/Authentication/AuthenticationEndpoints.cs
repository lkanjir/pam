using System.Security.Claims;
using Application.Sessions;
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

    private static IResult GetCurrentUser(ClaimsPrincipal user, HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";

        if (!PamClaims.TryRead(user, out var identity)) return TypedResults.Unauthorized();
        var response = new CurrentUserResponse(identity.PublicId, identity.DisplayName, [.. identity.Roles]);

        return TypedResults.Ok(response);
    }
}
