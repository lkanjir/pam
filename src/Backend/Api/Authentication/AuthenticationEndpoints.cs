using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

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
            context.Features.Set(new SessionTermination("logout"));

            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return TypedResults.NoContent();
        });
        
        return endpoints;
    }

    private static IResult GetCurrentUser(ClaimsPrincipal user, HttpContext context)
    {
        context.Response.Headers.CacheControl = "no-store";

        var publicIdClaim = user.FindFirst("pam_public_id")?.Value;
        if (!Guid.TryParse(publicIdClaim, out var publicId)) return TypedResults.Unauthorized();

        var response = new CurrentUserResponse(publicId, user.Identity?.Name ?? string.Empty,
            [.. user.FindAll("pam_role").Select(claim => claim.Value)]);
        
        return TypedResults.Ok(response);
    }
}
