using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace Api.Authentication;

public static class AuthenticationEndpoints
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/auth/login", () => Results.Challenge(
            properties: new AuthenticationProperties { RedirectUri = "/api/me" },
            authenticationSchemes: ["oidc"])).AllowAnonymous();

        endpoints.MapGet("/api/me", GetCurrentUser).RequireAuthorization();

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