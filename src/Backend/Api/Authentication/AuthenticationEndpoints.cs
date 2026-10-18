using Microsoft.AspNetCore.Authentication;

namespace Api.Authentication;

public static class AuthenticationEndpoints
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/api/auth/login", () => Results.Challenge(
            properties: new AuthenticationProperties { RedirectUri = "/api/me" },
            authenticationSchemes: ["oidc"])).AllowAnonymous();

        return endpoints;
    }
}