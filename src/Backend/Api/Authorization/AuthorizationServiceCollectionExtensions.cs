using Application.Authorization;

namespace Api.Authorization;

public static class AuthorizationServiceCollectionExtensions
{
    public static IServiceCollection AddPamAuthorization(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy(PamPermissions.RequestsReadOwn, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamRoleCodes.User))
            .AddPolicy(PamPermissions.ResourcesReadAll, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamRoleCodes.Admin));
        return services;
    }
}
