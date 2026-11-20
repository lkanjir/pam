using Application.Authorization;

namespace Api.Authorization;

public static class AuthorizationServiceCollectionExtensions
{
    public static IServiceCollection AddPamAuthorization(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy(PamPermissions.RequestsCreate, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.RequestsCreate)))
            .AddPolicy(PamPermissions.RequestsReadOwn, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.RequestsReadOwn)))
            .AddPolicy(PamPermissions.ResourcesReadAll, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.ResourcesReadAll)));
        return services;
    }
}
