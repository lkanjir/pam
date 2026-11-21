using Application.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace Api.Authorization;

public static class AuthorizationServiceCollectionExtensions
{
    public static IServiceCollection AddPamAuthorization(this IServiceCollection services)
    {
        services.AddSingleton<IStartupFilter, PamEndpointAuthorizationStartupFilter>();
        services.AddSingleton<IAuthorizationHandler, PamRecentAuthenticationHandler>();
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, PamAuthorizationResultHandler>();
        services.AddAuthorizationBuilder()
            .AddPolicy(PamPolicies.RecentAuthentication, policy =>
                policy.RequireAuthenticatedUser().AddRequirements(new PamRecentAuthenticationRequirement()))
            .AddPolicy(PamPermissions.RequestsCreate, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.RequestsCreate)))
            .AddPolicy(PamPermissions.RequestsReadOwn, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.RequestsReadOwn)))
            .AddPolicy(PamPermissions.ResourcesReadAll, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.ResourcesReadAll)))
            .AddPolicy(PamPermissions.ResourcesManage, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.ResourcesManage)))
            .AddPolicy(PamPermissions.PrincipalsRead, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.PrincipalsRead)))
            .AddPolicy(PamPermissions.PrincipalsManage, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.PrincipalsManage)));
        return services;
    }
}
