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
            .AddPolicy(PamPermissions.ResourcesReadScoped, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.ResourcesReadScoped)))
            .AddPolicy(PamPermissions.ResourcesManage, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.ResourcesManage)))
            .AddPolicy(PamPermissions.PrincipalsRead, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.PrincipalsRead)))
            .AddPolicy(PamPermissions.PrincipalsManage, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.PrincipalsManage)))
            .AddPolicy(PamPermissions.RolesRead, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.RolesRead)))
            .AddPolicy(PamPermissions.RolesAssign, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.RolesAssign)))
            .AddPolicy(PamPermissions.ResourceAccessRead, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.ResourceAccessRead)))
            .AddPolicy(PamPermissions.ResourceAccessAssign, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.ResourceAccessAssign)))
            .AddPolicy(PamPermissions.EligibilityRead, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.EligibilityRead)))
            .AddPolicy(PamPermissions.EligibilityAssign, policy =>
                policy.RequireAuthenticatedUser().RequireRole(PamPermissionRoles.For(PamPermissions.EligibilityAssign)));
        return services;
    }
}
