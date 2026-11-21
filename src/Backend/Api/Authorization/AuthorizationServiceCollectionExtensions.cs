using Api.Authentication;
using Application.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace Api.Authorization;

public static class AuthorizationServiceCollectionExtensions
{
    public static IServiceCollection AddPamAuthorization(this IServiceCollection services)
    {
        services.AddSingleton<IStartupFilter, PamEndpointAuthorizationStartupFilter>();
        services.AddSingleton<IAuthorizationHandler, PamRecentAuthenticationHandler>();
        services.AddSingleton<IAuthorizationHandler, PamBootstrapOperationHandler>();
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, PamAuthorizationResultHandler>();
        services.AddAuthorizationBuilder()
            .AddPolicy(PamPolicies.RecentAuthentication, policy =>
                policy.RequireAuthenticatedUser().AddRequirements(new PamRecentAuthenticationRequirement()))
            .AddPolicy(PamPolicies.PermanentAdministrator, policy => policy.RequireAuthenticatedUser()
                .RequireAssertion(context => !context.User.HasClaim(PamClaimTypes.Bootstrap, "true")))
            .AddPamPermission(PamPermissions.BootstrapRead)
            .AddPamPermission(PamPermissions.RequestsCreate)
            .AddPamPermission(PamPermissions.RequestsReadOwn)
            .AddPamPermission(PamPermissions.ResourcesReadAll)
            .AddPamPermission(PamPermissions.ResourcesReadScoped)
            .AddPamPermission(PamPermissions.ResourcesManage)
            .AddPamPermission(PamPermissions.PrincipalsRead)
            .AddPamPermission(PamPermissions.PrincipalsManage)
            .AddPamPermission(PamPermissions.RolesRead)
            .AddPamPermission(PamPermissions.RolesAssign)
            .AddPamPermission(PamPermissions.ResourceAccessRead)
            .AddPamPermission(PamPermissions.ResourceAccessAssign)
            .AddPamPermission(PamPermissions.EligibilityRead)
            .AddPamPermission(PamPermissions.EligibilityAssign)
            .AddPamPermission(PamPermissions.ApprovalAuthorityAssign)
            .AddPamPermission(PamPermissions.ApprovalAuthorityRead);
        return services;
    }

    private static AuthorizationBuilder AddPamPermission(this AuthorizationBuilder builder, string permission) =>
        builder.AddPolicy(permission, policy => policy.RequireAuthenticatedUser()
            .RequireRole(PamPermissionRoles.For(permission)).AddRequirements(new PamBootstrapOperationRequirement(permission)));

}
