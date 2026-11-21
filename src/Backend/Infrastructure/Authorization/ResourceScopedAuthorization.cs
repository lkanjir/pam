using Application.Authorization;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;

namespace Infrastructure.Authorization;

internal static class ResourceScopedAuthorization
{
    public static IQueryable<ManagedResource> VisibleResources(PamDbContext database, long principalId)
    {
        var roles = PamPermissionRoles.For(PamPermissions.ResourcesReadScoped);
        return database.ManagedResources.Where(resource => database.ResourcePrincipalBindings.Any(binding =>
                binding.ResourceId == resource.Id && binding.PrincipalId == principalId
                && binding.Kind == ResourceBindingKind.ViewResource && binding.IsActive)
            && database.Principals.Any(principal => principal.Id == principalId && principal.IsEnabled
                && principal.RoleAssignments.Any(assignment => roles.Contains(assignment.Role.Code))));
    }

    public static IQueryable<ManagedResource> RequesterResources(PamDbContext database, long principalId)
    {
        var roles = PamPermissionRoles.For(PamPermissions.RequestsCreate);
        return VisibleResources(database, principalId).Where(resource => database.PamRoleAssignments.Any(assignment =>
            assignment.PrincipalId == principalId && roles.Contains(assignment.Role.Code)));
    }
}
