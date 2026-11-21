using Application.Authorization;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;

namespace Infrastructure.Authorization;

internal static class ResourceScopedAuthorization
{
    public static IQueryable<ManagedResource> VisibleResources(PamDbContext database, long principalId) =>
        ReadResources(database, principalId, includeApprovalContext: true);

    private static IQueryable<ManagedResource> ReadResources(PamDbContext database, long principalId, bool includeApprovalContext)
    {
        var roles = PamPermissionRoles.For(PamPermissions.ResourcesReadScoped);
        var approvalRoles = ResourceBindingRoles.For(ResourceBindingKind.ApproveRequests);
        return database.ManagedResources.Where(resource => database.ResourcePrincipalBindings.Any(binding =>
                binding.ResourceId == resource.Id && binding.PrincipalId == principalId
                && binding.IsActive && (binding.Kind == ResourceBindingKind.ViewResource
                    || (includeApprovalContext && binding.Kind == ResourceBindingKind.ApproveRequests
                        && database.PamRoleAssignments.Any(assignment => assignment.PrincipalId == principalId
                            && approvalRoles.Contains(assignment.Role.Code)))))
            && database.Principals.Any(principal => principal.Id == principalId && principal.IsEnabled
                && principal.RoleAssignments.Any(assignment => roles.Contains(assignment.Role.Code))));
    }

    public static IQueryable<ManagedResource> RequesterResources(PamDbContext database, long principalId)
    {
        var roles = PamPermissionRoles.For(PamPermissions.RequestsCreate);
        // Approval-context visibility never substitutes for a requester's explicit view assignment.
        return ReadResources(database, principalId, includeApprovalContext: false).Where(resource => database.PamRoleAssignments.Any(assignment =>
            assignment.PrincipalId == principalId && roles.Contains(assignment.Role.Code)));
    }
}
