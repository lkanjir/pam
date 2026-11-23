namespace Application.Authorization;

/// <summary>Explicit supporting bundles for each delivered resource relationship.</summary>
public static class ResourceBindingRoles
{
    public static string[] For(ResourceBindingKind kind) => kind switch
    {
        ResourceBindingKind.ViewResource => PamPermissionRoles.For(PamPermissions.ResourcesReadScoped),
        ResourceBindingKind.ApproveRequests => [PamRoleCodes.Approver],
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, "The resource relationship is not registered.")
    };
}
