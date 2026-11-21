namespace Application.Authorization;

/// <summary>Explicit role bundles for delivered capabilities; no inheritance or wildcard grants.</summary>
public static class PamPermissionRoles
{
    public static bool RequiresRecentAuthentication(string permission) => permission switch
    {
        PamPermissions.ResourcesManage or PamPermissions.PrincipalsManage or PamPermissions.RolesAssign => true,
        PamPermissions.ResourcesReadAll or PamPermissions.RequestsReadOwn or PamPermissions.RequestsCreate
            or PamPermissions.PrincipalsRead or PamPermissions.RolesRead or PamPermissions.ResourcesReadScoped
            or PamPermissions.ResourceAccessRead => false,
        _ => throw new ArgumentException("The permission is not registered.", nameof(permission))
    };

    public static string[] For(string permission) => permission switch
    {
        PamPermissions.ResourcesReadAll or PamPermissions.ResourcesManage or PamPermissions.PrincipalsRead
            or PamPermissions.PrincipalsManage or PamPermissions.RolesRead or PamPermissions.RolesAssign
            or PamPermissions.ResourceAccessRead => [PamRoleCodes.Admin],
        PamPermissions.RequestsReadOwn or PamPermissions.RequestsCreate => [PamRoleCodes.User],
        PamPermissions.ResourcesReadScoped => [PamRoleCodes.User, PamRoleCodes.Approver],
        _ => throw new ArgumentException("The permission is not registered.", nameof(permission))
    };
}
