namespace Application.Authorization;

/// <summary>Explicit role bundles for delivered capabilities; no inheritance or wildcard grants.</summary>
public static class PamPermissionRoles
{
    public static bool RequiresRecentAuthentication(string permission) => permission switch
    {
        PamPermissions.ResourcesManage => true,
        PamPermissions.ResourcesReadAll or PamPermissions.RequestsReadOwn or PamPermissions.RequestsCreate => false,
        _ => throw new ArgumentException("The permission is not registered.", nameof(permission))
    };

    public static string[] For(string permission) => permission switch
    {
        PamPermissions.ResourcesReadAll or PamPermissions.ResourcesManage => [PamRoleCodes.Admin],
        PamPermissions.RequestsReadOwn or PamPermissions.RequestsCreate => [PamRoleCodes.User],
        _ => throw new ArgumentException("The permission is not registered.", nameof(permission))
    };
}
