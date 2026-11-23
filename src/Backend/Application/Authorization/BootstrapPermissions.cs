namespace Application.Authorization;

/// <summary>A bootstrap identity can perform setup only; permissions do not imply unrestricted Admin use.</summary>
public static class BootstrapPermissions
{
    public static bool Allows(string permission) => permission is PamPermissions.PrincipalsRead or PamPermissions.PrincipalsManage
        or PamPermissions.RolesRead or PamPermissions.RolesAssign or PamPermissions.BootstrapRead;
}
