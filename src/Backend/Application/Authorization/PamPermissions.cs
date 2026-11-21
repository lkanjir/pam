namespace Application.Authorization;

/// <summary>Stable capability identifiers, independent of endpoint and role names.</summary>
public static class PamPermissions
{
    public const string RequestsCreate = "requests.create";
    public const string RequestsReadOwn = "requests.read_own";
    public const string ResourcesReadAll = "resources.read_all";
    public const string ResourcesReadScoped = "resources.read_scoped";
    public const string ResourcesManage = "resources.manage";
    public const string PrincipalsRead = "principals.read";
    public const string PrincipalsManage = "principals.manage";
    public const string RolesRead = "roles.read";
    public const string RolesAssign = "roles.assign";
    public const string ResourceAccessRead = "resource_access.read";
    public const string ResourceAccessAssign = "resource_access.assign";
    public const string EligibilityRead = "eligibility.read";
    public const string EligibilityAssign = "eligibility.assign";
}
