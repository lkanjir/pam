namespace Application.Authorization;

/// <summary>Stable capability identifiers, independent of endpoint and role names.</summary>
public static class PamPermissions
{
    public const string RequestsCreate = "requests.create";
    public const string RequestsReadOwn = "requests.read_own";
    public const string ResourcesReadAll = "resources.read_all";
}
