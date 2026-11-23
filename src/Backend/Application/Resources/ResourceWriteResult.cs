namespace Application.Resources;

public enum ResourceWriteKind
{
    Succeeded,
    NotFound,
    Conflict,
    Forbidden,
    RecentAuthenticationRequired
}

public sealed record ResourceWriteResult(ResourceWriteKind Kind, ResourceResponse? Resource = null);
