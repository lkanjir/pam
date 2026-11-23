namespace Application.Resources;

public enum ResourceWriteKind
{
    Succeeded,
    NotFound,
    Conflict
}

public sealed record ResourceWriteResult(ResourceWriteKind Kind, ResourceResponse? Resource = null);
