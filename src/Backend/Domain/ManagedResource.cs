namespace Domain;

public sealed class ManagedResource
{
    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public string Name { get; init; } = string.Empty;
    public string? Description { get; init; }
    public string ResourceType { get; init; } = string.Empty;
    public string Environment { get; init; } = string.Empty;
    public bool IsActive { get; init; }
    public DateTime CreatedAt { get; init; }
    public long CreatedByPrincipalId { get; init; }
    public DateTime ModifiedAt { get; init; }
    public long ModifiedByPrincipalId { get; init; }
}
