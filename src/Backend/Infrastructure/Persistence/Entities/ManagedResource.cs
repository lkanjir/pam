namespace Infrastructure.Persistence.Entities;

public sealed class ManagedResource
{
    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string ResourceType { get; set; } = string.Empty;
    public string Environment { get; set; } = string.Empty;
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; init; }
    public long CreatedByPrincipalId { get; init; }
    public DateTime ModifiedAt { get; set; }
    public long ModifiedByPrincipalId { get; set; }
    public DateTime? DeletedAt { get; set; }

    public Principal CreatedByPrincipal { get; set; } = null!;
    public Principal ModifiedByPrincipal { get; set; } = null!;
    public ICollection<Entitlement> Entitlements { get; } = new List<Entitlement>();
}
