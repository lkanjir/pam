using Application.Authorization;

namespace Infrastructure.Persistence.Entities;

public sealed class ResourcePrincipalBinding
{
    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public long PrincipalId { get; init; }
    public long ResourceId { get; init; }
    public ResourceBindingKind Kind { get; init; }
    public bool IsActive { get; set; } = true;
    public DateTime AssignedAt { get; init; }
    public long AssignedByPrincipalId { get; init; }
    public DateTime ModifiedAt { get; set; }
    public long ModifiedByPrincipalId { get; set; }
    public uint Version { get; private set; }

    // Nullable navigations express that a relationship need not be loaded.
    // The non-nullable foreign keys and EF configuration require every parent in storage.
    public Principal? Principal { get; set; }
    public ManagedResource? Resource { get; set; }
    public Principal? AssignedByPrincipal { get; set; }
    public Principal? ModifiedByPrincipal { get; set; }
}
