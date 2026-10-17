namespace Domain;

public sealed class Entitlement
{
    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public long ResourceId { get; init; }
    public string Code { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public int MaxDurationMinutes { get; init; }
    public bool RequiresApproval { get; init; }
    public bool RequiresTicket { get; init; }
    public bool IsActive { get; init; }
}
