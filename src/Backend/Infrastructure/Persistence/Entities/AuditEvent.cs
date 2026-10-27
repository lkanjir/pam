namespace Infrastructure.Persistence.Entities;

public sealed class AuditEvent
{
    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public string EventType { get; init; } = string.Empty;
    public int SchemaVersion { get; init; }
    public DateTime OccurredAt { get; init; }
    public string ActorKind { get; init; } = string.Empty;
    public long? ActorPrincipalId { get; init; }
    public long? SubjectPrincipalId { get; init; }
    public long? ResourceId { get; init; }
    public long? EntitlementId { get; init; }
    public long? RequestId { get; init; }
    public string? ActorSnapshot { get; init; }
    public string? SubjectSnapshot { get; init; }
    public string? ResourceSnapshot { get; init; }
    public string? EntitlementSnapshot { get; init; }
    public string? SessionIdHash { get; init; }
    public string CorrelationId { get; init; } = string.Empty;
    public Guid? CausationId { get; init; }
    public string Source { get; init; } = string.Empty;
    public string? Outcome { get; init; }
    public string? ReasonCode { get; init; }
    public string? Metadata { get; init; }
}
