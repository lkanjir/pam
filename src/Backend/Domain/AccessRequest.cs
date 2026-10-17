namespace Domain;

public sealed class AccessRequest
{
    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public long RequesterPrincipalId { get; init; }
    public long EntitlementId { get; init; }
    public int RequestedDurationMinutes { get; init; }
    public string Justification { get; init; } = string.Empty;
    public string? TicketReference { get; init; }
    public string State { get; private set; } = string.Empty;
    public string IdempotencyKey { get; init; } = string.Empty;
    public string? PayloadHash { get; init; }
    public DateTime CreatedAt { get; init; }
}
