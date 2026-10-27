namespace Infrastructure.Persistence.Entities;

public sealed class EligibilityRule
{
    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public long PrincipalId { get; init; }
    public long EntitlementId { get; init; }
    public bool IsEnabled { get; init; }
    public DateTime CreatedAt { get; init; }
}
