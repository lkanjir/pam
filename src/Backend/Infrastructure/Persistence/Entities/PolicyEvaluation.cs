namespace Infrastructure.Persistence.Entities;

public sealed class PolicyEvaluation
{
    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public long RequestId { get; init; }
    public string PolicyCode { get; init; } = string.Empty;
    public int PolicyVersion { get; init; }
    public string Decision { get; private set; } = string.Empty;
    public string? ReasonCode { get; init; }
    public string? Explanation { get; init; }
    public string? InputSnapshot { get; init; }
    public DateTime EvaluatedAt { get; init; }
}
