namespace Domain;

public sealed class PamRole
{
    public int Id { get; init; }
    public string Code { get; init; } = string.Empty;
    public string Description { get; private set; } = string.Empty;
    public DateTime CreatedAt { get; init; }
    public long CreatedByPrincipalId { get; init; }
}
