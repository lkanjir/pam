namespace Infrastructure.Persistence.Entities;

public sealed class Principal
{
    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public string Issuer { get; init; } = string.Empty;
    public string Subject { get; init; } = string.Empty;
    public string DisplayName { get; private set; } = string.Empty;
    public bool IsEnabled { get; private set; }
    public DateTime CreatedAt { get; init; }
    public DateTime ModifiedAt { get; private set; }
}