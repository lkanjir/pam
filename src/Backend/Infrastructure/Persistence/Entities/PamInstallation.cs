namespace Infrastructure.Persistence.Entities;

public sealed class PamInstallation
{
    public int Id { get; init; } = 1;
    public long BootstrapPrincipalId { get; init; }
    public DateTime InitializedAt { get; init; }
    public DateTime? CompletedAt { get; private set; }
    public long? CompletedByPrincipalId { get; private set; }
    public uint Version { get; private set; }

    public Principal? BootstrapPrincipal { get; private set; }
    public Principal? CompletedByPrincipal { get; private set; }
}
