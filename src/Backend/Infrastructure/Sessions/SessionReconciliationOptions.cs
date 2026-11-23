namespace Infrastructure.Sessions;

public sealed class SessionReconciliationOptions
{
    public const string SectionName = "SessionReconciliation";
    public bool Enabled { get; set; } = true;
    public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(30);
    public int BatchSize { get; set; } = 200;
}
