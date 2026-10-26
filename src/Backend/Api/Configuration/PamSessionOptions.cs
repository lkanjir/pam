namespace Api.Configuration;

public sealed class PamSessionOptions
{
    public const string SectionName = "PamSession";

    public TimeSpan IdleTimeout { get; init; }
    public TimeSpan AbsoluteTimeout { get; init; }
}
