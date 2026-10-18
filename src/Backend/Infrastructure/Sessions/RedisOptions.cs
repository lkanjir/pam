namespace Infrastructure.Sessions;

public sealed class RedisOptions
{
    public const string SectionName = "Redis";

    public string Host { get; init; } = string.Empty;
    public int Port { get; init; }
    public string User { get; init; } = "default";
    public string Password { get; init; } = string.Empty;
}