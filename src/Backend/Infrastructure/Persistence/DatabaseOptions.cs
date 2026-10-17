namespace Infrastructure.Persistence;

public sealed class DatabaseOptions
{
    public const string SectionName = "Database";
    
    public string ConnectionString { get; init; } = string.Empty;
}