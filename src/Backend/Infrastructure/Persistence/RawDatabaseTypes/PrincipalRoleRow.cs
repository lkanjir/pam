namespace Infrastructure.Persistence.RawDatabaseTypes;

public sealed class PrincipalRoleRow
{
    public long Id { get; set; }
    public Guid PublicId { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public bool IsEnabled { get; set; }
    public string? RoleCode { get; set; }
}
