namespace Application.Identity;

public sealed record PrincipalIdentity(long Id, Guid PublicId, string DisplayName, bool IsEnabled, IReadOnlyList<string> Roles);