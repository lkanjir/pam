namespace Application.Sessions;

public sealed record PrincipalSnapshot(
    long Id,
    Guid PublicId,
    string DisplayName,
    string Issuer,
    string Subject);
