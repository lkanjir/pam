namespace Application.Principals;

/// <summary>A PAM identity mapping, with immutable issuer/subject and its current local account status.</summary>
public sealed record PrincipalResponse(Guid Id, string Issuer, string Subject, string DisplayName, bool IsEnabled,
    DateTimeOffset CreatedAt, DateTimeOffset ModifiedAt);
