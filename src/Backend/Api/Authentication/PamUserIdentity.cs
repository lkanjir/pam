namespace Api.Authentication;

public sealed record PamUserIdentity(long Id, Guid PublicId, string DisplayName,
    string Issuer, string Subject, IReadOnlyList<string> Roles, string? IdpSessionId);
