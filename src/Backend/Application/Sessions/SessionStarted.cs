namespace Application.Sessions;

public sealed record SessionStarted(
    PrincipalSnapshot Principal,
    string SessionIdHash,
    string? IdpSessionId,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpectedExpiresAt,
    SessionRequestMetadata Request);
